package coreelf

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/cilium/ebpf"
)

//go:generate go tool bpf2go -target bpf -tags !nocpumap vxlan ../../src/xdp_vxlan.c -- -O2 -g -Wall -Werror -UNO_CPUMAP
//go:generate go tool bpf2go -target bpf -tags nocpumap -output-stem vxlan_direct vxlan ../../src/xdp_vxlan.c -- -O2 -g -Wall -Werror -DNO_CPUMAP

type VXLANPort struct {
	Device  string      `json:"device"`
	VNI     uint32      `json:"vni,omitempty"`
	LocalIP string      `json:"local_ip,omitempty"`
	VLANs   []VXLANVLAN `json:"vlans,omitempty"`
}

// VXLANVLAN preserves one inline 802.1Q tag while selecting its VNI.
type VXLANVLAN struct {
	VID uint16 `json:"vid"`
	VNI uint32 `json:"vni"`
}

func (p VXLANPort) memberVLAN(vni uint32) (uint16, bool) {
	if p.LocalIP != "" {
		return 0, true
	}
	if len(p.VLANs) == 0 {
		return 0, p.VNI == vni
	}
	for _, vlan := range p.VLANs {
		if vlan.VNI == vni {
			return vlan.VID, true
		}
	}
	return 0, false
}

type VXLANGroup struct {
	VNI          uint32      `json:"vni"`
	MulticastIP  string      `json:"multicast_ip,omitempty"`
	UnicastPeers []VXLANPeer `json:"unicast_peers,omitempty"`
	Devices      []string    `json:"devices"`
}

type VXLANPeer struct {
	Device    string `json:"device"`
	RemoteIP  string `json:"remote_ip"`
	RemoteMAC string `json:"remote_mac"`
}

type VXLANFDBEntry struct {
	VNI    uint32 `json:"vni"`
	MAC    string `json:"mac"`
	Device string `json:"device"`
}

type VXLANConfig struct {
	Ports  []VXLANPort     `json:"ports"`
	Groups []VXLANGroup    `json:"groups"`
	FDB    []VXLANFDBEntry `json:"fdb,omitempty"`
}

func DecodeVXLANConfig(r io.Reader) (VXLANConfig, error) {
	var cfg VXLANConfig
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode VXLAN config: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return cfg, errors.New("VXLAN config must contain one JSON object")
	}
	return cfg, cfg.Validate()
}

func (c VXLANConfig) Devices() []string {
	devices := make([]string, 0, len(c.Ports))
	for _, port := range c.Ports {
		devices = append(devices, port.Device)
	}
	return devices
}

func validVNI(vni uint32) bool { return vni > 0 && vni < 1<<24 }

func ipv4Value(s string, multicast bool) (uint32, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() != multicast || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return 0, fmt.Errorf("invalid IPv4 address %q (multicast=%v)", s, multicast)
	}
	addr := ip.As4()
	return binary.NativeEndian.Uint32(addr[:]), nil
}

func (c VXLANConfig) Validate() error {
	if len(c.Ports) == 0 || len(c.Ports) > 256 || len(c.Groups) == 0 || len(c.Groups) > 64 {
		return errors.New("VXLAN requires 1 to 256 ports and 1 to 64 VNI groups")
	}
	ports := make(map[string]VXLANPort)
	for _, p := range c.Ports {
		if p.Device == "" || ports[p.Device].Device != "" {
			return fmt.Errorf("empty or duplicate VXLAN device %q", p.Device)
		}
		if p.LocalIP != "" {
			if p.VNI != 0 || len(p.VLANs) != 0 {
				return fmt.Errorf("tunnel port %s must not specify a VNI or VLAN bindings", p.Device)
			}
			if _, err := ipv4Value(p.LocalIP, false); err != nil {
				return err
			}
		} else if len(p.VLANs) != 0 {
			if p.VNI != 0 || len(p.VLANs) > 64 {
				return fmt.Errorf("VLAN port %s requires 1 to 64 bindings and no fixed VNI", p.Device)
			}
			vids, vnis := make(map[uint16]bool), make(map[uint32]bool)
			for _, vlan := range p.VLANs {
				if vlan.VID == 0 || vlan.VID >= 4095 || !validVNI(vlan.VNI) || vids[vlan.VID] || vnis[vlan.VNI] {
					return fmt.Errorf("invalid or duplicate VLAN binding on %s: VID %d, VNI %d", p.Device, vlan.VID, vlan.VNI)
				}
				vids[vlan.VID], vnis[vlan.VNI] = true, true
			}
		} else if !validVNI(p.VNI) {
			return fmt.Errorf("access port %s requires a VNI in 1..16777215", p.Device)
		}
		ports[p.Device] = p
	}
	groups := make(map[uint32]map[string]bool)
	for _, group := range c.Groups {
		if !validVNI(group.VNI) || groups[group.VNI] != nil {
			return fmt.Errorf("invalid or duplicate VNI %d", group.VNI)
		}
		if group.MulticastIP != "" {
			if len(group.UnicastPeers) != 0 {
				return fmt.Errorf("VNI %d must choose multicast_ip or unicast_peers", group.VNI)
			}
			if _, err := ipv4Value(group.MulticastIP, true); err != nil {
				return err
			}
		} else if len(group.UnicastPeers) == 0 {
			return fmt.Errorf("VNI %d requires multicast_ip or unicast_peers", group.VNI)
		}
		if err := validateMembers(group.VNI, group.Devices, ports); err != nil {
			return err
		}
		members := make(map[string]bool)
		for _, name := range group.Devices {
			members[name] = true
		}
		seenPeers := make(map[string]bool)
		for _, peer := range group.UnicastPeers {
			if !members[peer.Device] || seenPeers[peer.Device] {
				return fmt.Errorf("invalid or duplicate unicast peer device %q in VNI %d", peer.Device, group.VNI)
			}
			if _, err := makePeer(peer, ports); err != nil {
				return err
			}
			seenPeers[peer.Device] = true
		}
		if group.MulticastIP == "" {
			for _, name := range group.Devices {
				if ports[name].LocalIP != "" && !seenPeers[name] {
					return fmt.Errorf("tunnel %s requires a unicast peer in VNI %d", name, group.VNI)
				}
			}
		}
		groups[group.VNI] = members
	}
	for _, port := range c.Ports {
		for _, vlan := range port.VLANs {
			if !groups[vlan.VNI][port.Device] {
				return fmt.Errorf("VLAN port %s must belong to VNI %d's group", port.Device, vlan.VNI)
			}
		}
		if port.LocalIP == "" && len(port.VLANs) == 0 && !groups[port.VNI][port.Device] {
			return fmt.Errorf("access port %s must belong to VNI %d's group", port.Device, port.VNI)
		}
	}
	seen := make(map[string]bool)
	for _, entry := range c.FDB {
		mac, err := net.ParseMAC(entry.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			return fmt.Errorf("FDB requires a unicast Ethernet MAC: %q", entry.MAC)
		}
		p := ports[entry.Device]
		_, member := p.memberVLAN(entry.VNI)
		if p.Device == "" || p.LocalIP != "" || !member || !groups[entry.VNI][p.Device] {
			return fmt.Errorf("FDB destination %s must be an access member of VNI %d", entry.Device, entry.VNI)
		}
		key := fmt.Sprintf("%d/%s", entry.VNI, mac)
		if seen[key] {
			return fmt.Errorf("duplicate FDB entry %s", key)
		}
		seen[key] = true
	}
	return nil
}

func makePeer(peer VXLANPeer, ports map[string]VXLANPort) (vxlanPeerConfig, error) {
	var value vxlanPeerConfig
	port, ok := ports[peer.Device]
	if !ok || port.LocalIP == "" {
		return value, fmt.Errorf("unicast peer %s requires a configured tunnel port", peer.Device)
	}
	ip, err := ipv4Value(peer.RemoteIP, false)
	if err != nil {
		return value, err
	}
	localIP, _ := ipv4Value(port.LocalIP, false)
	if ip == localIP {
		return value, fmt.Errorf("unicast peer %s must differ from local IP", peer.Device)
	}
	mac, err := net.ParseMAC(peer.RemoteMAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return value, fmt.Errorf("unicast peer %s requires a unicast Ethernet MAC", peer.Device)
	}
	value.RemoteIp = ip
	copy(value.Mac[:], mac)
	return value, nil
}

func validateMembers(vni uint32, devices []string, ports map[string]VXLANPort) error {
	if len(devices) == 0 || len(devices) > 64 {
		return fmt.Errorf("VNI %d requires 1 to 64 group members", vni)
	}
	seen := make(map[string]bool)
	encoding := -1
	for _, name := range devices {
		p, ok := ports[name]
		vid, member := p.memberVLAN(vni)
		if !ok || seen[name] || !member {
			return fmt.Errorf("invalid, duplicate, or foreign-VNI member %q in VNI %d", name, vni)
		}
		if p.LocalIP == "" {
			if encoding >= 0 && encoding != int(vid) {
				return fmt.Errorf("VNI %d local members require the same VLAN encoding; legacy and VLAN ports cannot mix", vni)
			}
			encoding = int(vid)
		}
		seen[name] = true
	}
	return nil
}

// VXLAN owns the ingress/egress programs and their forwarding maps.
// UpdateMembers selects from a VNI's preconfigured outputs without reattaching.
type VXLAN struct {
	objects vxlanObjects
	tc      *vxlanTCObjects
	ports   map[string]VXLANPort
	indices map[string]uint32
	groups  map[uint32]map[string]bool
	peerMu  sync.Mutex
}

type vxlanTCObjects struct {
	Program *ebpf.Program `ebpf:"tc_vxlan"`
	Groups  *ebpf.Map     `ebpf:"tc_groups"`
}

func (v *VXLAN) Program() *ebpf.Program { return v.objects.VxlanIngress }
func (v *VXLAN) TCProgram() *ebpf.Program {
	if v.tc == nil {
		return nil
	}
	return v.tc.Program
}

func (v *VXLAN) Close() error {
	err := v.objects.Close()
	if v.tc != nil {
		err = errors.Join(err, v.tc.Program.Close(), v.tc.Groups.Close())
	}
	return err
}

func ReadVXLANCollection(cfg VXLANConfig, cpus ...uint32) (_ *VXLAN, retErr error) {
	return readVXLANCollection(cfg, false, cpus...)
}

// ReadTCVXLANCollection shares XDP classification and decapsulation with the
// devmap backend, then hands the frame to TC for cloning and encapsulation.
func ReadTCVXLANCollection(cfg VXLANConfig, cpus ...uint32) (*VXLAN, error) {
	return readVXLANCollection(cfg, true, cpus...)
}

func readVXLANCollection(cfg VXLANConfig, tc bool, cpus ...uint32) (_ *VXLAN, retErr error) {
	if !CPUMAPEnabled && len(cpus) != 0 {
		return nil, ErrCPUMAPDisabled
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	v := &VXLAN{ports: make(map[string]VXLANPort), indices: make(map[string]uint32), groups: make(map[uint32]map[string]bool)}
	resolved := make(map[uint32]vxlanPortConfig)
	for _, p := range cfg.Ports {
		iface, err := net.InterfaceByName(p.Device)
		if err != nil {
			return nil, err
		}
		if len(iface.HardwareAddr) != 6 {
			return nil, fmt.Errorf("%s is not an Ethernet interface", p.Device)
		}
		entry := vxlanPortConfig{Kind: 1, Vni: p.VNI, Mtu: uint32(iface.MTU)}
		copy(entry.Mac[:], iface.HardwareAddr)
		if p.LocalIP != "" {
			entry.Kind = 2
			entry.LocalIp, _ = ipv4Value(p.LocalIP, false)
		} else if len(p.VLANs) != 0 {
			entry.Kind = 3
		}
		v.ports[p.Device], v.indices[p.Device] = p, uint32(iface.Index)
		resolved[uint32(iface.Index)] = entry
	}
	spec, err := loadVxlan()
	if tc {
		spec, err = loadTcVxlan()
	}
	if err != nil {
		return nil, err
	}
	if err := configureVXLANCPUSpec(spec, cpus); err != nil {
		return nil, err
	}
	var objects any = &v.objects
	if tc {
		v.tc = &vxlanTCObjects{}
		objects = &struct {
			Objects *vxlanObjects
			TC      *vxlanTCObjects
		}{&v.objects, v.tc}
	}
	if err := spec.LoadAndAssign(objects, nil); err != nil {
		return nil, fmt.Errorf("load VXLAN objects: %w", err)
	}
	defer func() {
		if retErr != nil {
			v.Close()
		}
	}()
	if err := setVXLANCPUMaps(&v.objects, cpus); err != nil {
		return nil, err
	}
	if err := v.objects.DevmapPrograms.Update(uint32(1), uint32(v.objects.VxlanRewrite.FD()), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	for _, p := range cfg.Ports {
		index := v.indices[p.Device]
		port := resolved[index]
		if err := v.objects.Ports.Update(index, port, ebpf.UpdateAny); err != nil {
			return nil, err
		}
		for _, vlan := range p.VLANs {
			key := vxlanVlanKey{Ifindex: index, Vid: uint32(vlan.VID)}
			if err := v.objects.VlanBindings.Put(key, vlan.VNI); err != nil {
				return nil, err
			}
		}
	}
	for _, group := range cfg.Groups {
		var ip uint32
		if group.MulticastIP != "" {
			ip, _ = ipv4Value(group.MulticastIP, true)
		}
		if err := v.objects.Vnis.Update(group.VNI, vxlanVniConfig{MulticastIp: ip, Revision: 1}, ebpf.UpdateAny); err != nil {
			return nil, err
		}
		v.groups[group.VNI] = make(map[string]bool)
		for _, device := range group.Devices {
			v.groups[group.VNI][device] = true
			vid, _ := v.ports[device].memberVLAN(group.VNI)
			key := vxlanPeerKey{Vni: group.VNI, Ifindex: v.indices[device]}
			if err := v.objects.PortVnis.Put(key, uint32(vid)); err != nil {
				return nil, err
			}
		}
		for _, peer := range group.UnicastPeers {
			value, _ := makePeer(peer, v.ports)
			key := vxlanPeerKey{Vni: group.VNI, Ifindex: v.indices[peer.Device]}
			if err := v.objects.Peers.Update(key, value, ebpf.UpdateAny); err != nil {
				return nil, err
			}
		}
		if err := v.UpdateMembers(group.VNI, group.Devices); err != nil {
			return nil, err
		}
	}
	for _, entry := range cfg.FDB {
		mac, _ := net.ParseMAC(entry.MAC)
		key := vxlanFdbKey{Vni: entry.VNI}
		copy(key.Mac[:], mac)
		if err := v.objects.Fdb.Update(key, v.indices[entry.Device], ebpf.UpdateAny); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (v *VXLAN) UpdateMembers(vni uint32, devices []string) error {
	if v.groups[vni] == nil {
		return fmt.Errorf("unknown VNI %d", vni)
	}
	if err := validateMembers(vni, devices, v.ports); err != nil {
		return err
	}
	for _, device := range devices {
		if !v.groups[vni][device] {
			return fmt.Errorf("device %s is not a preconfigured member of VNI %d", device, vni)
		}
	}
	var config vxlanVniConfig
	if err := v.objects.Vnis.Lookup(vni, &config); err != nil {
		return err
	}
	if config.MulticastIp == 0 {
		for _, device := range devices {
			if v.ports[device].LocalIP != "" {
				var peer vxlanPeerConfig
				if err := v.objects.Peers.Lookup(vxlanPeerKey{Vni: vni, Ifindex: v.indices[device]}, &peer); err != nil {
					return fmt.Errorf("tunnel %s requires a configured peer for VNI %d: %w", device, vni, err)
				}
			}
		}
	}
	if v.tc != nil {
		var group struct {
			Count     uint32
			Ifindices [64]uint32
		}
		group.Count = uint32(len(devices))
		for i, device := range devices {
			group.Ifindices[i] = v.indices[device]
		}
		return v.tc.Groups.Put(vni, group)
	}
	spec, err := loadVxlan()
	if err != nil {
		return err
	}
	members, err := ebpf.NewMap(spec.Maps["vni_groups"].InnerMap.Copy())
	if err != nil {
		return err
	}
	defer members.Close()
	for _, device := range devices {
		// struct bpf_devmap_val: interface index followed by the program FD.
		value := [2]uint32{v.indices[device], uint32(v.objects.VxlanEgress.FD())}
		if err := members.Update(value[0], value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("set VNI %d member %s: %w", vni, device, err)
		}
	}
	return v.objects.VniGroups.Update(vni, members, ebpf.UpdateAny)
}

// UpdatePeer changes a unicast destination and advances the VNI's cache
// revision. Each CPU refreshes its own LRU value on its next packet.
func (v *VXLAN) UpdatePeer(vni uint32, peer VXLANPeer) error {
	v.peerMu.Lock()
	defer v.peerMu.Unlock()
	if v.groups[vni] == nil {
		return fmt.Errorf("unknown VNI %d", vni)
	}
	if !v.groups[vni][peer.Device] {
		return fmt.Errorf("device %s is not a preconfigured member of VNI %d", peer.Device, vni)
	}
	value, err := makePeer(peer, v.ports)
	if err != nil {
		return err
	}
	var config vxlanVniConfig
	if err := v.objects.Vnis.Lookup(vni, &config); err != nil {
		return err
	}
	if config.MulticastIp != 0 {
		return fmt.Errorf("VNI %d uses multicast_ip", vni)
	}
	if config.Revision == ^uint32(0) {
		return errors.New("peer cache revision exhausted")
	}
	key := vxlanPeerKey{Vni: vni, Ifindex: v.indices[peer.Device]}
	if err := v.objects.Peers.Update(key, value, ebpf.UpdateAny); err != nil {
		return err
	}
	config.Revision++
	return v.objects.Vnis.Update(vni, config, ebpf.UpdateAny)
}
