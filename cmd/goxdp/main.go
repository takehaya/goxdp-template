package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/goxdp-template/pkg/coreelf"
	"github.com/takehaya/goxdp-template/pkg/version"
	"github.com/urfave/cli"
)

func main() {
	if err := newApp(version.Version).Run(os.Args); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Printf("%+v", verr)
		}
		log.Fatal(err)
	}
}

func newApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "goxdp"
	app.Version = version
	app.Usage = "XDP examples using cilium/ebpf"
	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "backend",
			Value: "xdp",
			Usage: "Replication backend: xdp or tc (XDP ingress with TC cloning)",
		},
		cli.BoolFlag{
			Name:  "cpu-redirect",
			Usage: "Run VXLAN or FIB forwarding through CPUMAP before forwarding",
		},
		cli.IntSliceFlag{
			Name:  "cpu",
			Usage: "Target CPU for --cpu-redirect (repeatable; defaults to process affinity)",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "vxlan",
			Usage: "Example to run: vxlan, broadcast, or fib",
		},
		cli.StringFlag{
			Name:  "config",
			Usage: "VXLAN JSON configuration (ports, VNI groups, and optional local FDB)",
		},
		cli.StringSliceFlag{
			Name:  "device",
			Usage: "Ingress interface to attach to (repeatable)",
		},
		cli.StringSliceFlag{
			Name:  "egress",
			Usage: "Replication group member for broadcast mode (repeatable, up to 64)",
		},
		cli.StringSliceFlag{
			Name:  "local-delivery",
			Usage: "Local receiving veth (repeatable; add its peer as an egress/access member)",
		},
	}
	app.Action = run
	return app
}

func run(ctx *cli.Context) error {
	mode := ctx.String("mode")
	backend := ctx.String("backend")
	if backend != "xdp" && backend != "tc" {
		return fmt.Errorf("unknown backend %q: choose xdp or tc", backend)
	}
	if backend == "tc" && mode == "fib" {
		return errors.New("--backend tc is supported in broadcast and vxlan modes")
	}
	localDevices := ctx.StringSlice("local-delivery")
	if len(localDevices) != 0 && mode != "broadcast" && mode != "vxlan" {
		return errors.New("--local-delivery is supported in broadcast and vxlan modes")
	}
	redirectCPU := ctx.Bool("cpu-redirect")
	if ctx.IsSet("cpu") && !redirectCPU {
		return errors.New("--cpu requires --cpu-redirect")
	}
	if redirectCPU && mode != "vxlan" && mode != "fib" {
		return errors.New("--cpu-redirect is supported in vxlan and fib modes")
	}
	if redirectCPU && !coreelf.CPUMAPEnabled {
		return coreelf.ErrCPUMAPDisabled
	}
	var cpus []uint32
	if redirectCPU {
		var err error
		cpus, err = coreelf.SelectCPUs(ctx.IntSlice("cpu"))
		if err != nil {
			return err
		}
		log.Printf("CPU redirect targets: %v", cpus)
	}
	devices := ctx.StringSlice("device")
	egress := ctx.StringSlice("egress")
	var vxlanConfig coreelf.VXLANConfig
	configPath := ctx.String("config")
	if configPath != "" {
		if mode != "vxlan" {
			return errors.New("--config is only supported in vxlan mode")
		}
		f, err := os.Open(configPath)
		if err != nil {
			return err
		}
		vxlanConfig, err = coreelf.DecodeVXLANConfig(f)
		f.Close()
		if err != nil {
			return err
		}
		if len(devices) == 0 {
			devices = vxlanConfig.Devices()
		}
	}
	if err := validateOptions(mode, devices, egress); err != nil {
		return err
	}
	if _, err := interfaceIndices(devices); err != nil {
		return err
	}
	ifindices, err := interfaceIndices(egress)
	if err != nil {
		return err
	}
	if err := validateLocalDelivery(localDevices, devices, egress, vxlanConfig.Devices()); err != nil {
		return err
	}
	if mode == "vxlan" && configPath == "" {
		return errors.New("vxlan mode requires --config; use --mode fib for the FIB lookup example")
	}
	if mode == "vxlan" {
		configured := make(map[string]bool)
		for _, name := range vxlanConfig.Devices() {
			configured[name] = true
		}
		for _, name := range devices {
			if !configured[name] {
				return fmt.Errorf("device %s is absent from VXLAN config", name)
			}
		}
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	if mode == "broadcast" {
		if backend == "tc" {
			objs, err := coreelf.ReadTCBroadcastCollection(ifindices)
			if err != nil {
				return err
			}
			defer objs.Close()
			return runAttached(objs.XdpBroadcast, objs.TcBroadcast, devices, localDevices)
		}
		objs, err := coreelf.ReadBroadcastCollection(ifindices)
		if err != nil {
			return err
		}
		defer objs.Close()
		log.Printf("replication group: %v (ingress excluded)", egress)
		return runAttached(objs.XdpBroadcast, nil, devices, localDevices)
	}
	if mode == "vxlan" {
		load := coreelf.ReadVXLANCollection
		if backend == "tc" {
			load = coreelf.ReadTCVXLANCollection
		}
		obj, err := load(vxlanConfig, cpus...)
		if err != nil {
			return err
		}
		defer obj.Close()
		return runAttached(obj.Program(), obj.TCProgram(), devices, localDevices)
	}

	ncpus, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	objs, err := coreelf.ReadCollection(ncpus, cpus...)
	if err != nil {
		return err
	}
	defer objs.Close()
	if redirectCPU {
		return runAttached(objs.CPUProgram(), nil, devices, nil)
	}
	return runAttached(objs.XdpProg, nil, devices, nil)
}

func validateLocalDelivery(receivers []string, forwarding ...[]string) error {
	if _, err := interfaceIndices(receivers); err != nil {
		return err
	}
	for _, name := range receivers {
		for _, devices := range forwarding {
			for _, device := range devices {
				if name == device {
					return fmt.Errorf("local-delivery receiver %s must be separate from forwarding ports", name)
				}
			}
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		if len(iface.HardwareAddr) != 6 {
			return fmt.Errorf("local-delivery receiver %s must be an Ethernet interface", name)
		}
	}
	return nil
}

func validateOptions(mode string, devices, egress []string) error {
	if mode != "vxlan" && mode != "broadcast" && mode != "fib" {
		return fmt.Errorf("unknown mode %q: choose vxlan, broadcast, or fib", mode)
	}
	if len(devices) == 0 {
		return errors.New("specify at least one --device ingress interface")
	}
	if mode == "broadcast" && len(egress) == 0 {
		return errors.New("broadcast mode requires at least one --egress interface")
	}
	if mode != "broadcast" && len(egress) != 0 {
		return errors.New("--egress is only supported in broadcast mode")
	}
	return nil
}

func interfaceIndices(names []string) ([]uint32, error) {
	indices := make([]uint32, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			return nil, fmt.Errorf("duplicate interface %q", name)
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("find interface %q: %w", name, err)
		}
		indices = append(indices, uint32(iface.Index))
		seen[name] = true
	}
	return indices, nil
}

func runAttached(prog, tcProg *ebpf.Program, devices, localDevices []string) (retErr error) {
	ifindices, err := interfaceIndices(devices)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	var links []link.Link
	var localObjects []io.Closer
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			retErr = errors.Join(retErr, links[i].Close())
		}
		for _, objects := range localObjects {
			retErr = errors.Join(retErr, objects.Close())
		}
	}()
	for _, dev := range localDevices {
		iface, err := net.InterfaceByName(dev)
		if err != nil {
			return err
		}
		var receiver *ebpf.Program
		if tcProg != nil {
			objects, err := coreelf.ReadTCLocalDeliveryCollection(iface.HardwareAddr)
			if err != nil {
				return err
			}
			localObjects = append(localObjects, objects)
			tcLink, err := link.AttachTCX(link.TCXOptions{
				Program: objects.TcLocalReceive, Interface: iface.Index, Attach: ebpf.AttachTCXIngress,
			})
			if err != nil {
				return fmt.Errorf("attach TCX ingress to %s: %w", dev, err)
			}
			links = append(links, tcLink)
			receiver = objects.LocalReceive
		} else {
			objects, err := coreelf.ReadLocalDeliveryCollection(iface.HardwareAddr)
			if err != nil {
				return err
			}
			localObjects = append(localObjects, objects)
			receiver = objects.LocalReceive
		}
		attached, err := link.AttachXDP(link.XDPOptions{
			Program: receiver, Interface: iface.Index, Flags: link.XDPDriverMode,
		})
		if err != nil {
			return fmt.Errorf("attach XDP to %s: %w", dev, err)
		}
		links = append(links, attached)
		log.Printf("local stack delivery on %s", dev)
	}
	for i, dev := range devices {
		if tcProg == nil {
			break
		}
		attached, err := link.AttachTCX(link.TCXOptions{
			Program: tcProg, Interface: int(ifindices[i]), Attach: ebpf.AttachTCXIngress,
		})
		if err != nil {
			return fmt.Errorf("attach TCX ingress to %s: %w", dev, err)
		}
		links = append(links, attached)
		log.Printf("attached TCX ingress to %s", dev)
	}
	for i, dev := range devices {
		attached, err := link.AttachXDP(link.XDPOptions{
			Program: prog, Interface: int(ifindices[i]), Flags: link.XDPDriverMode,
		})
		if err != nil {
			return fmt.Errorf("attach XDP to %s: %w", dev, err)
		}
		links = append(links, attached)
		log.Printf("attached native XDP to %s", dev)
	}
	log.Println("Press CTRL+C to detach and stop.")
	<-ctx.Done()
	return nil
}
