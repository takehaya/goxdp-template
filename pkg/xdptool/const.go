package xdptool

const (
	XDP_ABORTED uint32 = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

const (
	BPF_FIB_LKUP_RET_SUCCESS      uint8 = iota /* lookup successful */
	BPF_FIB_LKUP_RET_BLACKHOLE                 /* dest is blackholed; can be dropped */
	BPF_FIB_LKUP_RET_UNREACHABLE               /* dest is unreachable; can be dropped */
	BPF_FIB_LKUP_RET_PROHIBIT                  /* dest not allowed; can be dropped */
	BPF_FIB_LKUP_RET_NOT_FWDED                 /* packet is not forwarded */
	BPF_FIB_LKUP_RET_FWD_DISABLED              /* fwding is not enabled on ingress */
	BPF_FIB_LKUP_RET_UNSUPP_LWT                /* fwd requires encapsulation */
	BPF_FIB_LKUP_RET_NO_NEIGH                  /* no neighbor entry for nh */
	BPF_FIB_LKUP_RET_FRAG_NEEDED               /* fragmentation required to fwd */
)
