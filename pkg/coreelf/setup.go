package coreelf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func setTailCall(objs *xdpObjects) error {
	proglist := []*ebpf.Program{
		objs.XdpProg,
	}
	for i := 0; i < len(proglist); i++ {
		err := objs.XdpProgArray.Update(
			uint32(i),
			uint32(proglist[i].FD()),
			ebpf.UpdateAny,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func setCpusMaps(objs *xdpObjects, ncpus int) error {
	if ncpus < 0 {
		return fmt.Errorf("invalid CPU number: %d", ncpus)
	}
	val := xdpBpfCpumapVal{
		Qsize: 128,
		BpfProg: struct{ Fd int32 }{
			Fd: int32(objs.XdpMainJump.FD()),
		},
	}
	for cpu := 0; cpu < ncpus; cpu++ {
		err := objs.CpusMap.Update(
			uint32(cpu),
			val,
			ebpf.UpdateAny,
		)
		if err != nil {
			return fmt.Errorf("fail to set CPU dispatch: %w", err)
		}
	}
	return nil
}
