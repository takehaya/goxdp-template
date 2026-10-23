package coreelf

import "testing"

func TestSelectCPUs(t *testing.T) {
	cpus, err := SelectCPUs(nil)
	if err != nil {
		t.Fatal(err)
	}
	cpu := int(cpus[len(cpus)-1])
	selected, err := SelectCPUs([]int{cpu})
	if err != nil || len(selected) != 1 || selected[0] != uint32(cpu) {
		t.Fatalf("explicit CPU selection: %v, %v", selected, err)
	}
	for _, invalid := range [][]int{{-1}, {1 << 30}, {cpu, cpu}} {
		if _, err := SelectCPUs(invalid); err == nil {
			t.Fatalf("accepted invalid CPUs %v", invalid)
		}
	}
}
