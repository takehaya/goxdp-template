# goxdp
A sample for writing XDP programs in Go

It's best to change this to get started with code for xdp using [cilium/ebpf](https://github.com/cilium/ebpf).


## Build
In today's Linux, bpf_helper_defs.h is supposed to build.
If you hit this script accordingly, it will fetch the kernel code and build it.
Please use according to your kernel version.
There is no problem with the first execution.

```
./gen_bpf_helper.sh
```

Let's build go & ebpf
```
make
```

## Run
```
./bin/goxdp

# use option
./bin/goxdp --device eth2 --device eth3
```

