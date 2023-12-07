package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	"github.com/takehaya/goxdp-template/pkg/coreelf"
	"github.com/takehaya/goxdp-template/pkg/version"
	"github.com/takehaya/goxdp-template/pkg/xdptool"
	"github.com/urfave/cli"
)

func main() {
	app := newApp(version.Version)
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "goxdp_tmp"
	app.Version = version

	app.Usage = "A template for writing XDP programs in Go"

	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringSliceFlag{
			Name:  "device",
			Value: &cli.StringSlice{"eth1"},
			Usage: "Adding a device to attach",
		},
	}
	app.Action = run
	return app
}

func disposeDevice(devices []string) error {
	for _, dev := range devices {
		err := xdptool.Detach(dev)
		if err != nil {
			return errors.WithStack(err)
		}
		log.Println("detach device: ", dev)
	}
	return nil
}

func run(ctx *cli.Context) error {
	devices := ctx.StringSlice("device")
	log.Println(devices)
	// get ebpf binary
	obj, err := coreelf.ReadCollection()
	if err != nil {
		return errors.WithStack(err)
	}

	//attach xdp
	for _, dev := range devices {
		err = xdptool.Attach(obj.XdpProg, dev)
		if err != nil {
			return errors.WithStack(err)
		}
		log.Println("attached device: ", dev)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	log.Println("XDP program successfully loaded and attached.")
	log.Println("Press CTRL+C to stop.")
	for {
		select {
		case <-signalChan:
			err := disposeDevice(devices)
			if err != nil {
				return errors.WithStack(err)
			}
			return nil
		}
	}

}
