//-----------------------------------------------------------------------------
/*

Test program to exercise the libjaylink Go wrapper.

*/
//-----------------------------------------------------------------------------

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/deadsy/libjaylink"
)

//-----------------------------------------------------------------------------

const colorGreen = "\033[0;32m"
const colorNone = "\033[0m"

func logCallback(domain, msg string) {
	s := []string{colorGreen, domain, msg, colorNone}
	fmt.Printf("%s\n", strings.Join(s, ""))
}

//-----------------------------------------------------------------------------

func libTest() error {

	fmt.Printf("package %s\n", libjaylink.VersionPackageGetString())
	fmt.Printf("library %s\n", libjaylink.VersionLibraryGetString())

	ctx, err := libjaylink.Init()
	if err != nil {
		return err
	}
	defer ctx.Exit()

	err = ctx.LogSetCallback(logCallback)
	if err != nil {
		return err
	}

	err = ctx.LogSetLevel(libjaylink.LOG_LEVEL_DEBUG)
	if err != nil {
		return err
	}

	err = ctx.LogSetDomain("test: ")
	if err != nil {
		return err
	}

	err = ctx.DiscoveryScan(libjaylink.HIF_USB)
	if err != nil {
		return err
	}

	dev, err := ctx.GetDevices()
	if err != nil {
		return err
	}
	defer ctx.FreeDevices(dev, true)

	fmt.Printf("%d devices found\n", len(dev))
	for i := range dev {
		fmt.Printf("device %d: %s\n", i, &dev[i])

		hdl, err := dev[i].Open()
		if err != nil {
			fmt.Printf("%s\n", err)
			continue
		}

		fmt.Printf("%s\n", hdl)

		err = hdl.Close()
		if err != nil {
			fmt.Printf("%s\n", err)
			continue
		}
	}

	return nil
}

//-----------------------------------------------------------------------------

func main() {
	err := libTest()
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

//-----------------------------------------------------------------------------
