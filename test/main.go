//-----------------------------------------------------------------------------
/*

Test program to exercise the libjaylink Go wrapper.

*/
//-----------------------------------------------------------------------------

package main

import (
	"fmt"
	"os"

	"github.com/deadsy/libjaylink"
)

//-----------------------------------------------------------------------------

func main() {

	fmt.Printf("package major %d minor %d micro %d %s\n",
		libjaylink.VersionPackageGetMajor(),
		libjaylink.VersionPackageGetMinor(),
		libjaylink.VersionPackageGetMicro(),
		libjaylink.VersionPackageGetString())

	fmt.Printf("library current %d revision %d age %d %s\n",
		libjaylink.VersionLibraryGetCurrent(),
		libjaylink.VersionLibraryGetRevision(),
		libjaylink.VersionLibraryGetAge(),
		libjaylink.VersionLibraryGetString())

	ctx, err := libjaylink.Init()
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	err = ctx.DiscoveryScan(libjaylink.HIF_USB)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	dev, err := ctx.GetDevices()
	if err != nil {
		fmt.Printf("%s\n", err)
		goto Exit
	}

	fmt.Printf("%d devices found\n", len(dev))
	for i := range dev {
		fmt.Printf("%d: %s\n", i, &dev[i])
	}

	ctx.FreeDevices(dev, true)

Exit:

	err = ctx.Exit()
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}

//-----------------------------------------------------------------------------
