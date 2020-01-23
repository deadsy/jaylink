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

func logCallback(domain, msg string, user interface{}) {
	s := []string{colorGreen, domain, msg, colorNone}
	fmt.Printf("%s\n", strings.Join(s, ""))
}

//-----------------------------------------------------------------------------

func displayDevice(dev *libjaylink.Device) string {
	s := []string{}
	// hardware version
	hw, err := dev.GetHardwareVersion()
	if err == nil {
		s = append(s, fmt.Sprintf("hardware version: %s", hw))
	}
	// product name
	name, err := dev.GetProductName()
	if err == nil {
		s = append(s, fmt.Sprintf("product name: %s", name))
	}
	// nickname
	name, err = dev.GetNickName()
	if err == nil {
		s = append(s, fmt.Sprintf("nickname: %s", name))
	}
	// serial number
	sn, err := dev.GetSerialNumber()
	if err == nil {
		s = append(s, fmt.Sprintf("serial number: %d", sn))
	}
	// host interface
	hi, err := dev.GetHostInterface()
	if err == nil {
		s = append(s, fmt.Sprintf("host interface: %s", hi.String()))
	}
	// usb address
	addr, err := dev.GetUsbAddress()
	if err == nil {
		s = append(s, fmt.Sprintf("usb address: %s", addr))
	}
	// usb bus and ports
	bus, ports, err := dev.GetUsbPorts()
	if err == nil {
		s = append(s, fmt.Sprintf("usb bus/ports: %d %v", bus, ports))
	}
	// mac address
	mac, err := dev.GetMacAddress()
	if err == nil {
		s = append(s, fmt.Sprintf("mac address: %v", mac))
	}
	// ipv4 address
	ip, err := dev.GetIPv4Address()
	if err == nil {
		s = append(s, fmt.Sprintf("ipv4 address: %s", ip))
	}
	return strings.Join(s, "\n")
}

//-----------------------------------------------------------------------------

func displayHandle(hdl *libjaylink.DeviceHandle) string {
	s := []string{}
	// firmware version
	ver, err := hdl.GetFirmwareVersion()
	if err == nil {
		s = append(s, fmt.Sprintf("firmware: %s", ver))
	}
	// hardware version
	hw, err := hdl.GetHardwareVersion()
	if err == nil {
		s = append(s, fmt.Sprintf("hardware: %s", hw))
	}
	// capabilities
	caps, err := hdl.GetAllCaps()
	if err == nil {
		s = append(s, fmt.Sprintf("capabilities:\n%s", caps))
	}
	// hardware info
	if caps.HasCap(libjaylink.DEV_CAP_GET_HW_INFO) {
		mask := libjaylink.HW_INFO_TARGET_POWER |
			libjaylink.HW_INFO_ITARGET |
			libjaylink.HW_INFO_ITARGET_PEAK
		info, err := hdl.GetHardwareInfo(mask)
		if err == nil {
			s = append(s, fmt.Sprintf("target power: %x", info[0]))
			s = append(s, fmt.Sprintf("target current: %x", info[1]))
			s = append(s, fmt.Sprintf("peak target current: %x", info[2]))
		}
	}
	// free memory
	if caps.HasCap(libjaylink.DEV_CAP_GET_FREE_MEMORY) {
		free, err := hdl.GetFreeMemory()
		if err == nil {
			s = append(s, fmt.Sprintf("free memory: %d bytes", free))
		}
	}
	// hardware status
	status, err := hdl.GetHardwareStatus()
	if err == nil {
		s = append(s, fmt.Sprintf("status: %s", status))
	}
	// config
	config, err := hdl.ReadRawConfig()
	if err == nil {
		s = append(s, fmt.Sprintf("config: %v", config))
	}

	return strings.Join(s, "\n")
}

//-----------------------------------------------------------------------------

func libTest() error {

	fmt.Printf("package: %s\n", libjaylink.VersionPackageGetString())
	fmt.Printf("library: %s\n", libjaylink.VersionLibraryGetString())

	ctx, err := libjaylink.Init()
	if err != nil {
		return err
	}
	defer ctx.Exit()

	err = ctx.LogSetCallback(logCallback, nil)
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
		fmt.Printf("device %d\n%s\n", i, displayDevice(&dev[i]))

		hdl, err := dev[i].Open()
		if err != nil {
			fmt.Printf("%s\n", err)
			continue
		}

		fmt.Printf("%s\n", displayHandle(hdl))

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
