//-----------------------------------------------------------------------------
/*

C-Go glue to the C-based libjaylink library.
See: https://gitlab.zapb.de/zapb/libjaylink

*/
//-----------------------------------------------------------------------------

package libjaylink

//-----------------------------------------------------------------------------

/*
#cgo pkg-config: libusb-1.0
#cgo pkg-config: libjaylink
#include <libjaylink/libjaylink.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"math/bits"
	"net"
	"strings"
	"unsafe"
)

//-----------------------------------------------------------------------------
// Errors

// Error stores C API error codes.
type Error struct {
	name string // function name
	rc   int    // C return code
}

func rcString(rc int) string {
	rcStrings := map[int]string{
		C.JAYLINK_OK:                    "no error",
		C.JAYLINK_ERR:                   "unspecified error",
		C.JAYLINK_ERR_ARG:               "invalid argument",
		C.JAYLINK_ERR_MALLOC:            "memory allocation error",
		C.JAYLINK_ERR_TIMEOUT:           "timeout occurred",
		C.JAYLINK_ERR_PROTO:             "protocol violation",
		C.JAYLINK_ERR_NOT_AVAILABLE:     "entity not available",
		C.JAYLINK_ERR_NOT_SUPPORTED:     "operation not supported",
		C.JAYLINK_ERR_IO:                "input/output error",
		C.JAYLINK_ERR_DEV:               "device: unspecified error",
		C.JAYLINK_ERR_DEV_NOT_SUPPORTED: "device: operation not supported",
		C.JAYLINK_ERR_DEV_NOT_AVAILABLE: "device: entity not available",
		C.JAYLINK_ERR_DEV_NO_MEMORY:     "device: not enough memory to perform operation",
	}
	s, ok := rcStrings[rc]
	if !ok {
		return fmt.Sprintf("unknown(%d)", rc)
	}
	return s
}

func newError(name string, rc int) *Error {
	return &Error{
		name: name,
		rc:   rc,
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s failed, %s", e.name, rcString(e.rc))
}

// StrError returns a human-readable description of the error code.
func StrError(code int) string {
	cStr := C.jaylink_strerror(C.int(code))
	return C.GoString(cStr)
}

// StrErrorName returns the name of the error code.
func StrErrorName(code int) string {
	cStr := C.jaylink_strerror_name(C.int(code))
	return C.GoString(cStr)
}

//-----------------------------------------------------------------------------

// HostInterface stores the host interface type.
type HostInterface uint32

// HostInterface values.
const (
	HIF_USB HostInterface = C.JAYLINK_HIF_USB
	HIF_TCP HostInterface = C.JAYLINK_HIF_TCP
)

func (h HostInterface) String() string {
	s := []string{}
	if h&HIF_USB != 0 {
		s = append(s, "usb")
	}
	if h&HIF_TCP != 0 {
		s = append(s, "tcp")
	}
	return strings.Join(s, ",")
}

//-----------------------------------------------------------------------------

// HardwareType stores the Segger hardware type.
type HardwareType uint32

// HardwareType values.
const (
	HW_TYPE_JLINK     HardwareType = C.JAYLINK_HW_TYPE_JLINK
	HW_TYPE_FLASHER   HardwareType = C.JAYLINK_HW_TYPE_FLASHER
	HW_TYPE_JLINK_PRO HardwareType = C.JAYLINK_HW_TYPE_JLINK_PRO
)

// HardwareVersion stores the Segger hardware version.
type HardwareVersion struct {
	typ      HardwareType
	major    uint8
	minor    uint8
	revision uint8
}

func (h HardwareVersion) String() string {
	s := map[HardwareType]string{HW_TYPE_JLINK: "jlink", HW_TYPE_FLASHER: "flasher", HW_TYPE_JLINK_PRO: "jlinkpro"}
	return fmt.Sprintf("%s %d.%d.%d", s[h.typ], h.major, h.minor, h.revision)
}

//-----------------------------------------------------------------------------

// UsbAddress stores the USB address number (PID).
type UsbAddress uint32

// UsbAddress values.
const (
	USB_ADDRESS_0 UsbAddress = C.JAYLINK_USB_ADDRESS_0 // USB address 0 (Product ID 0x0101)
	USB_ADDRESS_1 UsbAddress = C.JAYLINK_USB_ADDRESS_1 // USB address 1 (Product ID 0x0102)
	USB_ADDRESS_2 UsbAddress = C.JAYLINK_USB_ADDRESS_2 // USB address 2 (Product ID 0x0103)
	USB_ADDRESS_3 UsbAddress = C.JAYLINK_USB_ADDRESS_3 // USB address 3 (Product ID 0x0104)
)

func (u UsbAddress) String() string {
	return map[UsbAddress]string{
		USB_ADDRESS_0: "0x0101",
		USB_ADDRESS_1: "0x0102",
		USB_ADDRESS_2: "0x0103",
		USB_ADDRESS_3: "0x0104",
	}[u]
}

//-----------------------------------------------------------------------------

// HardwareInfo is a hardware information bitmap.
type HardwareInfo uint32

// HardwareInfo bit values.
const (
	HW_INFO_TARGET_POWER HardwareInfo = C.JAYLINK_HW_INFO_TARGET_POWER
	HW_INFO_ITARGET      HardwareInfo = C.JAYLINK_HW_INFO_ITARGET
	HW_INFO_ITARGET_PEAK HardwareInfo = C.JAYLINK_HW_INFO_ITARGET_PEAK
	HW_INFO_IPV4_ADDRESS HardwareInfo = C.JAYLINK_HW_INFO_IPV4_ADDRESS
	HW_INFO_IPV4_NETMASK HardwareInfo = C.JAYLINK_HW_INFO_IPV4_NETMASK
	HW_INFO_IPV4_GATEWAY HardwareInfo = C.JAYLINK_HW_INFO_IPV4_GATEWAY
	HW_INFO_IPV4_DNS     HardwareInfo = C.JAYLINK_HW_INFO_IPV4_DNS
)

//-----------------------------------------------------------------------------

func boolToInt(x bool) int {
	if x {
		return 1
	}
	return 0
}

// HardwareStatus stores the device hardware status.
type HardwareStatus struct {
	TargetVoltage uint16 // Target reference voltage in mV
	Tck           bool   // TCK pin state
	Tdi           bool   // TDI pin state
	Tdo           bool   // TDO pin state
	Tms           bool   // TMS pin state
	Tres          bool   // TRES pin state
	Trst          bool   // TRST pin state
}

func (hs *HardwareStatus) String() string {
	s := []string{}
	s = append(s, fmt.Sprintf("target_voltage %d", hs.TargetVoltage))
	s = append(s, fmt.Sprintf("tck %d", boolToInt(hs.Tck)))
	s = append(s, fmt.Sprintf("tdi %d", boolToInt(hs.Tdi)))
	s = append(s, fmt.Sprintf("tdo %d", boolToInt(hs.Tdo)))
	s = append(s, fmt.Sprintf("tms %d", boolToInt(hs.Tms)))
	s = append(s, fmt.Sprintf("tres %d", boolToInt(hs.Tres)))
	s = append(s, fmt.Sprintf("trst %d", boolToInt(hs.Trst)))
	return strings.Join(s, " ")
}

//-----------------------------------------------------------------------------

// Capabilities is a bitmap of device capabilities.
type Capabilities []byte

// DeviceCapability is a bit position within the capabilities bitmap.
type DeviceCapability uint

// DeviceCapability values.
const (
	// libjaylink values
	DEV_CAP_GET_HW_VERSION    DeviceCapability = C.JAYLINK_DEV_CAP_GET_HW_VERSION
	DEV_CAP_ADAPTIVE_CLOCKING DeviceCapability = C.JAYLINK_DEV_CAP_ADAPTIVE_CLOCKING
	DEV_CAP_READ_CONFIG       DeviceCapability = C.JAYLINK_DEV_CAP_READ_CONFIG
	DEV_CAP_WRITE_CONFIG      DeviceCapability = C.JAYLINK_DEV_CAP_WRITE_CONFIG
	DEV_CAP_GET_SPEEDS        DeviceCapability = C.JAYLINK_DEV_CAP_GET_SPEEDS
	DEV_CAP_GET_FREE_MEMORY   DeviceCapability = C.JAYLINK_DEV_CAP_GET_FREE_MEMORY
	DEV_CAP_GET_HW_INFO       DeviceCapability = C.JAYLINK_DEV_CAP_GET_HW_INFO
	DEV_CAP_SET_TARGET_POWER  DeviceCapability = C.JAYLINK_DEV_CAP_SET_TARGET_POWER
	DEV_CAP_SELECT_TIF        DeviceCapability = C.JAYLINK_DEV_CAP_SELECT_TIF
	DEV_CAP_GET_COUNTERS      DeviceCapability = C.JAYLINK_DEV_CAP_GET_COUNTERS
	DEV_CAP_SWO               DeviceCapability = C.JAYLINK_DEV_CAP_SWO
	DEV_CAP_FILE_IO           DeviceCapability = C.JAYLINK_DEV_CAP_FILE_IO
	DEV_CAP_REGISTER          DeviceCapability = C.JAYLINK_DEV_CAP_REGISTER
	DEV_CAP_GET_EXT_CAPS      DeviceCapability = C.JAYLINK_DEV_CAP_GET_EXT_CAPS
	DEV_CAP_EMUCOM            DeviceCapability = C.JAYLINK_DEV_CAP_EMUCOM
	DEV_CAP_ETHERNET          DeviceCapability = C.JAYLINK_DEV_CAP_ETHERNET
	// from jlink docs
	DEV_CAP_RESERVED_1         DeviceCapability = 0
	DEV_CAP_WRITE_DCC          DeviceCapability = 2
	DEV_CAP_TRACE              DeviceCapability = 6
	DEV_CAP_WRITE_MEM          DeviceCapability = 7
	DEV_CAP_READ_MEM           DeviceCapability = 8
	DEV_CAP_EXEC_CODE          DeviceCapability = 10
	DEV_CAP_RESET_STOP_TIMED   DeviceCapability = 14
	DEV_CAP_RESERVED_2         DeviceCapability = 15
	DEV_CAP_MEASURE_RTCK_REACT DeviceCapability = 16
	DEV_CAP_RW_MEM_ARM79       DeviceCapability = 18
	DEV_CAP_READ_DCC           DeviceCapability = 20
	DEV_CAP_GET_CPU_CAPS       DeviceCapability = 21
	DEV_CAP_EXEC_CPU_CMD       DeviceCapability = 22
	DEV_CAP_WRITE_DCC_EX       DeviceCapability = 24
	DEV_CAP_UPDATE_FIRMWARE_EX DeviceCapability = 25
	DEV_CAP_INDICATORS         DeviceCapability = 28
	DEV_CAP_TEST_NET_SPEED     DeviceCapability = 29
	DEV_CAP_RAWTRACE           DeviceCapability = 30
)

func (dc DeviceCapability) String() string {
	dcStr := map[DeviceCapability]string{
		// libjaylink values
		DEV_CAP_GET_HW_VERSION:    "DEV_CAP_GET_HW_VERSION",
		DEV_CAP_ADAPTIVE_CLOCKING: "DEV_CAP_ADAPTIVE_CLOCKING",
		DEV_CAP_READ_CONFIG:       "DEV_CAP_READ_CONFIG",
		DEV_CAP_WRITE_CONFIG:      "DEV_CAP_WRITE_CONFIG",
		DEV_CAP_GET_SPEEDS:        "DEV_CAP_GET_SPEEDS",
		DEV_CAP_GET_FREE_MEMORY:   "DEV_CAP_GET_FREE_MEMORY",
		DEV_CAP_GET_HW_INFO:       "DEV_CAP_GET_HW_INFO",
		DEV_CAP_SET_TARGET_POWER:  "DEV_CAP_SET_TARGET_POWER",
		DEV_CAP_SELECT_TIF:        "DEV_CAP_SELECT_TIF",
		DEV_CAP_GET_COUNTERS:      "DEV_CAP_GET_COUNTERS",
		DEV_CAP_SWO:               "DEV_CAP_SWO",
		DEV_CAP_FILE_IO:           "DEV_CAP_FILE_IO",
		DEV_CAP_REGISTER:          "DEV_CAP_REGISTER",
		DEV_CAP_GET_EXT_CAPS:      "DEV_CAP_GET_EXT_CAPS",
		DEV_CAP_EMUCOM:            "DEV_CAP_EMUCOM",
		DEV_CAP_ETHERNET:          "DEV_CAP_ETHERNET",
		// from jlink docs
		DEV_CAP_RESERVED_1:         "reserved (always 1)",
		DEV_CAP_WRITE_DCC:          "DEV_CAP_WRITE_DCC",
		DEV_CAP_TRACE:              "DEV_CAP_TRACE",
		DEV_CAP_WRITE_MEM:          "DEV_CAP_WRITE_MEM",
		DEV_CAP_READ_MEM:           "DEV_CAP_READ_MEM",
		DEV_CAP_EXEC_CODE:          "DEV_CAP_EXEC_CODE",
		DEV_CAP_RESET_STOP_TIMED:   "DEV_CAP_RESET_STOP_TIMED",
		DEV_CAP_RESERVED_2:         "reserved",
		DEV_CAP_MEASURE_RTCK_REACT: "DEV_CAP_MEASURE_RTCK_REACT",
		DEV_CAP_RW_MEM_ARM79:       "DEV_CAP_RW_MEM_ARM79",
		DEV_CAP_READ_DCC:           "DEV_CAP_READ_DCC",
		DEV_CAP_GET_CPU_CAPS:       "DEV_CAP_GET_CPU_CAPS",
		DEV_CAP_EXEC_CPU_CMD:       "DEV_CAP_EXEC_CPU_CMD",
		DEV_CAP_WRITE_DCC_EX:       "DEV_CAP_WRITE_DCC_EX",
		DEV_CAP_UPDATE_FIRMWARE_EX: "DEV_CAP_UPDATE_FIRMWARE_EX",
		DEV_CAP_INDICATORS:         "DEV_CAP_INDICATORS",
		DEV_CAP_TEST_NET_SPEED:     "DEV_CAP_TEST_NET_SPEED",
		DEV_CAP_RAWTRACE:           "DEV_CAP_RAWTRACE",
	}
	s, ok := dcStr[dc]
	if !ok {
		return fmt.Sprintf("?")
	}
	return s
}

// HasCap returns true if a capability is present within the capabilities set.
func (caps Capabilities) HasCap(dc DeviceCapability) bool {
	if caps == nil {
		return false
	}
	n := int(dc)
	if n >= (len(caps) << 3) {
		return false
	}
	return caps[n>>3]&(1<<(n&7)) != 0
}

func (caps Capabilities) String() string {
	s := []string{}
	for i := 0; i < (len(caps) << 3); i++ {
		dc := DeviceCapability(i)
		if caps.HasCap(dc) {
			s = append(s, fmt.Sprintf("(%2d) %s", i, dc.String()))
		}
	}
	return strings.Join(s, "\n")
}

//-----------------------------------------------------------------------------

// Context is a structure representing a libjaylink context.
type Context struct {
	ctx  *C.struct_jaylink_context
	devs **C.struct_jaylink_device
}

//-----------------------------------------------------------------------------

// Device is a structure representing a device.
type Device struct {
	dev *C.struct_jaylink_device
}

func (dev *Device) String() string {
	s := []string{}
	// hardware version
	hw, err := dev.GetHardwareVersion()
	if err == nil {
		s = append(s, fmt.Sprintf("hardware_version %s", hw))
	}
	// product name
	name, err := dev.GetProductName()
	if err == nil {
		s = append(s, fmt.Sprintf("product_name %s", name))
	}
	// nickname
	name, err = dev.GetNickName()
	if err == nil {
		s = append(s, fmt.Sprintf("nickname %s", name))
	}
	// serial number
	sn, err := dev.GetSerialNumber()
	if err == nil {
		s = append(s, fmt.Sprintf("serial_number %d", sn))
	}
	// host interface
	hi, err := dev.GetHostInterface()
	if err == nil {
		s = append(s, fmt.Sprintf("host_interface %s", hi.String()))
	}
	// usb address
	addr, err := dev.GetUsbAddress()
	if err == nil {
		s = append(s, fmt.Sprintf("usb_address %s", addr))
	}
	// mac address
	mac, err := dev.GetMacAddress()
	if err == nil {
		s = append(s, fmt.Sprintf("mac_address %s", mac))
	}
	// ipv4 address
	ip, err := dev.GetIPv4Address()
	if err == nil {
		s = append(s, fmt.Sprintf("ipv4_address %s", ip))
	}
	return strings.Join(s, " ")
}

//-----------------------------------------------------------------------------

// DeviceHandle is a structure representing a handle of a device.
type DeviceHandle struct {
	hdl *C.struct_jaylink_device_handle
}

func (hdl *DeviceHandle) String() string {
	s := []string{}

	// firmware version
	ver, err := hdl.GetFirmwareVersion()
	if err == nil {
		s = append(s, fmt.Sprintf("firmware version: %s", ver))
	}

	// capabilities
	caps, err := hdl.GetCaps()
	if err == nil && caps.HasCap(DEV_CAP_GET_EXT_CAPS) {
		caps, err = hdl.GetExtendedCaps()
	}
	if err == nil {
		s = append(s, fmt.Sprintf("capabilities:\n%s", caps))
	}

	// hardware info
	if caps.HasCap(DEV_CAP_GET_HW_INFO) {
		info, err := hdl.GetHardwareInfo(HW_INFO_TARGET_POWER | HW_INFO_ITARGET | HW_INFO_ITARGET_PEAK)
		if err == nil {
			s = append(s, fmt.Sprintf("target power: %x", info[0]))
			s = append(s, fmt.Sprintf("target current: %x", info[1]))
			s = append(s, fmt.Sprintf("peak target current: %x", info[2]))
		}
	}

	// free memory
	if caps.HasCap(DEV_CAP_GET_FREE_MEMORY) {
		free, err := hdl.GetFreeMemory()
		if err == nil {
			s = append(s, fmt.Sprintf("free memory: %d bytes", free))
		}
	}

	status, err := hdl.GetHardwareStatus()
	if err == nil {
		s = append(s, fmt.Sprintf("hardware status: %s", status))
	}

	return strings.Join(s, "\n")
}

//-----------------------------------------------------------------------------
// core.c

// Init initializes libjaylink.
func Init() (*Context, error) {
	ctx := Context{}
	rc := int(C.jaylink_init((**C.struct_jaylink_context)(&ctx.ctx)))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_init", rc)
	}
	return &ctx, nil
}

// Exit shutdowns libjaylink.
func (ctx *Context) Exit() error {
	rc := int(C.jaylink_exit(ctx.ctx))
	if rc != C.JAYLINK_OK {
		return newError("jaylink_exit", rc)
	}
	return nil
}

// LibraryHasCap checks for a capability of libjaylink.
func LibraryHasCap(capability uint) bool {
	return bool(C.jaylink_library_has_cap(uint32(capability)))
}

//-----------------------------------------------------------------------------
// device.c

// GetDevices gets available devices.
func (ctx *Context) GetDevices() ([]Device, error) {
	var count C.size_t
	rc := int(C.jaylink_get_devices(ctx.ctx, &ctx.devs, &count))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_get_devices", rc)
	}
	d := (*[1 << 30]*C.struct_jaylink_device)(unsafe.Pointer(ctx.devs))
	dev := make([]Device, int(count))
	for i := range dev {
		dev[i].dev = d[i]
	}
	return dev, nil
}

// FreeDevices frees devices.
func (ctx *Context) FreeDevices(dev []Device, unref bool) {
	// sanity check, []Device must be read-only
	d := (*[1 << 30]*C.struct_jaylink_device)(unsafe.Pointer(ctx.devs))
	for i := range dev {
		if d[i] != dev[i].dev {
			panic(fmt.Sprintf("dev[%d] pointer has changed", i))
		}
	}
	C.jaylink_free_devices(ctx.devs, C.bool(unref))
}

// GetHostInterface gets the host interface of a device.
func (dev *Device) GetHostInterface() (HostInterface, error) {
	var iface uint32
	rc := int(C.jaylink_device_get_host_interface(dev.dev, &iface))
	if rc != C.JAYLINK_OK {
		return 0, newError("jaylink_device_get_host_interface", rc)
	}
	return HostInterface(iface), nil
}

// GetSerialNumber gets the serial number of a device.
func (dev *Device) GetSerialNumber() (uint, error) {
	var serialNumber C.uint32_t
	rc := int(C.jaylink_device_get_serial_number(dev.dev, &serialNumber))
	if rc != C.JAYLINK_OK {
		return 0, newError("jaylink_device_get_serial_number", rc)
	}
	return uint(serialNumber), nil
}

// GetUsbAddress gets the USB address of a device.
func (dev *Device) GetUsbAddress() (UsbAddress, error) {
	var usbAddress uint32
	rc := int(C.jaylink_device_get_usb_address(dev.dev, &usbAddress))
	if rc != C.JAYLINK_OK {
		return 0, newError("jaylink_device_get_usb_address", rc)
	}
	return UsbAddress(usbAddress), nil
}

// GetUsbPorts gets the USB bus and port numbers of a device.
func (dev *Device) GetUsbPorts() (uint8, []uint8, error) {
	var cLength C.size_t
	var cPorts *C.uint8_t
	var cBus C.uint8_t
	rc := int(C.jaylink_device_get_usb_bus_ports(dev.dev, &cBus, &cPorts, &cLength))
	if rc != C.JAYLINK_OK {
		return 0, nil, newError("jaylink_device_get_usb_bus_ports", rc)
	}
	ports := make([]uint8, cLength)
	p := (*[1 << 30]C.uint8_t)(unsafe.Pointer(cPorts))
	for i := range ports {
		ports[i] = uint8(p[i])
	}
	return uint8(cBus), ports, nil
}

// GetIPv4Address gets the IPv4 address string of a device.
func (dev *Device) GetIPv4Address() (string, error) {
	addr := (*C.char)(C.malloc(C.INET_ADDRSTRLEN))
	defer C.free(unsafe.Pointer(addr))
	rc := int(C.jaylink_device_get_ipv4_address(dev.dev, addr))
	if rc != C.JAYLINK_OK {
		return "", newError("jaylink_device_get_ipv4_address", rc)
	}
	return C.GoString(addr), nil
}

// GetMacAddress gets the MAC address of a device.
func (dev *Device) GetMacAddress() (net.HardwareAddr, error) {
	mac := (*C.uint8_t)(C.malloc(C.JAYLINK_MAC_ADDRESS_LENGTH))
	defer C.free(unsafe.Pointer(mac))
	rc := int(C.jaylink_device_get_mac_address(dev.dev, mac))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_device_get_mac_address", rc)
	}
	m := (*[1 << 30]C.uint8_t)(unsafe.Pointer(mac))
	macAddr := make([]byte, C.JAYLINK_MAC_ADDRESS_LENGTH)
	for i := range macAddr {
		macAddr[i] = byte(m[i])
	}
	return macAddr, nil
}

// GetHardwareVersion gets the hardware version of a device.
func (dev *Device) GetHardwareVersion() (*HardwareVersion, error) {
	var hw C.struct_jaylink_hardware_version
	rc := int(C.jaylink_device_get_hardware_version(dev.dev, &hw))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_device_get_hardware_version", rc)
	}
	h := HardwareVersion{
		//typ: HardwareType(hw.type), TODO
		major:    uint8(hw.major),
		minor:    uint8(hw.minor),
		revision: uint8(hw.revision),
	}
	return &h, nil
}

// GetProductName gets the product name of a device.
func (dev *Device) GetProductName() (string, error) {
	name := (*C.char)(C.malloc(C.JAYLINK_PRODUCT_NAME_MAX_LENGTH))
	defer C.free(unsafe.Pointer(name))
	rc := int(C.jaylink_device_get_product_name(dev.dev, name))
	if rc != C.JAYLINK_OK {
		return "", newError("jaylink_device_get_product_name", rc)
	}
	return C.GoString(name), nil
}

// GetNickName gets the nickname of a device.
func (dev *Device) GetNickName() (string, error) {
	name := (*C.char)(C.malloc(C.JAYLINK_NICKNAME_MAX_LENGTH))
	defer C.free(unsafe.Pointer(name))
	rc := int(C.jaylink_device_get_nickname(dev.dev, name))
	if rc != C.JAYLINK_OK {
		return "", newError("jaylink_device_get_nickname", rc)
	}
	return C.GoString(name), nil
}

// RefDevice increments the reference count of a device.
func (dev *Device) RefDevice() *Device {
	x := C.jaylink_ref_device(dev.dev)
	if x == nil {
		return nil
	}
	return dev
}

// UnrefDevice decrements the reference count of a device.
func (dev *Device) UnrefDevice() {
	C.jaylink_unref_device(dev.dev)
}

// Open opens a device.
func (dev *Device) Open() (*DeviceHandle, error) {
	hdl := DeviceHandle{}
	rc := int(C.jaylink_open(dev.dev, (**C.struct_jaylink_device_handle)(&hdl.hdl)))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_open", rc)
	}
	return &hdl, nil
}

// Close closes a device.
func (hdl *DeviceHandle) Close() error {
	rc := int(C.jaylink_close(hdl.hdl))
	if rc != C.JAYLINK_OK {
		return newError("jaylink_close", rc)
	}
	return nil
}

// GetDevice gets the device instance from a device handle.
func (hdl *DeviceHandle) GetDevice() *Device {
	x := C.jaylink_get_device(hdl.hdl)
	if x == nil {
		return nil
	}
	return &Device{dev: x}
}

// GetFirmwareVersion retrieves the firmware version of a device.
func (hdl *DeviceHandle) GetFirmwareVersion() (string, error) {
	var cVersion *C.char
	var cLength C.size_t
	rc := int(C.jaylink_get_firmware_version(hdl.hdl, &cVersion, &cLength))
	if rc != C.JAYLINK_OK {
		return "", newError("jaylink_get_firmware_version", rc)
	}
	defer C.free(unsafe.Pointer(cVersion))
	return C.GoString(cVersion), nil
}

// GetHardwareInfo retrieves the hardware information of a device.
func (hdl *DeviceHandle) GetHardwareInfo(mask HardwareInfo) ([]uint32, error) {
	cInfo := (*C.uint32_t)(C.malloc(32 * C.sizeof_uint32_t))
	defer C.free(unsafe.Pointer(cInfo))
	rc := int(C.jaylink_get_hardware_info(hdl.hdl, C.uint32_t(mask), cInfo))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_get_hardware_info", rc)
	}
	info := make([]uint32, bits.OnesCount32(uint32(mask)))
	x := (*[1 << 30]C.uint32_t)(unsafe.Pointer(cInfo))
	for i := range info {
		info[i] = uint32(x[i])
	}
	return info, nil
}

/*

// GetCounters retrieves the counter values of a device.
func (hdl *DeviceHandle) GetCounters() error {
		rc := int(C.jaylink_get_counters(hdl.hdl, uint32_t mask, uint32_t *values))
    	if rc != C.JAYLINK_OK {
		return newError("jaylink_get_counters", rc)
	}
}

// GetHardwareVersion retrieves the hardware version of a device.
func (hdl *DeviceHandle) GetHardwareVersion() error {
		rc := int(C.jaylink_get_hardware_version(hdl.hdl, struct jaylink_hardware_version *version))
    	if rc != C.JAYLINK_OK {
		return newError("jaylink_get_hardware_version", rc)
	}
}

*/

// GetHardwareStatus retrieves the hardware status of a device.
func (hdl *DeviceHandle) GetHardwareStatus() (*HardwareStatus, error) {
	var cStatus C.struct_jaylink_hardware_status
	rc := int(C.jaylink_get_hardware_status(hdl.hdl, &cStatus))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_get_hardware_status", rc)
	}
	status := HardwareStatus{
		TargetVoltage: uint16(cStatus.target_voltage),
		Tck:           bool(cStatus.tck),
		Tdi:           bool(cStatus.tdi),
		Tdo:           bool(cStatus.tdo),
		Tms:           bool(cStatus.tms),
		Tres:          bool(cStatus.tres),
		Trst:          bool(cStatus.trst),
	}
	return &status, nil
}

// GetCaps retrieves the capabilities of a device.
func (hdl *DeviceHandle) GetCaps() (Capabilities, error) {
	cCaps := (*C.uint8_t)(C.malloc(C.JAYLINK_DEV_CAPS_SIZE))
	defer C.free(unsafe.Pointer(cCaps))
	rc := int(C.jaylink_get_caps(hdl.hdl, cCaps))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_get_caps", rc)
	}
	x := (*[1 << 30]C.uint8_t)(unsafe.Pointer(cCaps))
	caps := make([]byte, C.JAYLINK_DEV_CAPS_SIZE)
	for i := range caps {
		caps[i] = byte(x[i])
	}
	return caps, nil
}

// GetExtendedCaps retrieves the extended capabilities of a device.
func (hdl *DeviceHandle) GetExtendedCaps() (Capabilities, error) {
	cCaps := (*C.uint8_t)(C.malloc(C.JAYLINK_DEV_EXT_CAPS_SIZE))
	defer C.free(unsafe.Pointer(cCaps))
	rc := int(C.jaylink_get_extended_caps(hdl.hdl, cCaps))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_get_extended_caps", rc)
	}
	x := (*[1 << 30]C.uint8_t)(unsafe.Pointer(cCaps))
	caps := make([]byte, C.JAYLINK_DEV_EXT_CAPS_SIZE)
	for i := range caps {
		caps[i] = byte(x[i])
	}
	return caps, nil
}

// GetFreeMemory retrieves the size of free memory of a device.
func (hdl *DeviceHandle) GetFreeMemory() (uint32, error) {
	var cSize C.uint32_t
	rc := int(C.jaylink_get_free_memory(hdl.hdl, &cSize))
	if rc != C.JAYLINK_OK {
		return 0, newError("jaylink_get_free_memory", rc)
	}
	return uint32(cSize), nil
}

/*

// ReadRawConfig reads the raw configuration data of a device.
func (hdl *DeviceHandle) ReadRawConfig() error {
		rc := int(C.jaylink_read_raw_config(hdl.hdl, uint8_t *config))
    	if rc != C.JAYLINK_OK {
		return newError("jaylink_read_raw_config", rc)
	}
}

// WriteRawConfig writes the raw configuration data of a device.
func (hdl *DeviceHandle) WriteRawConfig() error {
		rc := int(C.jaylink_write_raw_config(hdl.hdl, const uint8_t *config))
    	if rc != C.JAYLINK_OK {
		return newError("jaylink_write_raw_config", rc)
	}
}

// Register registers a connection on a device.
func (hdl *DeviceHandle) Register() error {
		rc := int(C.jaylink_register(hdl.hdl, struct jaylink_connection *connection, struct jaylink_connection *connections, size_t *count))
    	if rc != C.JAYLINK_OK {
		return newError("jaylink_register", rc)
	}
}

// Unregister unregisters a connection from a device.
func (hdl *DeviceHandle) Unregister() error {
		rc := int(C.jaylink_unregister(hdl.hdl, const struct jaylink_connection *connection, struct jaylink_connection *connections, size_t *count))
    	if rc != C.JAYLINK_OK {
		return newError("jaylink_unregister", rc)
	}
}

*/

//-----------------------------------------------------------------------------
// discovery.c

// DiscoveryScan scans for devices.
func (ctx *Context) DiscoveryScan(ifaces HostInterface) error {
	rc := int(C.jaylink_discovery_scan(ctx.ctx, C.uint32_t(ifaces)))
	if rc != C.JAYLINK_OK {
		return newError("jaylink_discovery_scan", rc)
	}
	return nil
}

//-----------------------------------------------------------------------------
// emucom.c

// int jaylink_emucom_read(struct jaylink_device_handle *devh, uint32_t channel, uint8_t *buffer, uint32_t *length);
// int jaylink_emucom_write(struct jaylink_device_handle *devh, uint32_t channel, const uint8_t *buffer, uint32_t *length);

//-----------------------------------------------------------------------------
// fileio.c

// int jaylink_file_read(struct jaylink_device_handle *devh, const char *filename, uint8_t *buffer, uint32_t offset, uint32_t *length);
// int jaylink_file_write(struct jaylink_device_handle *devh, const char *filename, const uint8_t *buffer, uint32_t offset, uint32_t *length);
// int jaylink_file_get_size(struct jaylink_device_handle *devh, const char *filename, uint32_t *size);
// int jaylink_file_delete(struct jaylink_device_handle *devh, const char *filename);

//-----------------------------------------------------------------------------
// jtag.c

// JtagVersion is the JTAG command version.
type JtagVersion uint32

// JtagVersion values.
const (
	JTAG_VERSION_2 JtagVersion = C.JAYLINK_JTAG_VERSION_2 // JTAG command version 2. Obsolete for major hardware version 5 and above, use Version 3.
	JTAG_VERSION_3 JtagVersion = C.JAYLINK_JTAG_VERSION_3 // JTAG command version 3
)

// copyBufferGo2C copies a Go []byte buffer to a C uint8_t buffer.
// Call freeBuffer on the returned C buffer.
func copyBufferGo2C(buf []byte) *C.uint8_t {
	return (*C.uint8_t)(unsafe.Pointer(C.CString(string(buf))))
}

// copyBufferC2Go copies a C uint8_t buffer to a Go []byte buffer.
func copyBufferC2Go(buf *C.uint8_t, n int) []byte {
	x := (*[1 << 30]C.uint8_t)(unsafe.Pointer(buf))
	goBuf := make([]byte, n)
	for i := range goBuf {
		goBuf[i] = byte(x[i])
	}
	return goBuf
}

// allocBuffer allocates a C uint8_t buffer of length n bytes.
// Call freeBuffer on the returned C buffer.
func allocBuffer(n int) *C.uint8_t {
	return (*C.uint8_t)(C.malloc(C.ulong(n)))
}

// freeBuffer frees a C uint8_t buffer.
func freeBuffer(buf *C.uint8_t) {
	C.free(unsafe.Pointer(buf))
}

// JtagIO performs a JTAG I/O operation.
func (hdl *DeviceHandle) JtagIO(tms, tdi []byte, version JtagVersion) ([]byte, error) {
	n := len(tms)
	if len(tdi) != n {
		panic("len(tms) != len(tdi)")
	}
	cTms := copyBufferGo2C(tms)
	defer freeBuffer(cTms)
	cTdi := copyBufferGo2C(tdi)
	defer freeBuffer(cTdi)
	cTdo := allocBuffer(n)
	defer freeBuffer(cTdo)
	rc := int(C.jaylink_jtag_io(hdl.hdl, cTms, cTdi, cTdo, C.uint16_t(n), uint32(version)))
	if rc != C.JAYLINK_OK {
		return nil, newError("jaylink_jtag_io", rc)
	}
	return copyBufferC2Go(cTdo, n), nil
}

// JtagClearTrst clears the JTAG test reset (TRST) signal.
func (hdl *DeviceHandle) JtagClearTrst() error {
	rc := int(C.jaylink_jtag_clear_trst(hdl.hdl))
	if rc != C.JAYLINK_OK {
		return newError("jaylink_jtag_clear_trst", rc)
	}
	return nil
}

// JtagSetTrst sets the JTAG test reset (TRST) signal.
func (hdl *DeviceHandle) JtagSetTrst() error {
	rc := int(C.jaylink_jtag_set_trst(hdl.hdl))
	if rc != C.JAYLINK_OK {
		return newError("jaylink_jtag_set_trst", rc)
	}
	return nil
}

//-----------------------------------------------------------------------------
// Logging

// LogLevel is the log level.
type LogLevel uint32

// LogLevel values.
const (
	LOG_LEVEL_NONE     LogLevel = C.JAYLINK_LOG_LEVEL_NONE     // no messages
	LOG_LEVEL_ERROR    LogLevel = C.JAYLINK_LOG_LEVEL_ERROR    // error messages
	LOG_LEVEL_WARNING  LogLevel = C.JAYLINK_LOG_LEVEL_WARNING  // warnings
	LOG_LEVEL_INFO     LogLevel = C.JAYLINK_LOG_LEVEL_INFO     // informational messages
	LOG_LEVEL_DEBUG    LogLevel = C.JAYLINK_LOG_LEVEL_DEBUG    // debug messages
	LOG_LEVEL_DEBUG_IO LogLevel = C.JAYLINK_LOG_LEVEL_DEBUG_IO // I/O debug messages
)

// LogSetLevel sets the log level.
func (ctx *Context) LogSetLevel(level LogLevel) error {
	var cLevel uint32
	rc := int(C.jaylink_log_set_level(ctx.ctx, cLevel))
	if rc != C.JAYLINK_OK {
		return newError("jaylink_log_set_level", rc)
	}
	return nil
}

// LogGetLevel gets the log level.
func (ctx *Context) LogGetLevel() (LogLevel, error) {
	var cLevel uint32
	rc := int(C.jaylink_log_get_level(ctx.ctx, &cLevel))
	if rc != C.JAYLINK_OK {
		return 0, newError("jaylink_log_get_level", rc)
	}
	return LogLevel(cLevel), nil
}

/*

// LogSetCallback sets the log callback function.
func (ctx *Context) LogSetCallback() error {
  rc := int(C.jaylink_log_set_callback(ctx.ctx, jaylink_log_callback callback, void *user_data))
}

*/

// LogSetDomain sets the log domain.
func (ctx *Context) LogSetDomain(domain string) error {
	cDomain := C.CString(domain)
	defer C.free(unsafe.Pointer(cDomain))
	rc := int(C.jaylink_log_set_domain(ctx.ctx, cDomain))
	if rc != C.JAYLINK_OK {
		return newError("jaylink_log_set_domain", rc)
	}
	return nil
}

// LogGetDomain gets the log domain.
func (ctx *Context) LogGetDomain() string {
	cDomain := C.jaylink_log_get_domain(ctx.ctx)
	return C.GoString(cDomain)
}

//-----------------------------------------------------------------------------
// swd.c

// int jaylink_swd_io(struct jaylink_device_handle *devh, const uint8_t *direction, const uint8_t *out, uint8_t *in, uint16_t length);

//-----------------------------------------------------------------------------
// swo.c

// int jaylink_swo_start(struct jaylink_device_handle *devh, enum jaylink_swo_mode mode, uint32_t baudrate, uint32_t size);
// int jaylink_swo_stop(struct jaylink_device_handle *devh);
// int jaylink_swo_read(struct jaylink_device_handle *devh, uint8_t *buffer, uint32_t *length);
// int jaylink_swo_get_speeds(struct jaylink_device_handle *devh, enum jaylink_swo_mode mode, struct jaylink_swo_speed *speed);

//-----------------------------------------------------------------------------
// target.c

// int jaylink_set_speed(struct jaylink_device_handle *devh, uint16_t speed);
// int jaylink_get_speeds(struct jaylink_device_handle *devh, struct jaylink_speed *speed);
// int jaylink_select_interface(struct jaylink_device_handle *devh, enum jaylink_target_interface iface, enum jaylink_target_interface *prev_iface);
// int jaylink_get_available_interfaces(struct jaylink_device_handle *devh, uint32_t *ifaces);
// int jaylink_get_selected_interface(struct jaylink_device_handle *devh, enum jaylink_target_interface *iface);
// int jaylink_clear_reset(struct jaylink_device_handle *devh);
// int jaylink_set_reset(struct jaylink_device_handle *devh);
// int jaylink_set_target_power(struct jaylink_device_handle *devh, bool enable);

//-----------------------------------------------------------------------------
// version.c

// VersionPackageGetMajor gets the major version number of the libjaylink package.
func VersionPackageGetMajor() int {
	return int(C.jaylink_version_package_get_major())
}

// VersionPackageGetMinor gets the minor version number of the libjaylink package.
func VersionPackageGetMinor() int {
	return int(C.jaylink_version_package_get_minor())
}

// VersionPackageGetMicro gets the micro version number of the libjaylink package.
func VersionPackageGetMicro() int {
	return int(C.jaylink_version_package_get_micro())
}

// VersionPackageGetString gets the version number string of the libjaylink package.
func VersionPackageGetString() string {
	return C.GoString(C.jaylink_version_package_get_string())
}

// VersionLibraryGetCurrent gets the current version number of the libjaylink libtool interface.
func VersionLibraryGetCurrent() int {
	return int(C.jaylink_version_library_get_current())
}

// VersionLibraryGetRevision gets the revision version number of the libjaylink libtool interface.
func VersionLibraryGetRevision() int {
	return int(C.jaylink_version_library_get_revision())
}

// VersionLibraryGetAge gets the age version number of the libjaylink libtool interface.
func VersionLibraryGetAge() int {
	return int(C.jaylink_version_library_get_age())
}

// VersionLibraryGetString gets the version number string of the libjaylink libtool interface.
func VersionLibraryGetString() string {
	return C.GoString(C.jaylink_version_library_get_string())
}

//-----------------------------------------------------------------------------
