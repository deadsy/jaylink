//-----------------------------------------------------------------------------
/*

Go bindings for the libjaylink library.

See: https://github.com/deadsy/libjaylink
See: https://gitlab.zapb.de/zapb/libjaylink

*/
//-----------------------------------------------------------------------------

package jaylink

/*
#cgo pkg-config: libusb-1.0
#cgo pkg-config: libjaylink
#include <libjaylink/libjaylink.h>
#include <stdlib.h>

uint32_t get_hw_type(struct jaylink_hardware_version *h);

int LogCallback(const struct jaylink_context *ctx, enum jaylink_log_level level,
  const char *format, va_list args, void *user_data);

*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"
)

//-----------------------------------------------------------------------------
// utility functions

// go2cBuffer creates a C uint8_t buffer from a Go []byte buffer.
// Call freeBuffer on the returned C buffer.
func go2cBuffer(buf []byte) *C.uint8_t {
	return (*C.uint8_t)(unsafe.Pointer(C.CString(string(buf))))
}

// c2goCopy copies a C uint8_t buffer into a Go []byte slice.
func c2goCopy(s []byte, buf *C.uint8_t) []byte {
	x := (*[1 << 30]byte)(unsafe.Pointer(buf))
	copy(s, x[:])
	return s
}

// c2goSlice creates a Go []byte slice and copies in a C uint8_t buffer.
func c2goSlice(buf *C.uint8_t, n int) []byte {
	s := make([]byte, n)
	return c2goCopy(s, buf)
}

// allocBuffer allocates a C uint8_t buffer of length n bytes.
// Call freeBuffer on the returned C buffer.
func allocBuffer(n int) *C.uint8_t {
	return (*C.uint8_t)(C.malloc(C.size_t(n)))
}

// freeBuffer frees a C uint8_t buffer.
func freeBuffer(buf *C.uint8_t) {
	C.free(unsafe.Pointer(buf))
}

// boolToInt converts a boolean to an int.
func boolToInt(x bool) int {
	if x {
		return 1
	}
	return 0
}

// onesCount32 returns the number of 1's in a uint32.
func onesCount32(x uint32) int {
	i := 0
	for x != 0 {
		if x&1 != 0 {
			i++
		}
		x >>= 1
	}
	return i
}

//-----------------------------------------------------------------------------
// Errors

// Error stores error information.
type Error struct {
	Name string // function name
	Code int    // C return code
}

// apiError returns an C-API error.
func apiError(name string, rc int) *Error {
	return &Error{
		Name: name,
		Code: rc,
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s failed, %s", e.Name, StrError(e.Code))
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

// HostInterface is the host interface bitmap.
// When used for device discovery multiple bits are set.
// When used for specific devices one bit is set for the interface type.
type HostInterface uint32

// HostInterface bitmap values.
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
	if len(s) != 0 {
		return strings.Join(s, ",")
	}
	return "unknown"
}

// GetHostInterface gets the host interface of a device.
func (dev *Device) GetHostInterface() (HostInterface, error) {
	var iface uint32
	rc := int(C.jaylink_device_get_host_interface(dev.dev, &iface))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_device_get_host_interface", rc)
	}
	return HostInterface(iface), nil
}

//-----------------------------------------------------------------------------

// HardwareType is the device hardware type.
type HardwareType uint32

// HardwareType values.
const (
	// libjaylink values
	HW_TYPE_JLINK     HardwareType = C.JAYLINK_HW_TYPE_JLINK
	HW_TYPE_FLASHER   HardwareType = C.JAYLINK_HW_TYPE_FLASHER
	HW_TYPE_JLINK_PRO HardwareType = C.JAYLINK_HW_TYPE_JLINK_PRO
	// other values
	HW_TYPE_JTRACE             HardwareType = 1
	HW_TYPE_JLINK_LITE_ADI     HardwareType = 5
	HW_TYPE_JLINK_LITE_XMC4000 HardwareType = 16
	HW_TYPE_JLINK_LITE_XMC4200 HardwareType = 17
	HW_TYPE_LPCLINK2           HardwareType = 18
)

func (h HardwareType) String() string {
	names := map[HardwareType]string{
		HW_TYPE_JLINK:              "J-link",
		HW_TYPE_FLASHER:            "Flasher",
		HW_TYPE_JLINK_PRO:          "J-Link Pro",
		HW_TYPE_JTRACE:             "J-Trace",
		HW_TYPE_JLINK_LITE_ADI:     "J-Link Lite-ADI",
		HW_TYPE_JLINK_LITE_XMC4000: "J-Link Lite-XMC4000",
		HW_TYPE_JLINK_LITE_XMC4200: "J-Link Lite-XMC4200",
		HW_TYPE_LPCLINK2:           "J-Link on LPC-Link2",
	}
	if s, ok := names[h]; ok {
		return s
	}
	return "unknown"
}

//-----------------------------------------------------------------------------

// HardwareVersion is the hardware type and version.
type HardwareVersion struct {
	Hwtype   HardwareType
	Major    uint8
	Minor    uint8
	Revision uint8
}

func (h HardwareVersion) String() string {
	return fmt.Sprintf("%s %d.%d.%d", h.Hwtype, h.Major, h.Minor, h.Revision)
}

func c2goHardwareVersion(hw *C.struct_jaylink_hardware_version) *HardwareVersion {
	return &HardwareVersion{
		Hwtype:   HardwareType(C.get_hw_type(hw)),
		Major:    uint8(hw.major),
		Minor:    uint8(hw.minor),
		Revision: uint8(hw.revision),
	}
}

// GetHardwareVersion gets the hardware version of a device.
func (dev *Device) GetHardwareVersion() (*HardwareVersion, error) {
	var hw C.struct_jaylink_hardware_version
	rc := int(C.jaylink_device_get_hardware_version(dev.dev, &hw))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_device_get_hardware_version", rc)
	}
	return c2goHardwareVersion(&hw), nil
}

// GetHardwareVersion gets the hardware version of a device.
func (hdl *DeviceHandle) GetHardwareVersion() (*HardwareVersion, error) {
	var hw C.struct_jaylink_hardware_version
	rc := int(C.jaylink_get_hardware_version(hdl.hdl, &hw))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_get_hardware_version", rc)
	}
	return c2goHardwareVersion(&hw), nil
}

//-----------------------------------------------------------------------------

// UsbAddress stores the USB address number (Product ID).
type UsbAddress uint32

// UsbAddress values.
const (
	USB_ADDRESS_0 UsbAddress = C.JAYLINK_USB_ADDRESS_0 // USB address 0 (Product ID 0x0101)
	USB_ADDRESS_1 UsbAddress = C.JAYLINK_USB_ADDRESS_1 // USB address 1 (Product ID 0x0102)
	USB_ADDRESS_2 UsbAddress = C.JAYLINK_USB_ADDRESS_2 // USB address 2 (Product ID 0x0103)
	USB_ADDRESS_3 UsbAddress = C.JAYLINK_USB_ADDRESS_3 // USB address 3 (Product ID 0x0104)
)

func (u UsbAddress) String() string {
	names := map[UsbAddress]string{
		USB_ADDRESS_0: "0x0101",
		USB_ADDRESS_1: "0x0102",
		USB_ADDRESS_2: "0x0103",
		USB_ADDRESS_3: "0x0104",
	}
	if s, ok := names[u]; ok {
		return s
	}
	return "unknown"
}

// GetUsbAddress gets the USB address of a device.
func (dev *Device) GetUsbAddress() (UsbAddress, error) {
	var usbAddress uint32
	rc := int(C.jaylink_device_get_usb_address(dev.dev, &usbAddress))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_device_get_usb_address", rc)
	}
	return UsbAddress(usbAddress), nil
}

//-----------------------------------------------------------------------------

// HardwareInfo is a hardware information bitmap.
type HardwareInfo uint32

// HardwareInfo bitmap values.
const (
	HW_INFO_TARGET_POWER HardwareInfo = C.JAYLINK_HW_INFO_TARGET_POWER
	HW_INFO_ITARGET      HardwareInfo = C.JAYLINK_HW_INFO_ITARGET
	HW_INFO_ITARGET_PEAK HardwareInfo = C.JAYLINK_HW_INFO_ITARGET_PEAK
	HW_INFO_IPV4_ADDRESS HardwareInfo = C.JAYLINK_HW_INFO_IPV4_ADDRESS
	HW_INFO_IPV4_NETMASK HardwareInfo = C.JAYLINK_HW_INFO_IPV4_NETMASK
	HW_INFO_IPV4_GATEWAY HardwareInfo = C.JAYLINK_HW_INFO_IPV4_GATEWAY
	HW_INFO_IPV4_DNS     HardwareInfo = C.JAYLINK_HW_INFO_IPV4_DNS
)

// GetHardwareInfo retrieves the hardware information of a device.
func (hdl *DeviceHandle) GetHardwareInfo(mask HardwareInfo) ([]uint32, error) {
	cInfo := (*C.uint32_t)(C.malloc(32 * C.sizeof_uint32_t))
	defer C.free(unsafe.Pointer(cInfo))
	rc := int(C.jaylink_get_hardware_info(hdl.hdl, C.uint32_t(mask), cInfo))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_get_hardware_info", rc)
	}
	info := make([]uint32, onesCount32(uint32(mask)))
	x := (*[1 << 30]C.uint32_t)(unsafe.Pointer(cInfo))
	for i := range info {
		info[i] = uint32(x[i])
	}
	return info, nil
}

//-----------------------------------------------------------------------------

// Counter is a device counters bitmap.
type Counter uint32

// Counter bitmap values.
const (
	COUNTER_TARGET_TIME        Counter = C.JAYLINK_COUNTER_TARGET_TIME        // Time the device is connected to a target in milliseconds.
	COUNTER_TARGET_CONNECTIONS Counter = C.JAYLINK_COUNTER_TARGET_CONNECTIONS // Number of times the device was connected or disconnected from a target.
)

// GetCounters retrieves the counter values of a device.
func (hdl *DeviceHandle) GetCounters(mask Counter) ([]uint32, error) {
	cValues := (*C.uint32_t)(C.malloc(32 * C.sizeof_uint32_t))
	defer C.free(unsafe.Pointer(cValues))
	rc := int(C.jaylink_get_counters(hdl.hdl, C.uint32_t(mask), cValues))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_get_counters", rc)
	}
	values := make([]uint32, onesCount32(uint32(mask)))
	x := (*[1 << 30]C.uint32_t)(unsafe.Pointer(cValues))
	for i := range values {
		values[i] = uint32(x[i])
	}
	return values, nil
}

//-----------------------------------------------------------------------------

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
	s = append(s, fmt.Sprintf("target voltage %d mV,", hs.TargetVoltage))
	s = append(s, fmt.Sprintf("tck %d", boolToInt(hs.Tck)))
	s = append(s, fmt.Sprintf("tdi %d", boolToInt(hs.Tdi)))
	s = append(s, fmt.Sprintf("tdo %d", boolToInt(hs.Tdo)))
	s = append(s, fmt.Sprintf("tms %d", boolToInt(hs.Tms)))
	s = append(s, fmt.Sprintf("tres %d", boolToInt(hs.Tres)))
	s = append(s, fmt.Sprintf("trst %d", boolToInt(hs.Trst)))
	return strings.Join(s, " ")
}

// GetHardwareStatus retrieves the hardware status of a device.
func (hdl *DeviceHandle) GetHardwareStatus() (*HardwareStatus, error) {
	var cStatus C.struct_jaylink_hardware_status
	rc := int(C.jaylink_get_hardware_status(hdl.hdl, &cStatus))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_get_hardware_status", rc)
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

//-----------------------------------------------------------------------------
// Capabilities

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
	// from Segger J-Link docs
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
	if s, ok := dcStr[dc]; ok {
		return s
	}
	return "unknown"
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

// GetCaps retrieves the capabilities of a device.
func (hdl *DeviceHandle) GetCaps() (Capabilities, error) {
	cCaps := (*C.uint8_t)(C.malloc(C.JAYLINK_DEV_CAPS_SIZE))
	defer C.free(unsafe.Pointer(cCaps))
	rc := int(C.jaylink_get_caps(hdl.hdl, cCaps))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_get_caps", rc)
	}
	x := (*[1 << 30]C.uint8_t)(unsafe.Pointer(cCaps))
	caps := make([]byte, C.JAYLINK_DEV_CAPS_SIZE)
	for i := range caps {
		caps[i] = byte(x[i])
	}
	return caps, nil
}

// GetExtendedCaps retrieves the extended capabilities of a device.
// Extended capabilties are a superset of normal capabilities.
func (hdl *DeviceHandle) GetExtendedCaps() (Capabilities, error) {
	cCaps := (*C.uint8_t)(C.malloc(C.JAYLINK_DEV_EXT_CAPS_SIZE))
	defer C.free(unsafe.Pointer(cCaps))
	rc := int(C.jaylink_get_extended_caps(hdl.hdl, cCaps))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_get_extended_caps", rc)
	}
	x := (*[1 << 30]C.uint8_t)(unsafe.Pointer(cCaps))
	caps := make([]byte, C.JAYLINK_DEV_EXT_CAPS_SIZE)
	for i := range caps {
		caps[i] = byte(x[i])
	}
	return caps, nil
}

// GetAllCaps returns all device capabilities (normal or extended).
func (hdl *DeviceHandle) GetAllCaps() (Capabilities, error) {
	caps, err := hdl.GetCaps()
	if err == nil && caps.HasCap(DEV_CAP_GET_EXT_CAPS) {
		caps, err = hdl.GetExtendedCaps()
	}
	return caps, err
}

//-----------------------------------------------------------------------------

// Context is a structure representing a libjaylink context.
type Context struct {
	ctx  *C.struct_jaylink_context
	devs **C.struct_jaylink_device
	cb   LogFunc     // logging callback
	user interface{} // user data for logging callback
}

// gContext maps a C context pointer back to the Go context structure.
var gContext = map[*C.struct_jaylink_context]*Context{}

// lock the gContext map during access.
var gLock = sync.RWMutex{}

// ctxLookup lookups a Go context using a C context.
func ctxLookup(cCtx *C.struct_jaylink_context) *Context {
	gLock.RLock()
	ctx := gContext[cCtx]
	gLock.RUnlock()
	return ctx
}

// ctxAdd adds a C to Go context lookup.
func ctxAdd(ctx *Context) {
	gLock.Lock()
	gContext[ctx.ctx] = ctx
	gLock.Unlock()
}

// ctxRemove removes a C to Go context lookup.
func ctxRemove(ctx *Context) {
	gLock.Lock()
	delete(gContext, ctx.ctx)
	gLock.Unlock()
}

//-----------------------------------------------------------------------------
// Core Operations

// Init initializes libjaylink.
func Init() (*Context, error) {
	ctx := Context{}
	rc := int(C.jaylink_init((**C.struct_jaylink_context)(&ctx.ctx)))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_init", rc)
	}
	ctxAdd(&ctx)
	return &ctx, nil
}

// Exit shutdowns libjaylink.
func (ctx *Context) Exit() error {
	ctxRemove(ctx)
	rc := int(C.jaylink_exit(ctx.ctx))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_exit", rc)
	}
	return nil
}

// LibraryHasCap checks for a capability of libjaylink.
func LibraryHasCap(capability uint) bool {
	return bool(C.jaylink_library_has_cap(uint32(capability)))
}

//-----------------------------------------------------------------------------
// Device Operations

// Device is a structure representing a device.
type Device struct {
	dev *C.struct_jaylink_device
}

// DeviceHandle is a structure representing a handle of a device.
type DeviceHandle struct {
	hdl *C.struct_jaylink_device_handle
}

// GetDevices gets available devices.
func (ctx *Context) GetDevices() ([]Device, error) {
	var count C.size_t
	rc := int(C.jaylink_get_devices(ctx.ctx, &ctx.devs, &count))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_get_devices", rc)
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

// GetSerialNumber gets the serial number of a device.
func (dev *Device) GetSerialNumber() (uint, error) {
	var serialNumber C.uint32_t
	rc := int(C.jaylink_device_get_serial_number(dev.dev, &serialNumber))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_device_get_serial_number", rc)
	}
	return uint(serialNumber), nil
}

// GetUsbPorts gets the USB bus and port numbers of a device.
func (dev *Device) GetUsbPorts() (uint8, []uint8, error) {
	var cLength C.size_t
	var cPorts *C.uint8_t
	var cBus C.uint8_t
	rc := int(C.jaylink_device_get_usb_bus_ports(dev.dev, &cBus, &cPorts, &cLength))
	if rc != C.JAYLINK_OK {
		return 0, nil, apiError("jaylink_device_get_usb_bus_ports", rc)
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
		return "", apiError("jaylink_device_get_ipv4_address", rc)
	}
	return C.GoString(addr), nil
}

// GetMacAddress gets the MAC address of a device.
func (dev *Device) GetMacAddress() ([]byte, error) {
	mac := allocBuffer(C.JAYLINK_MAC_ADDRESS_LENGTH)
	defer freeBuffer(mac)
	rc := int(C.jaylink_device_get_mac_address(dev.dev, mac))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_device_get_mac_address", rc)
	}
	return c2goSlice(mac, C.JAYLINK_MAC_ADDRESS_LENGTH), nil
}

// GetProductName gets the product name of a device.
func (dev *Device) GetProductName() (string, error) {
	name := (*C.char)(C.malloc(C.JAYLINK_PRODUCT_NAME_MAX_LENGTH))
	defer C.free(unsafe.Pointer(name))
	rc := int(C.jaylink_device_get_product_name(dev.dev, name))
	if rc != C.JAYLINK_OK {
		return "", apiError("jaylink_device_get_product_name", rc)
	}
	return C.GoString(name), nil
}

// GetNickName gets the nickname of a device.
func (dev *Device) GetNickName() (string, error) {
	name := (*C.char)(C.malloc(C.JAYLINK_NICKNAME_MAX_LENGTH))
	defer C.free(unsafe.Pointer(name))
	rc := int(C.jaylink_device_get_nickname(dev.dev, name))
	if rc != C.JAYLINK_OK {
		return "", apiError("jaylink_device_get_nickname", rc)
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
		return nil, apiError("jaylink_open", rc)
	}
	return &hdl, nil
}

// Close closes a device.
func (hdl *DeviceHandle) Close() error {
	rc := int(C.jaylink_close(hdl.hdl))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_close", rc)
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
		return "", apiError("jaylink_get_firmware_version", rc)
	}
	defer C.free(unsafe.Pointer(cVersion))
	return C.GoString(cVersion), nil
}

// GetFreeMemory retrieves the size of free memory of a device.
func (hdl *DeviceHandle) GetFreeMemory() (uint32, error) {
	var cSize C.uint32_t
	rc := int(C.jaylink_get_free_memory(hdl.hdl, &cSize))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_get_free_memory", rc)
	}
	return uint32(cSize), nil
}

// RawConfig is the raw device configuration.
type RawConfig [C.JAYLINK_DEV_CONFIG_SIZE]byte

// ReadRawConfig reads the raw configuration data of a device.
func (hdl *DeviceHandle) ReadRawConfig() (*RawConfig, error) {
	cConfig := allocBuffer(C.JAYLINK_DEV_CONFIG_SIZE)
	defer freeBuffer(cConfig)
	rc := int(C.jaylink_read_raw_config(hdl.hdl, cConfig))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_read_raw_config", rc)
	}
	var config RawConfig
	c2goCopy(config[:], cConfig)
	return &config, nil
}

// WriteRawConfig writes the raw configuration data of a device.
func (hdl *DeviceHandle) WriteRawConfig(config *RawConfig) error {
	cConfig := go2cBuffer(config[:])
	defer freeBuffer(cConfig)
	rc := int(C.jaylink_write_raw_config(hdl.hdl, cConfig))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_write_raw_config", rc)
	}
	return nil
}

//-----------------------------------------------------------------------------

// Connection is a device connection.
type Connection struct {
	Handle    uint16                  // handle
	Pid       uint32                  // client process id
	Hid       [C.INET_ADDRSTRLEN]byte // host id
	Iid       uint8                   // IID
	Cid       uint8                   // CID
	Timestamp uint32                  // Timestamp of the last registration in milliseconds.
}

// c2goConnection copies connection data from C to Go.
func c2goConnection(connection *Connection, cConnection *C.struct_jaylink_connection) {
	connection.Handle = uint16(cConnection.handle)
	connection.Pid = uint32(cConnection.pid)
	for i := range connection.Hid {
		connection.Hid[i] = byte(cConnection.hid[i])
	}
	connection.Iid = uint8(cConnection.iid)
	connection.Cid = uint8(cConnection.cid)
	connection.Timestamp = uint32(cConnection.timestamp)
}

// go2cConnection copies connection data from Go to C.
func go2cConnection(connection *Connection) *C.struct_jaylink_connection {
	cConnection := (*C.struct_jaylink_connection)(C.malloc(C.sizeof_struct_jaylink_connection))
	cConnection.handle = C.uint16_t(connection.Handle)
	cConnection.pid = C.uint32_t(connection.Pid)
	for i := range connection.Hid {
		cConnection.hid[i] = C.char(connection.Hid[i])
	}
	cConnection.iid = C.uint8_t(connection.Iid)
	cConnection.cid = C.uint8_t(connection.Cid)
	cConnection.timestamp = C.uint32_t(connection.Timestamp)
	return cConnection
}

// Register registers a connection on a device.
func (hdl *DeviceHandle) Register(connection *Connection) ([]Connection, error) {
	cConnection := go2cConnection(connection)
	defer C.free(unsafe.Pointer(cConnection))
	cConnections := (*C.struct_jaylink_connection)(C.malloc(C.JAYLINK_MAX_CONNECTIONS * C.sizeof_struct_jaylink_connection))
	defer C.free(unsafe.Pointer(cConnections))
	var cCount C.size_t
	// register
	rc := int(C.jaylink_register(hdl.hdl, cConnection, cConnections, &cCount))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_register", rc)
	}
	// copy the result to go
	connections := make([]Connection, int(cCount))
	x := (*[1 << 30](C.struct_jaylink_connection))(unsafe.Pointer(cConnections))
	for i := range connections {
		c2goConnection(&connections[i], &x[i])
	}
	return connections, nil
}

// Unregister unregisters a connection from a device.
func (hdl *DeviceHandle) Unregister(connection *Connection) ([]Connection, error) {
	cConnection := go2cConnection(connection)
	defer C.free(unsafe.Pointer(cConnection))
	cConnections := (*C.struct_jaylink_connection)(C.malloc(C.JAYLINK_MAX_CONNECTIONS * C.sizeof_struct_jaylink_connection))
	defer C.free(unsafe.Pointer(cConnections))
	var cCount C.size_t
	// unregister
	rc := int(C.jaylink_unregister(hdl.hdl, cConnection, cConnections, &cCount))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_unregister", rc)
	}
	// copy the result to go
	connections := make([]Connection, int(cCount))
	x := (*[1 << 30](C.struct_jaylink_connection))(unsafe.Pointer(cConnections))
	for i := range connections {
		c2goConnection(&connections[i], &x[i])
	}
	return connections, nil
}

//-----------------------------------------------------------------------------
// Device Discovery

// DiscoveryScan scans for devices.
func (ctx *Context) DiscoveryScan(ifaces HostInterface) error {
	rc := int(C.jaylink_discovery_scan(ctx.ctx, C.uint32_t(ifaces)))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_discovery_scan", rc)
	}
	return nil
}

//-----------------------------------------------------------------------------
// EMUCOM Operations

// EmuComRead reads from an EMUCOM channel.
func (hdl *DeviceHandle) EmuComRead(channel uint32, length int) ([]byte, error) {
	cBuffer := allocBuffer(length)
	defer freeBuffer(cBuffer)
	cLength := C.uint32_t(length)
	rc := int(C.jaylink_emucom_read(hdl.hdl, C.uint32_t(channel), cBuffer, &cLength))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_emucom_read", rc)
	}
	return c2goSlice(cBuffer, int(cLength)), nil
}

// EmuComWrite writes to an EMUCOM channel.
func (hdl *DeviceHandle) EmuComWrite(channel uint32, buffer []byte) (int, error) {
	cBuffer := go2cBuffer(buffer)
	defer freeBuffer(cBuffer)
	cLength := C.uint32_t(len(buffer))
	rc := int(C.jaylink_emucom_write(hdl.hdl, C.uint32_t(channel), cBuffer, &cLength))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_emucom_write", rc)
	}
	return int(cLength), nil
}

//-----------------------------------------------------------------------------
// File I/O Operations

// FileRead reads from a file.
func (hdl *DeviceHandle) FileRead(filename string, offset uint32, length int) ([]byte, error) {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	cBuffer := allocBuffer(length)
	defer freeBuffer(cBuffer)
	cLength := C.uint32_t(length)
	rc := int(C.jaylink_file_read(hdl.hdl, cFilename, cBuffer, C.uint32_t(offset), &cLength))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_file_read", rc)
	}
	return c2goSlice(cBuffer, int(cLength)), nil
}

// FileWrite writes to a file.
func (hdl *DeviceHandle) FileWrite(filename string, buffer []byte, offset uint32) (int, error) {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	cBuffer := go2cBuffer(buffer)
	defer freeBuffer(cBuffer)
	cLength := C.uint32_t(len(buffer))
	rc := int(C.jaylink_file_write(hdl.hdl, cFilename, cBuffer, C.uint32_t(offset), &cLength))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_file_write", rc)
	}
	return int(cLength), nil
}

// FileGetSize retrieves the size of a file.
func (hdl *DeviceHandle) FileGetSize(filename string) (uint32, error) {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	var cSize C.uint32_t
	rc := int(C.jaylink_file_get_size(hdl.hdl, cFilename, &cSize))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_file_get_size", rc)
	}
	return uint32(cSize), nil
}

// FileDelete deletes a file.
func (hdl *DeviceHandle) FileDelete(filename string) error {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	rc := int(C.jaylink_file_delete(hdl.hdl, cFilename))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_file_delete", rc)
	}
	return nil
}

//-----------------------------------------------------------------------------
// JTAG Operations

// JtagVersion is the JTAG command version.
type JtagVersion uint32

// JtagVersion values.
const (
	JTAG_VERSION_2 JtagVersion = C.JAYLINK_JTAG_VERSION_2
	JTAG_VERSION_3 JtagVersion = C.JAYLINK_JTAG_VERSION_3
)

// GetJtagCommandVersion gets the JTAG command version for the device.
func (hdl *DeviceHandle) GetJtagCommandVersion() (JtagVersion, error) {
	hw, err := hdl.GetHardwareVersion()
	if err != nil {
		return 0, err
	}
	// For major hardware version 5 and above, use Version 3.
	if hw.Major >= 5 {
		return JTAG_VERSION_3, nil
	}
	return JTAG_VERSION_2, nil
}

// JtagIO performs a JTAG I/O operation.
func (hdl *DeviceHandle) JtagIO(tms, tdi []byte, n uint16, version JtagVersion) ([]byte, error) {
	nbytes := len(tms)
	if len(tdi) != nbytes {
		panic("len(tms) != len(tdi)")
	}
	cTms := go2cBuffer(tms)
	cTdi := go2cBuffer(tdi)
	cTdo := allocBuffer(nbytes)
	defer freeBuffer(cTms)
	defer freeBuffer(cTdi)
	defer freeBuffer(cTdo)
	rc := int(C.jaylink_jtag_io(hdl.hdl, cTms, cTdi, cTdo, C.uint16_t(n), uint32(version)))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_jtag_io", rc)
	}
	return c2goSlice(cTdo, nbytes), nil
}

// JtagClearTrst clears the JTAG test reset (TRST) signal.
func (hdl *DeviceHandle) JtagClearTrst() error {
	rc := int(C.jaylink_jtag_clear_trst(hdl.hdl))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_jtag_clear_trst", rc)
	}
	return nil
}

// JtagSetTrst sets the JTAG test reset (TRST) signal.
func (hdl *DeviceHandle) JtagSetTrst() error {
	rc := int(C.jaylink_jtag_set_trst(hdl.hdl))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_jtag_set_trst", rc)
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

// LogFunc is a logging callback function.
type LogFunc func(domain, msg string, user interface{})

//export goLogCallback
func goLogCallback(cCtx *C.struct_jaylink_context, cMsg *C.char) {
	ctx := ctxLookup(cCtx)
	if ctx != nil {
		ctx.cb(ctx.LogGetDomain(), C.GoString(cMsg), ctx.user)
	}
}

// LogSetLevel sets the log level.
func (ctx *Context) LogSetLevel(level LogLevel) error {
	rc := int(C.jaylink_log_set_level(ctx.ctx, uint32(level)))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_log_set_level", rc)
	}
	return nil
}

// LogGetLevel gets the log level.
func (ctx *Context) LogGetLevel() (LogLevel, error) {
	var cLevel uint32
	rc := int(C.jaylink_log_get_level(ctx.ctx, &cLevel))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_log_get_level", rc)
	}
	return LogLevel(cLevel), nil
}

// LogSetCallback sets the logging callback function.
func (ctx *Context) LogSetCallback(cb LogFunc, user interface{}) error {
	rc := int(C.jaylink_log_set_callback(ctx.ctx, C.jaylink_log_callback(C.LogCallback), nil))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_log_set_callback", rc)
	}
	ctx.cb = cb
	ctx.user = user
	return nil
}

// LogSetDomain sets the log domain.
func (ctx *Context) LogSetDomain(domain string) error {
	cDomain := C.CString(domain)
	defer C.free(unsafe.Pointer(cDomain))
	rc := int(C.jaylink_log_set_domain(ctx.ctx, cDomain))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_log_set_domain", rc)
	}
	return nil
}

// LogGetDomain gets the log domain.
func (ctx *Context) LogGetDomain() string {
	cDomain := C.jaylink_log_get_domain(ctx.ctx)
	return C.GoString(cDomain)
}

//-----------------------------------------------------------------------------
// Serial Wire Debug

// SwdIO performs a SWD I/O operation.
func (hdl *DeviceHandle) SwdIO(direction, out []byte, n uint16) ([]byte, error) {
	nbytes := len(direction)
	if len(out) != nbytes {
		panic("len(direction) != len(out)")
	}
	cDirection := go2cBuffer(direction)
	cOut := go2cBuffer(out)
	cIn := allocBuffer(nbytes)
	defer freeBuffer(cDirection)
	defer freeBuffer(cOut)
	defer freeBuffer(cIn)
	rc := int(C.jaylink_swd_io(hdl.hdl, cDirection, cOut, cIn, C.uint16_t(n)))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_swd_io", rc)
	}
	return c2goSlice(cIn, nbytes), nil
}

//-----------------------------------------------------------------------------
// Serial Wire Output

// SwoMode is the Serial Wire Output (SWO) capture mode.
type SwoMode uint32

// SwoMode values.
const (
	SWO_MODE_UART SwoMode = C.JAYLINK_SWO_MODE_UART // Universal Asynchronous Receiver Transmitter (UART).
)

// SwoSpeed store Serial Wire Output (SWO) speed information.
type SwoSpeed struct {
	Freq         uint32 // Base frequency in Hz
	MinDiv       uint32 // Minimum frequency divider
	MaxDiv       uint32 // Maximum frequency divider
	MinPrescaler uint32 // Minimum prescaler
	MaxPrescaler uint32 // Maximum prescaler
}

// SwoStart starts SWO capture.
func (hdl *DeviceHandle) SwoStart(mode SwoMode, baudrate, size uint32) error {
	rc := int(C.jaylink_swo_start(hdl.hdl, uint32(mode), C.uint32_t(baudrate), C.uint32_t(size)))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_swo_start", rc)
	}
	return nil
}

// SwoStop stops SWO capture.
func (hdl *DeviceHandle) SwoStop() error {
	rc := int(C.jaylink_swo_stop(hdl.hdl))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_swo_stop", rc)
	}
	return nil
}

// SwoRead reads SWO trace data.
func (hdl *DeviceHandle) SwoRead(length int) ([]byte, error) {
	cLength := C.uint32_t(length)
	cBuffer := allocBuffer(length)
	defer freeBuffer(cBuffer)
	rc := int(C.jaylink_swo_read(hdl.hdl, cBuffer, &cLength))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_swo_read", rc)
	}
	return c2goSlice(cBuffer, int(cLength)), nil
}

// SwoGetSpeeds retrieves SWO speeds.
func (hdl *DeviceHandle) SwoGetSpeeds(mode SwoMode) (*SwoSpeed, error) {
	var cSpeed C.struct_jaylink_swo_speed
	rc := int(C.jaylink_swo_get_speeds(hdl.hdl, uint32(mode), &cSpeed))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_swo_get_speeds", rc)
	}
	speed := SwoSpeed{
		Freq:         uint32(cSpeed.freq),
		MinDiv:       uint32(cSpeed.min_div),
		MaxDiv:       uint32(cSpeed.max_div),
		MinPrescaler: uint32(cSpeed.min_prescaler),
		MaxPrescaler: uint32(cSpeed.max_prescaler),
	}
	return &speed, nil
}

//-----------------------------------------------------------------------------
// Target functions

// TargetInterface is a bitmap of target interfaces.
type TargetInterface uint32

// TargetInterface bit values
const (
	TIF_JTAG          TargetInterface = C.JAYLINK_TIF_JTAG          // Joint Test Action Group, IEEE 1149.1 (JTAG).
	TIF_SWD           TargetInterface = C.JAYLINK_TIF_SWD           // Serial Wire Debug (SWD).
	TIF_BDM3          TargetInterface = C.JAYLINK_TIF_BDM3          // Background Debug Mode 3 (BDM3).
	TIF_FINE          TargetInterface = C.JAYLINK_TIF_FINE          // Renesas’ single-wire debug interface (FINE).
	TIF_2W_JTAG_PIC32 TargetInterface = C.JAYLINK_TIF_2W_JTAG_PIC32 // 2-wire JTAG for PIC32 compliant devices.
)

// Speed stores the target interface speed information.
type Speed struct {
	Freq uint32 // Base frequency in Hz.
	Div  uint16 // Minimum frequency divider.
}

// SetSpeed sets the target interface speed (in kHz units).
func (hdl *DeviceHandle) SetSpeed(speed uint16) error {
	rc := int(C.jaylink_set_speed(hdl.hdl, C.uint16_t(speed)))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_set_speed", rc)
	}
	return nil
}

// GetSpeeds retrieves target interface speeds.
func (hdl *DeviceHandle) GetSpeeds() (*Speed, error) {
	var cSpeed C.struct_jaylink_speed
	rc := int(C.jaylink_get_speeds(hdl.hdl, &cSpeed))
	if rc != C.JAYLINK_OK {
		return nil, apiError("jaylink_get_speeds", rc)
	}
	speed := Speed{
		Freq: uint32(cSpeed.freq),
		Div:  uint16(cSpeed.div),
	}
	return &speed, nil
}

// GetMaxSpeed returns the maximum interface speed.
func (hdl *DeviceHandle) GetMaxSpeed() (uint16, error) {
	speed, err := hdl.GetSpeeds()
	if err != nil {
		return 0, err
	}
	if speed.Div == 0 {
		return 0, errors.New("Speed.Div == 0")
	}
	return uint16(speed.Freq / (1000 * uint32(speed.Div))), nil
}

// SelectInterface selects the target interface.
func (hdl *DeviceHandle) SelectInterface(iface TargetInterface) (TargetInterface, error) {
	var prev uint32
	rc := int(C.jaylink_select_interface(hdl.hdl, uint32(iface), &prev))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_select_interface", rc)
	}
	return TargetInterface(prev), nil
}

// GetAvailableInterfaces retrieves the available target interfaces.
func (hdl *DeviceHandle) GetAvailableInterfaces() (uint32, error) {
	var ifaces C.uint32_t
	rc := int(C.jaylink_get_available_interfaces(hdl.hdl, &ifaces))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_get_available_interfaces", rc)
	}
	return uint32(ifaces), nil
}

// GetSelectedInterface retrieves the selected target interface.
func (hdl *DeviceHandle) GetSelectedInterface() (TargetInterface, error) {
	var iface uint32
	rc := int(C.jaylink_get_selected_interface(hdl.hdl, &iface))
	if rc != C.JAYLINK_OK {
		return 0, apiError("jaylink_get_selected_interface", rc)
	}
	return TargetInterface(iface), nil
}

// ClearReset clears the target reset signal.
func (hdl *DeviceHandle) ClearReset() error {
	rc := int(C.jaylink_clear_reset(hdl.hdl))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_clear_reset", rc)
	}
	return nil
}

// SetReset sets the target reset signal.
func (hdl *DeviceHandle) SetReset() error {
	rc := int(C.jaylink_set_reset(hdl.hdl))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_set_reset", rc)
	}
	return nil
}

// SetTargetPower sets the target power supply.
func (hdl *DeviceHandle) SetTargetPower(enable bool) error {
	rc := int(C.jaylink_set_target_power(hdl.hdl, C.bool(enable)))
	if rc != C.JAYLINK_OK {
		return apiError("jaylink_set_target_power", rc)
	}
	return nil
}

//-----------------------------------------------------------------------------
// Version functions

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
