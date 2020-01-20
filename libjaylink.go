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
	"strings"
	"unsafe"
)

//-----------------------------------------------------------------------------

// Host Interface
type HostInterface uint32

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

type HardwareType uint32

const (
	HW_TYPE_JLINK     HardwareType = C.JAYLINK_HW_TYPE_JLINK
	HW_TYPE_FLASHER   HardwareType = C.JAYLINK_HW_TYPE_FLASHER
	HW_TYPE_JLINK_PRO HardwareType = C.JAYLINK_HW_TYPE_JLINK_PRO
)

type HardwareVersion struct {
	hwtype                 HardwareType
	major, minor, revision uint8
}

//-----------------------------------------------------------------------------

// Context is a structure representing a libjaylink context.
type Context struct {
	ctx  *C.struct_jaylink_context
	devs **C.struct_jaylink_device
}

//-----------------------------------------------------------------------------

// Device is an opaque structure representing a device.
type Device struct {
	dev *C.struct_jaylink_device
}

func (dev *Device) String() string {

	s := []string{}

	hi, err := dev.GetHostInterface()
	if err != nil {
		return err.Error()
	}
	s = append(s, hi.String())

	name, err := dev.GetProductName()
	if err != nil {
		return err.Error()
	}
	s = append(s, name)

	name, err = dev.GetNickName()
	if err != nil {
		return err.Error()
	}
	s = append(s, name)

	return strings.Join(s, " ")
}

// DeviceHandle is an opaque structure representing a handle of a device.
type DeviceHandle *C.struct_jaylink_device_handle

//-----------------------------------------------------------------------------
// core.c

// Init initializes libjaylink.
func Init() (*Context, error) {
	ctx := Context{}
	rc := int(C.jaylink_init((**C.struct_jaylink_context)(&ctx.ctx)))
	if rc != C.JAYLINK_OK {
		return nil, fmt.Errorf("jaylink_init failed (%d)", rc)
	}
	return &ctx, nil
}

// Exit shutdowns libjaylink.
func (ctx *Context) Exit() error {
	rc := int(C.jaylink_exit(ctx.ctx))
	if rc != C.JAYLINK_OK {
		return fmt.Errorf("jaylink_exit failed (%d)", rc)
	}
	return nil
}

// LibraryHasCap checks for a capability of libjaylink.
func LibraryHasCap(capability uint) bool {
	return bool(C.jaylink_library_has_cap(uint32(capability)))
}

//-----------------------------------------------------------------------------
// device.c

func (ctx *Context) GetDevices() ([]Device, error) {
	var count C.size_t
	rc := int(C.jaylink_get_devices(ctx.ctx, &ctx.devs, &count))
	if rc != C.JAYLINK_OK {
		return nil, fmt.Errorf("jaylink_get_devices failed (%d)", rc)
	}
	d := (*[1 << 30]*C.struct_jaylink_device)(unsafe.Pointer(ctx.devs))
	dev := make([]Device, int(count))
	for i := range dev {
		dev[i].dev = d[i]
	}
	return dev, nil
}

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

func (dev *Device) GetHostInterface() (HostInterface, error) {
	var iface uint32
	rc := int(C.jaylink_device_get_host_interface(dev.dev, &iface))
	if rc != C.JAYLINK_OK {
		return 0, fmt.Errorf("jaylink_device_get_host_interface failed (%d)", rc)
	}
	return HostInterface(iface), nil
}

/*

func (dev *Device) GetSerialNumber() (uint32, error) {
rc := int(C.jaylink_device_get_serial_number(dev.dev, uint32_t *serial_number);
	if rc != C.JAYLINK_OK {
		return 0, fmt.Errorf("jaylink_device_get_serial_number failed (%d)", rc)
	}
	return 0, nil
}

func (dev *Device) GetUsbAddress() (UsbAddress, error) {
 rc := int(C.jaylink_device_get_usb_address(dev.dev, enum jaylink_usb_address *address);
 	if rc != C.JAYLINK_OK {
		return 0, fmt.Errorf("jaylink_device_get_usb_address failed (%d)", rc)
	}

 	return 0, nil
}

func (dev *Device) GetUsbPorts() ([]uint8, error) {
  rc := int(C.jaylink_device_get_usb_bus_ports(dev.dev, uint8_t *bus, uint8_t **ports, size_t *length);
  	if rc != C.JAYLINK_OK {
		return nil, fmt.Errorf("jaylink_device_get_usb_bus_ports failed (%d)", rc)
	}

  	return nil, nil
}

func (dev *Device) GetIPv4Address() (net.IP, error) {
  rc := int(C.jaylink_device_get_ipv4_address(dev.dev, char *address);
  	if rc != C.JAYLINK_OK {
		return 0, fmt.Errorf("jaylink_device_get_ipv4_address failed (%d)", rc)
	}
	return net.IPv4(0,0,0,0), nil
}

func (dev *Device) GetMacAddress() ([6]uint8, error) {
  rc := int(C.jaylink_device_get_mac_address(dev.dev, uint8_t *address);
  	if rc != C.JAYLINK_OK {
		return 0, fmt.Errorf("jaylink_device_get_mac_address failed (%d)", rc)
	}

	return [6]uint8{}, nil
}

func (dev *Device) GetHardwareVersion() (*HardwareVersion, error) {
  rc := int(C.jaylink_device_get_hardware_version(dev.dev, struct jaylink_hardware_version *version);
  	if rc != C.JAYLINK_OK {
		return 0, fmt.Errorf("jaylink_device_get_hardware_version failed (%d)", rc)
	}
}

*/

func (dev *Device) GetProductName() (string, error) {
	name := (*C.char)(C.malloc(C.JAYLINK_PRODUCT_NAME_MAX_LENGTH))
	defer C.free(unsafe.Pointer(name))
	rc := int(C.jaylink_device_get_product_name(dev.dev, name))
	if rc != C.JAYLINK_OK {
		return "", fmt.Errorf("jaylink_device_get_product_name failed (%d)", rc)
	}
	return C.GoString(name), nil
}

func (dev *Device) GetNickName() (string, error) {
	name := (*C.char)(C.malloc(C.JAYLINK_NICKNAME_MAX_LENGTH))
	defer C.free(unsafe.Pointer(name))
	rc := int(C.jaylink_device_get_nickname(dev.dev, name))
	if rc != C.JAYLINK_OK {
		return "", fmt.Errorf("jaylink_device_get_nickname failed (%d)", rc)
	}
	return C.GoString(name), nil
}

// struct jaylink_device *jaylink_ref_device(struct jaylink_device *dev);
// void jaylink_unref_device(struct jaylink_device *dev);
// int jaylink_open(struct jaylink_device *dev, struct jaylink_device_handle **devh);
// int jaylink_close(struct jaylink_device_handle *devh);
// struct jaylink_device *jaylink_get_device(struct jaylink_device_handle *devh);
// int jaylink_get_firmware_version(struct jaylink_device_handle *devh, char **version, size_t *length);
// int jaylink_get_hardware_info(struct jaylink_device_handle *devh, uint32_t mask, uint32_t *info);
// int jaylink_get_counters(struct jaylink_device_handle *devh, uint32_t mask, uint32_t *values);
// int jaylink_get_hardware_version(struct jaylink_device_handle *devh, struct jaylink_hardware_version *version);
// int jaylink_get_hardware_status(struct jaylink_device_handle *devh, struct jaylink_hardware_status *status);
// int jaylink_get_caps(struct jaylink_device_handle *devh, uint8_t *caps);
// int jaylink_get_extended_caps(struct jaylink_device_handle *devh, uint8_t *caps);
// int jaylink_get_free_memory(struct jaylink_device_handle *devh, uint32_t *size);
// int jaylink_read_raw_config(struct jaylink_device_handle *devh, uint8_t *config);
// int jaylink_write_raw_config(struct jaylink_device_handle *devh, const uint8_t *config);
// int jaylink_register(struct jaylink_device_handle *devh, struct jaylink_connection *connection, struct jaylink_connection *connections, size_t *count);
// int jaylink_unregister(struct jaylink_device_handle *devh, const struct jaylink_connection *connection, struct jaylink_connection *connections, size_t *count);

//-----------------------------------------------------------------------------
// discovery.c

func (ctx *Context) DiscoveryScan(ifaces HostInterface) error {
	rc := int(C.jaylink_discovery_scan(ctx.ctx, C.uint32_t(ifaces)))
	if rc != C.JAYLINK_OK {
		return fmt.Errorf("jaylink_discovery_scan failed (%d)", rc)
	}
	return nil
}

//-----------------------------------------------------------------------------
// emucom.c

// int jaylink_emucom_read(struct jaylink_device_handle *devh, uint32_t channel, uint8_t *buffer, uint32_t *length);
// int jaylink_emucom_write(struct jaylink_device_handle *devh, uint32_t channel, const uint8_t *buffer, uint32_t *length);

//-----------------------------------------------------------------------------
// error.c

// const char *jaylink_strerror(int error_code);
// const char *jaylink_strerror_name(int error_code);

//-----------------------------------------------------------------------------
// fileio.c

// int jaylink_file_read(struct jaylink_device_handle *devh, const char *filename, uint8_t *buffer, uint32_t offset, uint32_t *length);
// int jaylink_file_write(struct jaylink_device_handle *devh, const char *filename, const uint8_t *buffer, uint32_t offset, uint32_t *length);
// int jaylink_file_get_size(struct jaylink_device_handle *devh, const char *filename, uint32_t *size);
// int jaylink_file_delete(struct jaylink_device_handle *devh, const char *filename);

//-----------------------------------------------------------------------------
// jtag.c

// int jaylink_jtag_io(struct jaylink_device_handle *devh, const uint8_t *tms, const uint8_t *tdi, uint8_t *tdo, uint16_t length, enum jaylink_jtag_version version);
// int jaylink_jtag_clear_trst(struct jaylink_device_handle *devh);
// int jaylink_jtag_set_trst(struct jaylink_device_handle *devh);

//-----------------------------------------------------------------------------
// log.c

// int jaylink_log_set_level(struct jaylink_context *ctx, enum jaylink_log_level level);
// int jaylink_log_get_level(const struct jaylink_context *ctx, enum jaylink_log_level *level);
// int jaylink_log_set_callback(struct jaylink_context *ctx, jaylink_log_callback callback, void *user_data);
// int jaylink_log_set_domain(struct jaylink_context *ctx, const char *domain);
// const char *jaylink_log_get_domain(const struct jaylink_context *ctx);

//-----------------------------------------------------------------------------
// strutil.c

// int jaylink_parse_serial_number(const char *str, uint32_t *serial_number);

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
// util.c

// bool jaylink_has_cap(const uint8_t *caps, uint32_t cap);

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
