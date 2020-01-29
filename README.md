[![Go Report Card](https://goreportcard.com/badge/github.com/deadsy/libjaylink)](https://goreportcard.com/report/github.com/deadsy/libjaylink)
[![GoDoc](https://godoc.org/github.com/deadsy/libjaylink?status.svg)](https://godoc.org/github.com/deadsy/libjaylink)

# libjaylink
Go bindings for the libjaylink library.

## What Is It?

Segger makes J-Link devices. These are USB or network connected JTAG/SWD interfaces.

Devices: https://www.segger.com/products/debug-probes/j-link/

libjaylink is a C-based library providing an API for controlling J-Link devices.
This package provides a Go wrapper for the C-library API so the library can be called from Go programs.

## Dependencies

 * libjaylink (https://gitlab.zapb.de/zapb/libjaylink/)
 * libusb-1.0 (https://libusb.info/)

## Notes

All C-API functions have Go wrappers.
The public interface of this package is a 1-1 mapping from the C-API to a Go style function prototypes.
There are a couple of novel functions added as helper routines, but in general any C usage of the library has a simple mapping to Go.
 
## Status
 
Some testing has been done, mostly using USB based J-Link devices.
