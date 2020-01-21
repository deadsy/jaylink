[![Go Report Card](https://goreportcard.com/badge/github.com/deadsy/libjaylink)](https://goreportcard.com/report/github.com/deadsy/libjaylink)
[![GoDoc](https://godoc.org/github.com/deadsy/libjaylink?status.svg)](https://godoc.org/github.com/deadsy/libjaylink)

# libjaylink
Go bindings for the libjaylink library.

## What Is It?

Segger makes J-Link devices. These are USB or network connected JTAG/SWD interfaces.
Devices: https://www.segger.com/products/debug-probes/j-link/

libjaylink is a C-based library providing an API for controlling J-Link devices.
This package provides a Go wrapper around the C-library API so you can use the library from Go programs.

## Dependencies

 * libjaylink (https://gitlab.zapb.de/zapb/libjaylink/)
 * libusb-1.0 (https://libusb.info/)
 
## Status
 
 In development.
 
