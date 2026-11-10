//go:build windows

// OTun additions to winsys for the strict-route "block bypass UDP" filters
// (see tun_windows_otun.go). Kept in a separate file so upgrading sing-tun
// only conflicts here, never inside upstream files.

package winsys

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procFwpmTransactionBegin0  = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0 = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0  = modfwpuclnt.NewProc("FwpmTransactionAbort0")
)

// FWPM APIs return the Win32/FWP error code directly (not via GetLastError),
// so these wrappers surface r1 as the error.

// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
func FwpmTransactionBegin0(engineHandle uintptr, flags uint32) error {
	r1, _, _ := syscall.SyscallN(procFwpmTransactionBegin0.Addr(), engineHandle, uintptr(flags))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactioncommit0
func FwpmTransactionCommit0(engineHandle uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmTransactionCommit0.Addr(), engineHandle)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionabort0
func FwpmTransactionAbort0(engineHandle uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmTransactionAbort0.Addr(), engineHandle)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// FwpmFilterAddErr is FwpmFilterAdd0 returning the real FWP error code
// (the generated wrapper reports GetLastError, which is usually 0 here).
func FwpmFilterAddErr(engineHandle uintptr, filter *FWPM_FILTER0, id *uint64) error {
	r1, _, _ := syscall.SyscallN(procFwpmFilterAdd0.Addr(), engineHandle, uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(id)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// FWP_V4_ADDR_AND_MASK: addr and mask in host byte order.
type FWP_V4_ADDR_AND_MASK struct {
	Addr uint32
	Mask uint32
}

// FWP_V6_ADDR_AND_MASK
type FWP_V6_ADDR_AND_MASK struct {
	Addr         [16]byte
	PrefixLength uint8
}

// 0c1ba1af-5765-453f-af22-a8f791ac775b
var FWPM_CONDITION_IP_LOCAL_PORT = windows.GUID{
	Data1: 0x0c1ba1af,
	Data2: 0x5765,
	Data3: 0x453f,
	Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b},
}

// b235ae9a-1d64-49b8-a44c-5ff3d9095045
var FWPM_CONDITION_IP_REMOTE_ADDRESS = windows.GUID{
	Data1: 0xb235ae9a,
	Data2: 0x1d64,
	Data3: 0x49b8,
	Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
}

// e1cd9fe7-f4b5-4273-96c0-592e487b8650
var FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = windows.GUID{
	Data1: 0xe1cd9fe7,
	Data2: 0xf4b5,
	Data3: 0x4273,
	Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50},
}

// a3b42c97-9f04-4672-b87e-cee9c483257f
var FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = windows.GUID{
	Data1: 0xa3b42c97,
	Data2: 0x9f04,
	Data3: 0x4672,
	Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f},
}
