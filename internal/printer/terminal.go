//go:build linux

package printer

import (
"syscall"
"unsafe"
)

func isTerminal(fd uintptr) bool {
var termios syscall.Termios
_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))
return err == 0
}

func terminalWidth(fd uintptr) int {
type winsize struct{ Row, Col, Xpixel, Ypixel uint16 }
var ws winsize
_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, 0x5413, uintptr(unsafe.Pointer(&ws)))
if err == 0 && ws.Col > 0 {
return int(ws.Col)
}
return 80
}
