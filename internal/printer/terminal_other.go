//go:build !linux

package printer

func isTerminal(fd uintptr) bool {
return false
}

func terminalWidth(fd uintptr) int {
return 80
}
