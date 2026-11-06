package releasesigner

import (
	"fmt"
	"syscall"
)

// Harden stops core dumps (PR_SET_DUMPABLE 0) and locks all memory (MCL_CURRENT|MCL_FUTURE): the open key
// exists only in memory that is never swapped. It fails if either fails.
func Harden() error {
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 4, 0, 0); e != 0 {
		return fmt.Errorf("prctl: %w", e)
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_MLOCKALL, 3, 0, 0); e != 0 {
		return fmt.Errorf("mlockall: %w", e)
	}
	return nil
}
