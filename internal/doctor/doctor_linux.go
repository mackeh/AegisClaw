//go:build linux

package doctor

import (
	"fmt"
	"syscall"
)

func checkDiskSpace(cfgDir string) Result {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(cfgDir, &stat); err != nil {
		return Result{
			Name:   "Disk space",
			Status: StatusWarn,
			Detail: "unable to check",
		}
	}

	freeBytes := stat.Bavail * uint64(stat.Bsize)
	freeMB := freeBytes / (1024 * 1024)
	freeGB := float64(freeMB) / 1024.0

	if freeMB < 100 {
		return Result{
			Name:   "Disk space",
			Status: StatusFail,
			Detail: fmt.Sprintf("%.0f MB free", float64(freeMB)),
			Fix:    "Free up space in ~/.aegisclaw/",
		}
	}

	if freeMB < 500 {
		return Result{
			Name:   "Disk space",
			Status: StatusWarn,
			Detail: fmt.Sprintf("%.1f GB free (low)", freeGB),
			Fix:    "Consider freeing disk space",
		}
	}

	return Result{
		Name:   "Disk space",
		Status: StatusPass,
		Detail: fmt.Sprintf("%.1f GB free", freeGB),
	}
}
