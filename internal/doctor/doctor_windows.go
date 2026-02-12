//go:build windows

package doctor

func checkDiskSpace(cfgDir string) Result {
	// Disk space check not implemented for Windows yet.
	return Result{
		Name:   "Disk space",
		Status: StatusPass,
		Detail: "check skipped on Windows",
	}
}
