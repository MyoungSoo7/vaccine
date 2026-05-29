package scanner

import "os"

func fileStat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
