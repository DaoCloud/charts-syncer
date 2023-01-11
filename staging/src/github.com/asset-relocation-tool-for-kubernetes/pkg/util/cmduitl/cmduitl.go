package cmduitl

import (
	"io"
	"os"
	"strings"
)

func Move(source, destination string) error {
	err := os.Rename(source, destination)
	if err != nil && strings.Contains(err.Error(), "invalid cross-device link") {
		return moveCrossDevice(source, destination)
	}
	return err
}

func moveCrossDevice(source, destination string) error {
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}

	fi, err := os.Stat(source)
	if err != nil {
		_ = os.Remove(destination)
		return err
	}

	err = os.Chmod(destination, fi.Mode())
	if err != nil {
		_ = os.Remove(destination)
		return err
	}
	_ = os.Remove(source)
	return nil
}
