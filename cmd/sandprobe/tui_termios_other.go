//go:build !darwin && !linux

package main

import "errors"

func makeRaw(fd int) (func(), error) {
	return nil, errors.New("raw mode unsupported on this platform")
}

func termSize(fd int) (cols, rows int) {
	return 0, 0
}
