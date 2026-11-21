//go:build !unix

package analysis

func readFile(string) ([]byte, error) { return nil, ErrInput }
