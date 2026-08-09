//go:build linux && !android && !hybrid_awg

package system

func kernelAWGAvailable() bool {
	return false
}
