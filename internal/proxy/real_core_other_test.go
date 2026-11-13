//go:build !linux

package proxy

import "testing"

func TestRealCoreObservation(t *testing.T) {
	// #given this OS cannot show the owned process sockets
	// #when the real-core observation is requested
	// #then ready stays untested
	t.Skip("real Mihomo observation is untested on this OS")
}
