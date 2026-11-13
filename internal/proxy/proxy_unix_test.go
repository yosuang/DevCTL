//go:build unix

package proxy

import (
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDeadCoreStaysDownUntilStart(t *testing.T) {
	// #given a listening core that is killed
	// #when start is not called again
	// #then nothing restarts it, and the next start is a new process
	dir := t.TempDir()
	keep(t, dir)
	useCore(t, "listen")
	plantCopy(t, dir, 0x11, "copy_complete", "", exampleURI)
	if _, err := callStart(t, dir, "", corePath); err != nil {
		t.Fatal(err)
	}
	pid := readRuntimePID(t, dir)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for processAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatal("still alive")
	}
	time.Sleep(200 * time.Millisecond)
	if readRuns(t) != 1 || processAlive(pid) {
		t.Fatal("restarted")
	}
	if _, err := callStart(t, dir, "", corePath); err != nil || readRuns(t) != 2 {
		t.Fatalf("restart %v runs %d", err, readRuns(t))
	}
}

func TestInterruptDuringWait(t *testing.T) {
	// #given a core that has not accepted a connection yet
	// #when the wait is interrupted
	// #then the core is stopped and start does not report listening
	dir := t.TempDir()
	keep(t, dir)
	useCore(t, "delay")
	plantCopy(t, dir, 0x11, "copy_complete", "", exampleURI)
	caught := make(chan os.Signal, 1)
	signal.Notify(caught, os.Interrupt)
	t.Cleanup(func() { signal.Stop(caught) })
	done := make(chan error, 1)
	buf := captureOut(t)
	go func() {
		done <- Start(t.Context(), dir, "", corePath)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for readRuns(t) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, errInterrupted) {
			t.Fatalf("err %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("wait")
	}
	if strings.Contains(buf.String(), "listening") || strings.Contains(buf.String(), "ready") {
		t.Fatal("output")
	}
	if _, statErr := os.Stat(runtimeDir(dir, 0x11)); !os.IsNotExist(statErr) {
		t.Fatal("runtime remains")
	}
}
