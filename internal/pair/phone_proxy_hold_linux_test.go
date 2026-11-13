//go:build linux

package pair

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The receive process writes the local copy and then acknowledges it.
// This hold stops that acknowledgment syscall after the copy is complete,
// so the test can cancel the ticket before the coordinator consumes it.

func TestMain(m *testing.M) {
	if os.Getenv("DEVCTL_HOLD_ACK_EXEC") == "1" {
		if err := holdAckExec(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type holdSpec struct {
	Bin  string   `json:"bin"`
	Args []string `json:"args"`
}

func holdAckExec() error {
	runtime.LockOSThread()
	raw, err := os.ReadFile(os.Getenv("DEVCTL_HOLD_SPEC"))
	if err != nil {
		return err
	}
	var spec holdSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return err
	}
	sock, err := strconv.Atoi(os.Getenv("DEVCTL_HOLD_FD"))
	if err != nil {
		return err
	}
	notify, err := installAckFilter()
	if err != nil {
		return err
	}
	if err := unix.Sendmsg(sock, []byte{1}, unix.UnixRights(notify), nil, 0); err != nil {
		return err
	}
	_ = unix.Close(notify)
	_ = unix.Close(sock)
	env := make([]string, 0, len(os.Environ()))
	for _, item := range os.Environ() {
		if len(item) >= 12 && item[:12] == "DEVCTL_HOLD_" {
			continue
		}
		env = append(env, item)
	}
	argv := append([]string{spec.Bin}, spec.Args...)
	return unix.Exec(spec.Bin, argv, env)
}

func installAckFilter() (int, error) {
	arch := nativeAuditArch()
	if arch == 0 {
		return 0, fmt.Errorf("seccomp arch")
	}
	filter := notifyFilter(arch, []uint32{unix.SYS_WRITE, unix.SYS_WRITEV})
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 0, err
	}
	fd, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER),
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

func nativeAuditArch() uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64
	default:
		return 0
	}
}

func notifyFilter(arch uint32, syscalls []uint32) []unix.SockFilter {
	// 0 load arch, 1 compare, 2-3 allow on mismatch, 4 load nr, then one jump per syscall.
	n := len(syscalls)
	allowAt := 5 + n
	notifAt := allowAt + 1
	out := make([]unix.SockFilter, notifAt+1)
	out[0] = stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 4)
	out[1] = jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, arch, 2, 0)
	out[2] = stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW)
	out[3] = stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW)
	out[4] = stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0)
	for i, nr := range syscalls {
		idx := 5 + i
		out[idx] = jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, nr, uint8(notifAt-idx-1), 0)
	}
	out[allowAt] = stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW)
	out[notifAt] = stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF)
	return out
}

func stmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

type ackHold struct {
	notify   int
	held     chan struct{}
	kind     string
	mu       chan struct{}
	released bool
	pending  []uint64
	stop     chan struct{}
}

func startHeldDevctl(t *testing.T, ctx context.Context, bin, configDir string, args ...string) (*ackHold, *devctlProc) {
	t.Helper()
	if nativeAuditArch() == 0 || unsafe.Sizeof(uintptr(0)) != 8 {
		t.Fatal("seccomp hold is unavailable")
	}
	if err := checkNotifSizes(); err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(t.TempDir(), "hold-spec.json")
	raw, err := json.Marshal(holdSpec{Bin: bin, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(specPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(pair[0])
	parent := os.NewFile(uintptr(pair[0]), "hold-parent")
	child := os.NewFile(uintptr(pair[1]), "hold-child")
	defer child.Close()
	tv := unix.Timeval{Sec: 20}
	if err := unix.SetsockoptTimeval(pair[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		parent.Close()
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(cleanEnv(configDir),
		"DEVCTL_HOLD_ACK_EXEC=1",
		"DEVCTL_HOLD_FD=3",
		"DEVCTL_HOLD_SPEC="+specPath,
	)
	cmd.ExtraFiles = []*os.File{child}
	proc := runDevctlCmd(t, ctx, cmd, configDir)
	notify, err := readNotify(int(parent.Fd()))
	parent.Close()
	if err != nil {
		proc.stop()
		t.Fatal(err)
	}
	hold := &ackHold{
		notify: notify,
		held:   make(chan struct{}),
		mu:     make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	hold.mu <- struct{}{}
	go hold.serve()
	t.Cleanup(func() {
		hold.release()
		close(hold.stop)
		_ = unix.Close(notify)
	})
	return hold, proc
}

func readNotify(fd int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, 0)
	if err != nil {
		return 0, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return 0, err
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return 0, err
	}
	return fds[0], nil
}

func (h *ackHold) wait(t *testing.T, proc *devctlProc) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-h.held:
			return
		case <-time.After(50 * time.Millisecond):
			if proc.cmd.Process == nil {
				t.Fatalf("receive exited before the acknowledgment was held\n%s", proc.stderr.String())
			}
			if err := proc.cmd.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatalf("receive exited before the acknowledgment was held: %v\n%s", err, proc.stderr.String())
			}
		}
	}
	t.Fatalf("acknowledgment was not held\n%s", proc.stderr.String())
}

func (h *ackHold) release() {
	<-h.mu
	if h.released {
		h.mu <- struct{}{}
		return
	}
	h.released = true
	ids := h.pending
	h.pending = nil
	h.mu <- struct{}{}
	for _, id := range ids {
		h.reply(id)
	}
}

func (h *ackHold) serve() {
	for {
		select {
		case <-h.stop:
			return
		default:
		}
		note, err := h.recv()
		if err != nil {
			return
		}
		kind := ""
		if note.buf != nil {
			kind = ackKind(note.buf)
		}
		<-h.mu
		if !h.released && kind != "" {
			if h.kind == "" {
				h.kind = kind
				close(h.held)
			}
			h.pending = append(h.pending, note.id)
			h.mu <- struct{}{}
			continue
		}
		h.mu <- struct{}{}
		h.reply(note.id)
	}
}

func (h *ackHold) reply(id uint64) {
	resp := seccompNotifResp{ID: id, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	_ = ioctlPtr(h.notify, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&resp))
}

type heldNote struct {
	id  uint64
	buf []byte
}

func (h *ackHold) recv() (heldNote, error) {
	var note seccompNotif
	if err := ioctlPtr(h.notify, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&note)); err != nil {
		return heldNote{}, err
	}
	return heldNote{id: note.ID, buf: readSyscallBytes(int(note.PID), note.Data)}, nil
}

func ackKind(buf []byte) string {
	if bytes.Contains(buf, []byte(`"purpose":"op"`)) && !bytes.Contains(buf, []byte(`"pubkey"`)) {
		return "challenge"
	}
	if bytes.Contains(buf, []byte("/v1/tickets/ack")) {
		return "ack"
	}
	return ""
}

func readSyscallBytes(pid int, data seccompData) []byte {
	switch data.Nr {
	case unix.SYS_WRITE:
		return readRemote(pid, uintptr(data.Args[1]), int(data.Args[2]))
	case unix.SYS_WRITEV:
		return readWritev(pid, uintptr(data.Args[1]), int(data.Args[2]))
	default:
		return nil
	}
}

func readWritev(pid int, addr uintptr, count int) []byte {
	if count <= 0 {
		return nil
	}
	if count > 8 {
		count = 8
	}
	width := int(unsafe.Sizeof(uintptr(0))) * 2
	raw := readRemote(pid, addr, count*width)
	var out []byte
	for len(raw) >= width && len(out) < 4096 {
		base := uintptr(binary.LittleEndian.Uint64(raw[:8]))
		length := binary.LittleEndian.Uint64(raw[8:16])
		raw = raw[width:]
		if length > 4096 {
			length = 4096
		}
		out = append(out, readRemote(pid, base, int(length))...)
	}
	return out
}

func readRemote(pid int, addr uintptr, n int) []byte {
	if n <= 0 || addr == 0 {
		return nil
	}
	if n > 4096 {
		n = 4096
	}
	buf := make([]byte, n)
	local := []unix.Iovec{{Base: &buf[0]}}
	local[0].SetLen(len(buf))
	remote := []unix.RemoteIovec{{Base: addr, Len: n}}
	got, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err != nil || got <= 0 {
		return nil
	}
	return buf[:got]
}

func checkNotifSizes() error {
	var sizes struct {
		Notif uint16
		Resp  uint16
		Data  uint16
	}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, uintptr(unix.SECCOMP_GET_NOTIF_SIZES), 0, uintptr(unsafe.Pointer(&sizes)))
	if errno != 0 {
		return errno
	}
	if sizes.Notif != uint16(unsafe.Sizeof(seccompNotif{})) || sizes.Resp != uint16(unsafe.Sizeof(seccompNotifResp{})) {
		return fmt.Errorf("seccomp sizes %d %d, have %d %d", sizes.Notif, sizes.Resp, unsafe.Sizeof(seccompNotif{}), unsafe.Sizeof(seccompNotifResp{}))
	}
	return nil
}

func ioctlPtr(fd int, req uint, ptr unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(ptr))
	if errno != 0 {
		return errno
	}
	return nil
}

type seccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}

type seccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}
