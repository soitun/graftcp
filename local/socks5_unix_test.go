package local

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestSocks5UnixSocketPath(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantPath string
		wantOK   bool
	}{
		{
			name:     "unix colon prefix",
			addr:     "unix:/tmp/tor.sock",
			wantPath: "/tmp/tor.sock",
			wantOK:   true,
		},
		{
			name:     "unix URL prefix",
			addr:     "unix:///tmp/tor.sock",
			wantPath: "/tmp/tor.sock",
			wantOK:   true,
		},
		{
			name:     "absolute path",
			addr:     "/tmp/tor.sock",
			wantPath: "/tmp/tor.sock",
			wantOK:   true,
		},
		{
			name:   "unsupported unix plus prefix",
			addr:   "unix+/tmp/tor.sock",
			wantOK: false,
		},
		{
			name:   "TCP endpoint",
			addr:   "127.0.0.1:1080",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotOK := socks5UnixSocketPath(tt.addr)
			if gotOK != tt.wantOK {
				t.Fatalf("socks5UnixSocketPath(%q) ok = %v, want %v", tt.addr, gotOK, tt.wantOK)
			}
			if gotPath != tt.wantPath {
				t.Fatalf("socks5UnixSocketPath(%q) path = %q, want %q", tt.addr, gotPath, tt.wantPath)
			}
		})
	}
}

func TestDialTCPThroughSocks5UnixSocket(t *testing.T) {
	tests := []struct {
		name     string
		endpoint func(string) string
		username string
		password string
	}{
		{
			name:     "absolute path",
			endpoint: func(path string) string { return path },
		},
		{
			name:     "unix prefix with auth",
			endpoint: func(path string) string { return "unix:" + path },
			username: "tor_user",
			password: "RANDOM STRING",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := startFakeSocks5UnixServer(t, tt.username, tt.password)

			l, err := NewLocalListener(":0")
			if err != nil {
				t.Fatalf("NewLocalListener() error = %v", err)
			}
			if err := l.SetSelectMode("only_socks5"); err != nil {
				t.Fatalf("SetSelectMode() error = %v", err)
			}
			if err := l.ConfigureSOCKS5(tt.endpoint(server.path), tt.username, tt.password); err != nil {
				t.Fatalf("ConfigureSOCKS5() error = %v", err)
			}
			if l.socks5Network != "unix" {
				t.Fatalf("socks5Network = %q, want unix", l.socks5Network)
			}

			conn, err := l.dialTCP("example.com:443")
			if err != nil {
				t.Fatalf("dialTCP() error = %v", err)
			}
			defer conn.Close()

			select {
			case target := <-server.targets:
				if target != "example.com:443" {
					t.Fatalf("SOCKS5 target = %q, want example.com:443", target)
				}
			case err := <-server.errs:
				t.Fatalf("fake SOCKS5 server error = %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for SOCKS5 connect request")
			}
		})
	}
}

type fakeSocks5UnixServer struct {
	path     string
	ln       net.Listener
	username string
	password string
	targets  chan string
	errs     chan error
}

func startFakeSocks5UnixServer(t *testing.T, username, password string) *fakeSocks5UnixServer {
	t.Helper()

	path := filepath.Join(t.TempDir(), "socks5.sock")
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("Listen unix error = %v", err)
	}
	server := &fakeSocks5UnixServer{
		path:     path,
		ln:       ln,
		username: username,
		password: password,
		targets:  make(chan string, 1),
		errs:     make(chan error, 1),
	}
	go server.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(path)
	})
	return server
}

func (s *fakeSocks5UnixServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			if err := s.handleConn(conn); err != nil {
				select {
				case s.errs <- err:
				default:
				}
			}
		}()
	}
}

func (s *fakeSocks5UnixServer) handleConn(conn net.Conn) error {
	if err := s.negotiate(conn); err != nil {
		return err
	}
	target, err := readSocks5ConnectTarget(conn)
	if err != nil {
		return err
	}
	reply := []byte{socks5Version, 0x00, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return err
	}
	s.targets <- target
	return nil
}

func (s *fakeSocks5UnixServer) negotiate(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("bad SOCKS5 version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if s.username == "" {
		if _, err := conn.Write([]byte{socks5Version, socks5AuthNone}); err != nil {
			return err
		}
		return nil
	}

	if !hasSocks5Method(methods, socks5AuthUserPass) {
		return fmt.Errorf("SOCKS5 username/password auth was not offered")
	}
	if _, err := conn.Write([]byte{socks5Version, socks5AuthUserPass}); err != nil {
		return err
	}
	return s.authenticateUsernamePassword(conn)
}

func (s *fakeSocks5UnixServer) authenticateUsernamePassword(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 0x01 {
		return fmt.Errorf("bad SOCKS5 username/password auth version %d", header[0])
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	var passwordLen [1]byte
	if _, err := io.ReadFull(conn, passwordLen[:]); err != nil {
		return err
	}
	password := make([]byte, int(passwordLen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	if string(username) != s.username || string(password) != s.password {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("bad SOCKS5 username/password: %q/%q", username, password)
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func hasSocks5Method(methods []byte, want byte) bool {
	for _, method := range methods {
		if method == want {
			return true
		}
	}
	return false
}

func readSocks5ConnectTarget(conn net.Conn) (string, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", err
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("bad SOCKS5 connect version %d", header[0])
	}
	if header[1] != 0x01 {
		return "", fmt.Errorf("bad SOCKS5 command %d", header[1])
	}
	host, err := readSocks5Address(conn, header[3])
	if err != nil {
		return "", err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
