package broker

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
)

var errEgressBlocked = errors.New("broker: egress to non-public address blocked")

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64 can embed private v4
}

// isPublic rejects loopback, RFC1918, link-local (incl. cloud metadata
// 169.254.169.254), multicast, unspecified and other special ranges.
func isPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// egressControl runs after DNS resolution, on the exact IP being dialled.
// Checking here (not on the hostname) defeats DNS-rebinding SSRF.
func egressControl(allowPrivate bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		if allowPrivate {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !isPublic(ip) {
			return errEgressBlocked
		}
		return nil
	}
}

// redactor streams a response body, replacing every occurrence of the
// secret with '*' of equal length (so Content-Length stays valid). It
// holds back len(secret)-1 bytes so matches split across reads are caught.
type redactor struct {
	src    io.ReadCloser
	secret []byte
	pend   []byte
	out    []byte
	eof    bool
	chunk  []byte
}

func newRedactor(src io.ReadCloser, secret []byte) io.ReadCloser {
	if len(secret) == 0 {
		return src
	}
	return &redactor{src: src, secret: secret, chunk: make([]byte, 32<<10)}
}

func (r *redactor) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.eof {
			if len(r.pend) == 0 {
				return 0, io.EOF
			}
			r.out, r.pend = r.pend, nil
			break
		}
		n, err := r.src.Read(r.chunk)
		r.pend = append(r.pend, r.chunk[:n]...)
		if err == io.EOF {
			r.eof = true
		} else if err != nil {
			return 0, err
		}
		mask(r.pend, r.secret)
		keep := len(r.secret) - 1
		if r.eof {
			keep = 0
		}
		if len(r.pend) > keep {
			cut := len(r.pend) - keep
			r.out = append([]byte(nil), r.pend[:cut]...)
			r.pend = append([]byte(nil), r.pend[cut:]...)
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *redactor) Close() error { return r.src.Close() }

func mask(buf, secret []byte) {
	for i := 0; ; {
		j := bytes.Index(buf[i:], secret)
		if j < 0 {
			return
		}
		start := i + j
		for k := start; k < start+len(secret); k++ {
			buf[k] = '*'
		}
		i = start + len(secret)
	}
}
