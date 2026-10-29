// Package audit implements an append-only, tamper-evident audit log.
//
// Each line is a JSON entry whose MAC is HMAC-SHA256(key, entry) and whose
// "prev" field holds the previous entry's MAC, forming a hash chain:
// editing, deleting or reordering any entry breaks every MAC after it.
//
// Limitation: truncating the *tail* of the log is only detectable if the
// last sequence number is recorded elsewhere (e.g. shipped to a SIEM).
package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

var ErrTampered = errors.New("audit: log integrity violation")

var genesis = strings.Repeat("0", 64)

type Entry struct {
	Seq    uint64 `json:"seq"`
	Time   string `json:"time"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Result string `json:"result"`
	Prev   string `json:"prev"`
	MAC    string `json:"mac,omitempty"`
}

func (e Entry) mac(key []byte) []byte {
	e.MAC = ""
	b, _ := json.Marshal(e) // struct field order is fixed => canonical
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return m.Sum(nil)
}

type Log struct {
	mu   sync.Mutex
	f    *os.File
	key  []byte
	seq  uint64
	prev string
	now  func() time.Time
}

// Open opens (or creates) the log, verifies the existing chain and
// resumes appending after the last valid entry. A tampered log refuses
// to open so the problem cannot be silently papered over.
func Open(path string, key []byte) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	seq, prev, err := verify(f, key)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Log{f: f, key: append([]byte(nil), key...), seq: seq, prev: prev, now: time.Now}, nil
}

// Append writes one entry and fsyncs it before returning.
func (l *Log) Append(actor, action, target, result string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{
		Seq:    l.seq + 1,
		Time:   l.now().UTC().Format(time.RFC3339Nano),
		Actor:  actor,
		Action: action,
		Target: target,
		Result: result,
		Prev:   l.prev,
	}
	e.MAC = hex.EncodeToString(e.mac(l.key))
	line, err := json.Marshal(e) // escapes control chars: no log injection
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.seq, l.prev = e.Seq, e.MAC
	return nil
}

func (l *Log) Close() error { return l.f.Close() }

// Verify checks a whole log and returns the number of valid entries.
func Verify(r io.Reader, key []byte) (int, error) {
	seq, _, err := verify(r, key)
	return int(seq), err
}

func verify(r io.Reader, key []byte) (uint64, string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var seq uint64
	prev := genesis
	for line := 1; sc.Scan(); line++ {
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		var e Entry
		if err := dec.Decode(&e); err != nil {
			return 0, "", fmt.Errorf("%w: line %d: malformed: %v", ErrTampered, line, err)
		}
		if e.Seq != seq+1 {
			return 0, "", fmt.Errorf("%w: line %d: seq %d, want %d", ErrTampered, line, e.Seq, seq+1)
		}
		if e.Prev != prev {
			return 0, "", fmt.Errorf("%w: line %d: chain broken", ErrTampered, line)
		}
		got, err := hex.DecodeString(e.MAC)
		if err != nil || !hmac.Equal(got, e.mac(key)) {
			return 0, "", fmt.Errorf("%w: line %d: bad MAC", ErrTampered, line)
		}
		seq, prev = e.Seq, e.MAC
	}
	if err := sc.Err(); err != nil {
		return 0, "", err
	}
	return seq, prev, nil
}
