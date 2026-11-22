// Package store provides optional distributed Redis/Valkey state backing for
// multi-replica Kubernetes deployments of piton-sidecar so idempotency keys,
// per-trace call counters, and rolling 1-hour per-principal budgets cannot be
// multiplied across sidecar replicas.
//
// Implemented in pure Go stdlib RESP2 (zero external dependencies).
package store

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DistributedStore defines shared state operations across sidecar replicas.
type DistributedStore interface {
	CheckIdempotency(key string) (bool, error)
	CommitIdempotency(key string, ttl time.Duration) error
	IncrTraceCount(key string, ttl time.Duration) (int, error)
	GetRollingWindow(key string, now time.Time, window time.Duration) (calls int, sum float64, err error)
	RecordRollingSample(key string, now time.Time, window time.Duration, value float64) error
	Ping() error
}

// RedisStore is a lightweight, thread-safe RESP2 Redis/Valkey client using Go stdlib.
type RedisStore struct {
	addr     string
	password string
	prefix   string
	timeout  time.Duration

	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
}

func NewRedisStore(addr, password, prefix string) *RedisStore {
	if prefix == "" {
		prefix = "piton:"
	}
	return &RedisStore{
		addr:     strings.TrimSpace(addr),
		password: password,
		prefix:   prefix,
		timeout:  2 * time.Second,
	}
}

func (rs *RedisStore) closeLocked() {
	if rs.conn != nil {
		_ = rs.conn.Close()
		rs.conn = nil
		rs.r = nil
	}
}

func (rs *RedisStore) ensureConnLocked() error {
	if rs.conn != nil {
		return nil
	}
	c, err := net.DialTimeout("tcp", rs.addr, rs.timeout)
	if err != nil {
		return err
	}
	rs.conn = c
	rs.r = bufio.NewReader(c)
	if rs.password != "" {
		if _, err := rs.execLocked("AUTH", rs.password); err != nil {
			rs.closeLocked()
			return fmt.Errorf("redis AUTH failed: %w", err)
		}
	}
	return nil
}

func encodeRESP(args ...string) []byte {
	var b strings.Builder
	b.WriteString("*")
	b.WriteString(strconv.Itoa(len(args)))
	b.WriteString("\r\n")
	for _, a := range args {
		b.WriteString("$")
		b.WriteString(strconv.Itoa(len(a)))
		b.WriteString("\r\n")
		b.WriteString(a)
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

func readRESP(r *bufio.Reader) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\r\n")
	if len(line) == 0 {
		return nil, errors.New("empty RESP reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, errors.New("redis error: " + line[1:])
	case ':':
		n, err := strconv.ParseInt(line[1:], 10, 64)
		return n, err
	case '$':
		sz, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if sz < 0 {
			return nil, nil
		}
		buf := make([]byte, sz+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:sz]), nil
	case '*':
		cnt, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if cnt < 0 {
			return nil, nil
		}
		arr := make([]any, 0, cnt)
		for i := 0; i < cnt; i++ {
			v, err := readRESP(r)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unexpected RESP prefix %q", line[0])
	}
}

func (rs *RedisStore) execLocked(args ...string) (any, error) {
	_ = rs.conn.SetDeadline(time.Now().Add(rs.timeout))
	if _, err := rs.conn.Write(encodeRESP(args...)); err != nil {
		rs.closeLocked()
		return nil, err
	}
	val, err := readRESP(rs.r)
	if err != nil {
		// Drop broken connection on I/O errors so next call reconnects cleanly
		if !strings.HasPrefix(err.Error(), "redis error:") {
			rs.closeLocked()
		}
		return nil, err
	}
	return val, nil
}

func (rs *RedisStore) Do(args ...string) (any, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if err := rs.ensureConnLocked(); err != nil {
		return nil, err
	}
	val, err := rs.execLocked(args...)
	if err != nil && rs.conn == nil {
		// One reconnect attempt on stale TCP socket
		if err2 := rs.ensureConnLocked(); err2 != nil {
			return nil, err
		}
		return rs.execLocked(args...)
	}
	return val, err
}

func (rs *RedisStore) Close() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.closeLocked()
}

func (rs *RedisStore) Ping() error {
	_, err := rs.Do("PING")
	return err
}

func (rs *RedisStore) CheckIdempotency(key string) (bool, error) {
	v, err := rs.Do("EXISTS", rs.prefix+"idem:"+key)
	if err != nil {
		return false, err
	}
	if n, ok := v.(int64); ok {
		return n > 0, nil
	}
	return false, nil
}

func (rs *RedisStore) CommitIdempotency(key string, ttl time.Duration) error {
	secs := int(ttl.Seconds())
	if secs < 1 {
		secs = 1
	}
	_, err := rs.Do("SET", rs.prefix+"idem:"+key, "1", "EX", strconv.Itoa(secs), "NX")
	return err
}

func (rs *RedisStore) IncrTraceCount(key string, ttl time.Duration) (int, error) {
	full := rs.prefix + "trace:" + key
	v, err := rs.Do("INCR", full)
	if err != nil {
		return 0, err
	}
	n, _ := v.(int64)
	if n == 1 {
		secs := int(ttl.Seconds())
		if secs < 1 {
			secs = 1
		}
		_, _ = rs.Do("EXPIRE", full, strconv.Itoa(secs))
	}
	return int(n), nil
}

func (rs *RedisStore) GetRollingWindow(key string, now time.Time, window time.Duration) (int, float64, error) {
	full := rs.prefix + "roll:" + key
	cutoffMs := now.Add(-window).UnixMilli()
	if _, err := rs.Do("ZREMRANGEBYSCORE", full, "-inf", strconv.FormatInt(cutoffMs, 10)); err != nil {
		return 0, 0, err
	}
	v, err := rs.Do("ZRANGE", full, "0", "-1")
	if err != nil {
		return 0, 0, err
	}
	arr, ok := v.([]any)
	if !ok {
		return 0, 0, nil
	}
	calls := 0
	var sum float64
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			continue
		}
		calls++
		// Member format: "<nonce>:<float64>"
		if idx := strings.LastIndex(s, ":"); idx >= 0 {
			if f, err := strconv.ParseFloat(s[idx+1:], 64); err == nil {
				sum += f
			}
		}
	}
	return calls, sum, nil
}

func (rs *RedisStore) RecordRollingSample(key string, now time.Time, window time.Duration, value float64) error {
	full := rs.prefix + "roll:" + key
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	member := fmt.Sprintf("%s:%.6f", hex.EncodeToString(nonce[:]), value)
	score := strconv.FormatInt(now.UnixMilli(), 10)
	if _, err := rs.Do("ZADD", full, score, member); err != nil {
		return err
	}
	secs := int(window.Seconds()) + 60
	_, _ = rs.Do("EXPIRE", full, strconv.Itoa(secs))
	return nil
}
