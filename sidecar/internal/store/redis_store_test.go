package store

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRedisServer is an in-process RESP2 server covering PING, AUTH, EXISTS,
// SET, INCR, EXPIRE, ZADD, ZREMRANGEBYSCORE, and ZRANGE for race-checked tests.
type fakeRedisServer struct {
	ln       net.Listener
	password string
	mu       sync.Mutex
	kv       map[string]string
	zsets    map[string]map[string]float64
}

func startFakeRedis(t *testing.T, password string) *fakeRedisServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake redis: %v", err)
	}
	s := &fakeRedisServer{
		ln:       ln,
		password: password,
		kv:       make(map[string]string),
		zsets:    make(map[string]map[string]float64),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeRedisServer) handleConn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	authed := s.password == ""
	for {
		val, err := readRESP(r)
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
		arr, ok := val.([]any)
		if !ok || len(arr) == 0 {
			return
		}
		args := make([]string, len(arr))
		for i, a := range arr {
			args[i], _ = a.(string)
		}
		cmd := strings.ToUpper(args[0])
		if cmd == "AUTH" {
			if len(args) == 2 && args[1] == s.password {
				authed = true
				_, _ = c.Write([]byte("+OK\r\n"))
			} else {
				_, _ = c.Write([]byte("-ERR invalid password\r\n"))
			}
			continue
		}
		if !authed {
			_, _ = c.Write([]byte("-NOAUTH Authentication required\r\n"))
			continue
		}

		s.mu.Lock()
		switch cmd {
		case "PING":
			_, _ = c.Write([]byte("+PONG\r\n"))
		case "EXISTS":
			if _, ok := s.kv[args[1]]; ok {
				_, _ = c.Write([]byte(":1\r\n"))
			} else {
				_, _ = c.Write([]byte(":0\r\n"))
			}
		case "SET":
			s.kv[args[1]] = args[2]
			_, _ = c.Write([]byte("+OK\r\n"))
		case "INCR":
			cur, _ := strconv.Atoi(s.kv[args[1]])
			cur++
			s.kv[args[1]] = strconv.Itoa(cur)
			_, _ = c.Write([]byte(fmt.Sprintf(":%d\r\n", cur)))
		case "EXPIRE":
			_, _ = c.Write([]byte(":1\r\n"))
		case "ZADD":
			key := args[1]
			score, _ := strconv.ParseFloat(args[2], 64)
			member := args[3]
			if s.zsets[key] == nil {
				s.zsets[key] = make(map[string]float64)
			}
			s.zsets[key][member] = score
			_, _ = c.Write([]byte(":1\r\n"))
		case "ZREMRANGEBYSCORE":
			key := args[1]
			maxScore, _ := strconv.ParseFloat(args[3], 64)
			removed := 0
			for m, sc := range s.zsets[key] {
				if sc <= maxScore {
					delete(s.zsets[key], m)
					removed++
				}
			}
			_, _ = c.Write([]byte(fmt.Sprintf(":%d\r\n", removed)))
		case "ZRANGE":
			key := args[1]
			members := make([]string, 0, len(s.zsets[key]))
			for m := range s.zsets[key] {
				members = append(members, m)
			}
			var b strings.Builder
			b.WriteString(fmt.Sprintf("*%d\r\n", len(members)))
			for _, m := range members {
				b.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(m), m))
			}
			_, _ = c.Write([]byte(b.String()))
		default:
			_, _ = c.Write([]byte("-ERR unknown command\r\n"))
		}
		s.mu.Unlock()
	}
}

func TestRedisStoreMultiReplicaBudgetsAndIdempotency(t *testing.T) {
	srv := startFakeRedis(t, "s3cr3t")

	// Two separate RedisStore instances simulating two K8s sidecar replicas
	replicaA := NewRedisStore(srv.ln.Addr().String(), "s3cr3t", "prom-test:")
	replicaB := NewRedisStore(srv.ln.Addr().String(), "s3cr3t", "prom-test:")
	defer replicaA.Close()
	defer replicaB.Close()

	if err := replicaA.Ping(); err != nil {
		t.Fatalf("replicaA Ping failed: %v", err)
	}

	// 1. Shared idempotency across replicas
	exists, err := replicaA.CheckIdempotency("billing::refund::req-1")
	if err != nil || exists {
		t.Fatalf("expected non-existent idempotency key, got exists=%v err=%v", exists, err)
	}
	if err := replicaA.CommitIdempotency("billing::refund::req-1", time.Hour); err != nil {
		t.Fatalf("commit idempotency failed: %v", err)
	}
	existsB, err := replicaB.CheckIdempotency("billing::refund::req-1")
	if err != nil || !existsB {
		t.Fatalf("expected replicaB to observe committed idempotency key, got exists=%v err=%v", existsB, err)
	}

	// 2. Shared trace counter across replicas
	c1, err := replicaA.IncrTraceCount("trace-1::billing::refund", time.Hour)
	if err != nil || c1 != 1 {
		t.Fatalf("expected count=1, got %d err=%v", c1, err)
	}
	c2, err := replicaB.IncrTraceCount("trace-1::billing::refund", time.Hour)
	if err != nil || c2 != 2 {
		t.Fatalf("expected count=2 across replicas, got %d err=%v", c2, err)
	}

	// 3. Shared rolling 1h monetary sum across replicas (defeats multi-pod smurfing)
	now := time.Now()
	if err := replicaA.RecordRollingSample("user:alice::refund", now.Add(-2*time.Hour), time.Hour, 999.0); err != nil {
		t.Fatalf("record old sample: %v", err)
	}
	if err := replicaA.RecordRollingSample("user:alice::refund", now.Add(-5*time.Minute), time.Hour, 40.0); err != nil {
		t.Fatalf("record sample A: %v", err)
	}
	if err := replicaB.RecordRollingSample("user:alice::refund", now.Add(-1*time.Minute), time.Hour, 45.0); err != nil {
		t.Fatalf("record sample B: %v", err)
	}
	calls, sum, err := replicaB.GetRollingWindow("user:alice::refund", now, time.Hour)
	if err != nil {
		t.Fatalf("GetRollingWindow failed: %v", err)
	}
	if calls != 2 || sum < 84.99 || sum > 85.01 {
		t.Fatalf("expected calls=2 sum=85.00 (old 2h sample pruned), got calls=%d sum=%.2f", calls, sum)
	}
}
