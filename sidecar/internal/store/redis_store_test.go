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
			nx := false
			for i := 3; i < len(args); i++ {
				if strings.EqualFold(args[i], "NX") {
					nx = true
				}
			}
			if nx {
				if _, exists := s.kv[args[1]]; exists {
					_, _ = c.Write([]byte("$-1\r\n"))
					break
				}
			}
			s.kv[args[1]] = args[2]
			_, _ = c.Write([]byte("+OK\r\n"))
		case "EVAL":
			// Emulate rollingWindowLuaScript atomically under s.mu
			// args: EVAL script 1 key cutoffMs nowMs member val checkCalls maxCalls checkSum maxSum ttlSecs
			if len(args) < 13 {
				_, _ = c.Write([]byte("-ERR wrong number of arguments for EVAL\r\n"))
				break
			}
			key := args[3]
			cutoffMs, _ := strconv.ParseFloat(args[4], 64)
			nowMs, _ := strconv.ParseFloat(args[5], 64)
			member := args[6]
			valNum, _ := strconv.ParseFloat(args[7], 64)
			checkCalls := args[8] == "1"
			maxCalls, _ := strconv.Atoi(args[9])
			checkSum := args[10] == "1"
			maxSum, _ := strconv.ParseFloat(args[11], 64)

			if s.zsets[key] == nil {
				s.zsets[key] = make(map[string]float64)
			}
			for m, sc := range s.zsets[key] {
				if sc <= cutoffMs {
					delete(s.zsets[key], m)
				}
			}
			curCalls := 0
			var curSum float64
			for m := range s.zsets[key] {
				curCalls++
				if idx := strings.LastIndex(m, ":"); idx >= 0 {
					if f, err := strconv.ParseFloat(m[idx+1:], 64); err == nil {
						curSum += f
					}
				}
			}
			nextCalls := curCalls + 1
			nextSum := curSum + valNum
			allowed := 1
			if (checkCalls && nextCalls > maxCalls) || (checkSum && nextSum > maxSum) {
				allowed = 0
			} else {
				s.zsets[key][member] = nowMs
			}
			sumStr := fmt.Sprintf("%.6f", nextSum)
			_, _ = c.Write([]byte(fmt.Sprintf("*3\r\n:%d\r\n:%d\r\n$%d\r\n%s\r\n", allowed, nextCalls, len(sumStr), sumStr)))
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

	// 1. Atomic shared idempotency across replicas under concurrent contention
	const workers = 16
	var wg sync.WaitGroup
	var winMu sync.Mutex
	wins := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			st := replicaA
			if idx%2 == 1 {
				st = replicaB
			}
			acq, err := st.ReserveIdempotency("billing::refund::req-concurrent", time.Hour)
			if err != nil {
				t.Errorf("ReserveIdempotency error: %v", err)
				return
			}
			if acq {
				winMu.Lock()
				wins++
				winMu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("expected exactly 1 winner for concurrent ReserveIdempotency, got %d", wins)
	}

	// 2. Atomic single-use MRTR nonce consumption across replicas
	firstUse, err := replicaA.ConsumeMRTRNonce("jti-abc-123", 10*time.Minute)
	if err != nil || !firstUse {
		t.Fatalf("expected first MRTR nonce consume to succeed, got %v err=%v", firstUse, err)
	}
	secondUse, err := replicaB.ConsumeMRTRNonce("jti-abc-123", 10*time.Minute)
	if err != nil || secondUse {
		t.Fatalf("expected second MRTR nonce replay to fail, got %v err=%v", secondUse, err)
	}

	// 3. Shared trace counter across replicas
	c1, err := replicaA.IncrTraceCount("trace-1::billing::refund", time.Hour)
	if err != nil || c1 != 1 {
		t.Fatalf("expected count=1, got %d err=%v", c1, err)
	}
	c2, err := replicaB.IncrTraceCount("trace-1::billing::refund", time.Hour)
	if err != nil || c2 != 2 {
		t.Fatalf("expected count=2 across replicas, got %d err=%v", c2, err)
	}

	// 4. Atomic rolling 1h budget enforcement across replicas under concurrency (budget=100, each call=40 -> max 2 allowed)
	now := time.Now()
	budgetWins := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			st := replicaA
			if idx%2 == 1 {
				st = replicaB
			}
			_, _, allowed, err := st.CheckAndRecordRollingWindow(
				"user:bob::refund", now, time.Hour, 40.0, 0, 100.0, false, true,
			)
			if err != nil {
				t.Errorf("CheckAndRecordRollingWindow error: %v", err)
				return
			}
			if allowed {
				winMu.Lock()
				budgetWins++
				winMu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if budgetWins != 2 {
		t.Fatalf("expected exactly 2 calls allowed within $100 budget ($40 each), got %d", budgetWins)
	}
}
