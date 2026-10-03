package compliance

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// TestPerformance 复现验收规模：100 万用户（90 万属于同一租户），
// 初始装载后交错执行 20000 次单用户替换和 20000 次大租户汇总查询，
// 库操作总耗时（不含初始装载）应不超过 15 秒。
// 运行：go test -run TestPerformance -v
func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}
	const (
		totalUsers   = 1_000_000
		bigTenant    = "big-tenant"
		bigTenantN   = 900_000
		replaceOps   = 20_000
		queryOps     = 20_000
		maxOpElapsed = 15 * time.Second
	)

	rng := rand.New(rand.NewSource(7))
	d := NewDirectory()

	// 初始装载：密码修改时刻分散在不同秒。
	loadStart := time.Now()
	const batchSize = 10_000
	for start := 0; start < totalUsers; start += batchSize {
		batch := make([]User, 0, batchSize)
		for i := start; i < start+batchSize && i < totalUsers; i++ {
			tenant := bigTenant
			if i >= bigTenantN {
				tenant = fmt.Sprintf("tenant-%d", i%1000)
			}
			ts := baseTime.Add(time.Duration(rng.Int63n(10*365*86400)) * time.Second)
			u := User{
				UserKey:            UserKey{TenantID: tenant, UserID: fmt.Sprintf("user-%d", i)},
				AccountEnabled:     rng.Intn(20) != 0,
				MFAEnabled:         rng.Intn(2) == 0,
				IsGuest:            rng.Intn(5) == 0,
				HasAdminRole:       rng.Intn(10) == 0,
				LastPasswordChange: &ts,
			}
			if rng.Intn(10) == 0 {
				u.LastPasswordChange = nil
			}
			batch = append(batch, u)
		}
		d.ReplaceUsers(batch)
	}
	loadElapsed := time.Since(loadStart)

	// 交错执行替换与查询，只统计库操作耗时。
	cfg := RuleConfig{GuestAdminEnabled: true, MFARequiredEnabled: true, PasswordExpiryEnabled: true, MaxPasswordAgeDays: 90}
	var opElapsed time.Duration
	var lastSummary Summary
	for i := 0; i < replaceOps+queryOps; i++ {
		start := time.Now()
		if i%2 == 0 {
			// 单用户替换，可改变任意用户信息。
			id := rng.Intn(totalUsers)
			tenant := bigTenant
			if id >= bigTenantN {
				tenant = fmt.Sprintf("tenant-%d", id%1000)
			}
			u := User{
				UserKey:        UserKey{TenantID: tenant, UserID: fmt.Sprintf("user-%d", id)},
				AccountEnabled: rng.Intn(20) != 0,
				MFAEnabled:     rng.Intn(2) == 0,
				IsGuest:        rng.Intn(5) == 0,
				HasAdminRole:   rng.Intn(10) == 0,
			}
			if rng.Intn(10) != 0 {
				ts := baseTime.Add(time.Duration(rng.Int63n(10*365*86400)) * time.Second)
				u.LastPasswordChange = &ts
			}
			d.ReplaceUsers([]User{u})
		} else {
			// 大租户汇总查询，时刻、有效期及规则开关每次变化。
			cfg.GuestAdminEnabled = rng.Intn(4) != 0
			cfg.MFARequiredEnabled = rng.Intn(4) != 0
			cfg.PasswordExpiryEnabled = rng.Intn(4) != 0
			cfg.MaxPasswordAgeDays = 1 + rng.Intn(3650)
			check := baseTime.Add(time.Duration(rng.Int63n(12*365*86400)-365*86400) * time.Second)
			lastSummary = d.Summarize(bigTenant, check, cfg)
		}
		opElapsed += time.Since(start)
	}

	t.Logf("users=%d (big tenant=%d), load=%v, ops=%d replaces + %d queries, op elapsed=%v, last summary=%+v",
		totalUsers, bigTenantN, loadElapsed, replaceOps, queryOps, opElapsed, lastSummary)
	if opElapsed > maxOpElapsed {
		t.Fatalf("op elapsed %v exceeds %v", opElapsed, maxOpElapsed)
	}
}
