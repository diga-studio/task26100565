package compliance

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func timePtr(t time.Time) *time.Time { return &t }

var baseTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// bruteForce 是独立的逐用户完整计算，用于对照。
func bruteForce(users []User, tenantID string, checkTime time.Time, cfg RuleConfig) Summary {
	var sum Summary
	check := checkTime.UTC().Unix()
	days := cfg.MaxPasswordAgeDays
	if days < 1 {
		days = 1
	}
	if days > 3650 {
		days = 3650
	}
	for _, u := range users {
		if u.TenantID != tenantID || !u.AccountEnabled {
			continue
		}
		sum.Participants++
		critical := u.IsGuest && u.HasAdminRole
		high := !u.MFAEnabled
		medium := true
		if u.LastPasswordChange != nil {
			diff := check - u.LastPasswordChange.UTC().Unix()
			medium = diff >= 0 && diff >= int64(days)*secondsPerDay
		}
		switch {
		case cfg.GuestAdminEnabled && critical:
			sum.Critical++
		case cfg.MFARequiredEnabled && high:
			sum.High++
		case cfg.PasswordExpiryEnabled && medium:
			sum.Medium++
		}
	}
	if sum.Participants == 0 {
		sum.Score = 100
	} else {
		ded := 100*sum.Critical + 40*sum.High + 10*sum.Medium
		sum.Score = (100*sum.Participants - ded) / sum.Participants
	}
	return sum
}

func enabledUser(tenant, id string) User {
	return User{
		UserKey:         UserKey{TenantID: tenant, UserID: id},
		AccountEnabled:  true,
		MFAEnabled:      true,
		LastPasswordChange: timePtr(baseTime),
	}
}

func TestTripleHitCountsOnceAsCritical(t *testing.T) {
	d := NewDirectory()
	u := enabledUser("t1", "u1")
	u.MFAEnabled = false
	u.IsGuest = true
	u.HasAdminRole = true
	u.LastPasswordChange = nil // 缺失也算逾期
	d.ReplaceUsers([]User{u})

	cfg := RuleConfig{GuestAdminEnabled: true, MFARequiredEnabled: true, PasswordExpiryEnabled: true, MaxPasswordAgeDays: 90}
	got := d.Summarize("t1", baseTime, cfg)
	want := Summary{Participants: 1, Critical: 1, High: 0, Medium: 0, Score: 0}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestExactMaxAgeIsViolation(t *testing.T) {
	d := NewDirectory()
	u := enabledUser("t1", "u1")
	change := baseTime
	u.LastPasswordChange = &change
	d.ReplaceUsers([]User{u})

	cfg := RuleConfig{PasswordExpiryEnabled: true, MaxPasswordAgeDays: 30}
	// 恰好相差 30 个整天 => 违规
	atExact := baseTime.Add(30 * 24 * time.Hour)
	if got := d.Summarize("t1", atExact, cfg); got.Medium != 1 {
		t.Fatalf("at exact max age: got %+v, want Medium=1", got)
	}
	// 差 1 秒 => 不违规
	before := atExact.Add(-time.Second)
	if got := d.Summarize("t1", before, cfg); got.Medium != 0 {
		t.Fatalf("1s before max age: got %+v, want Medium=0", got)
	}
}

func TestCheckTimeMovesBackwardAndForward(t *testing.T) {
	d := NewDirectory()
	u := enabledUser("t1", "u1")
	change := baseTime
	u.LastPasswordChange = &change
	d.ReplaceUsers([]User{u})
	cfg := RuleConfig{PasswordExpiryEnabled: true, MaxPasswordAgeDays: 10}

	future := baseTime.Add(365 * 24 * time.Hour)
	if got := d.Summarize("t1", future, cfg); got.Medium != 1 {
		t.Fatalf("future check: got %+v, want Medium=1", got)
	}
	past := baseTime.Add(-365 * 24 * time.Hour)
	if got := d.Summarize("t1", past, cfg); got.Medium != 0 {
		t.Fatalf("past check (回退): got %+v, want Medium=0", got)
	}
	if got := d.Summarize("t1", future, cfg); got.Medium != 1 {
		t.Fatalf("forward again: got %+v, want Medium=1", got)
	}
}

func TestFuturePasswordChangeNotExpired(t *testing.T) {
	d := NewDirectory()
	u := enabledUser("t1", "u1")
	change := baseTime.Add(10 * 24 * time.Hour) // 修改时刻晚于检查时刻
	u.LastPasswordChange = &change
	d.ReplaceUsers([]User{u})
	cfg := RuleConfig{PasswordExpiryEnabled: true, MaxPasswordAgeDays: 1}
	if got := d.Summarize("t1", baseTime, cfg); got.Medium != 0 {
		t.Fatalf("got %+v, want Medium=0", got)
	}
}

func TestMissingPasswordTimeIsExpired(t *testing.T) {
	d := NewDirectory()
	u := enabledUser("t1", "u1")
	u.LastPasswordChange = nil
	d.ReplaceUsers([]User{u})
	cfg := RuleConfig{PasswordExpiryEnabled: true, MaxPasswordAgeDays: 3650}
	if got := d.Summarize("t1", baseTime, cfg); got.Medium != 1 {
		t.Fatalf("got %+v, want Medium=1", got)
	}
}

func TestDisabledAndDeletedUsersNotScored(t *testing.T) {
	d := NewDirectory()
	u1 := enabledUser("t1", "u1")
	u1.MFAEnabled = false
	u2 := enabledUser("t1", "u2")
	u2.MFAEnabled = false
	d.ReplaceUsers([]User{u1, u2})
	cfg := RuleConfig{MFARequiredEnabled: true}

	if got := d.Summarize("t1", baseTime, cfg); got.Participants != 2 || got.High != 2 {
		t.Fatalf("initial: got %+v", got)
	}
	// 停用 u1
	u1.AccountEnabled = false
	d.ReplaceUsers([]User{u1})
	if got := d.Summarize("t1", baseTime, cfg); got.Participants != 1 || got.High != 1 {
		t.Fatalf("after disable: got %+v", got)
	}
	// 删除 u2
	d.DeleteUsers([]UserKey{u2.UserKey})
	want := Summary{Participants: 0, Score: 100}
	if got := d.Summarize("t1", baseTime, cfg); got != want {
		t.Fatalf("after delete: got %+v, want %+v", got, want)
	}
	// 重新启用 u1 应恢复计分
	u1.AccountEnabled = true
	d.ReplaceUsers([]User{u1})
	if got := d.Summarize("t1", baseTime, cfg); got.Participants != 1 || got.High != 1 {
		t.Fatalf("after re-enable: got %+v", got)
	}
}

func TestRuleTogglesAndSeverityFallback(t *testing.T) {
	d := NewDirectory()
	u := enabledUser("t1", "u1")
	u.MFAEnabled = false
	u.IsGuest = true
	u.HasAdminRole = true
	u.LastPasswordChange = nil
	d.ReplaceUsers([]User{u})

	// 全部停用 => 无违规
	got := d.Summarize("t1", baseTime, RuleConfig{MaxPasswordAgeDays: 90})
	if got != (Summary{Participants: 1, Score: 100}) {
		t.Fatalf("all disabled: got %+v", got)
	}
	// 仅 High：访客管理员命中 High
	got = d.Summarize("t1", baseTime, RuleConfig{MFARequiredEnabled: true})
	if got.High != 1 || got.Critical != 0 || got.Medium != 0 {
		t.Fatalf("high only: got %+v", got)
	}
	// 仅 Medium：访客管理员命中 Medium（密码缺失）
	got = d.Summarize("t1", baseTime, RuleConfig{PasswordExpiryEnabled: true, MaxPasswordAgeDays: 90})
	if got.Medium != 1 || got.Critical != 0 || got.High != 0 {
		t.Fatalf("medium only: got %+v", got)
	}
	// Critical 停用、High+Medium 启用 => 归入 High
	got = d.Summarize("t1", baseTime, RuleConfig{MFARequiredEnabled: true, PasswordExpiryEnabled: true, MaxPasswordAgeDays: 90})
	if got.High != 1 || got.Medium != 0 {
		t.Fatalf("fallback to high: got %+v", got)
	}
}

func TestScoreRoundingAndEmptyTenant(t *testing.T) {
	d := NewDirectory()
	if got := d.Summarize("nope", baseTime, RuleConfig{}); got.Score != 100 || got.Participants != 0 {
		t.Fatalf("empty tenant: got %+v", got)
	}
	// 3 个启用用户，1 个 Medium => 人均扣分 10/3，得分 floor(100 - 3.33) = 96
	var users []User
	for i := 0; i < 3; i++ {
		users = append(users, enabledUser("t1", fmt.Sprintf("u%d", i)))
	}
	users[0].LastPasswordChange = nil
	d.ReplaceUsers(users)
	cfg := RuleConfig{PasswordExpiryEnabled: true, MaxPasswordAgeDays: 90}
	got := d.Summarize("t1", baseTime, cfg)
	if got.Score != 96 || got.Medium != 1 || got.Participants != 3 {
		t.Fatalf("got %+v, want Score=96 Medium=1 Participants=3", got)
	}
}

func TestSameUserIDDifferentTenants(t *testing.T) {
	d := NewDirectory()
	a := enabledUser("ta", "u1")
	a.MFAEnabled = false
	b := enabledUser("tb", "u1")
	d.ReplaceUsers([]User{a, b})
	cfg := RuleConfig{MFARequiredEnabled: true}
	if got := d.Summarize("ta", baseTime, cfg); got.High != 1 {
		t.Fatalf("ta: got %+v", got)
	}
	if got := d.Summarize("tb", baseTime, cfg); got.High != 0 || got.Participants != 1 {
		t.Fatalf("tb: got %+v", got)
	}
	d.DeleteUsers([]UserKey{a.UserKey})
	if got := d.Summarize("tb", baseTime, cfg); got.Participants != 1 {
		t.Fatalf("tb after ta delete: got %+v", got)
	}
}

// TestRandomizedAgainstBruteForce 混合新增、替换、删除及规则配置变化，
// 所有汇总与独立的逐用户完整计算结果一致。
func TestRandomizedAgainstBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	d := NewDirectory()
	live := make(map[UserKey]User)
	tenants := []string{"t1", "t2", "t3"}

	randomUser := func() User {
		u := User{
			UserKey: UserKey{
				TenantID: tenants[rng.Intn(len(tenants))],
				UserID:   fmt.Sprintf("u%d", rng.Intn(300)),
			},
			AccountEnabled: rng.Intn(4) != 0,
			MFAEnabled:     rng.Intn(2) == 0,
			IsGuest:        rng.Intn(3) == 0,
			HasAdminRole:   rng.Intn(3) == 0,
		}
		if rng.Intn(4) != 0 {
			ts := baseTime.Add(time.Duration(rng.Int63n(400*86400)-200*86400) * time.Second)
			u.LastPasswordChange = &ts
		}
		return u
	}

	for step := 0; step < 4000; step++ {
		switch rng.Intn(3) {
		case 0: // 批量替换/新增
			batch := make([]User, 1+rng.Intn(20))
			for i := range batch {
				batch[i] = randomUser()
			}
			d.ReplaceUsers(batch)
			for _, u := range batch {
				live[u.UserKey] = u
			}
		case 1: // 批量删除
			keys := make([]UserKey, 0, 10)
			for k := range live {
				if rng.Intn(10) == 0 {
					keys = append(keys, k)
				}
				if len(keys) >= 10 {
					break
				}
			}
			d.DeleteUsers(keys)
			for _, k := range keys {
				delete(live, k)
			}
		case 2: // 查询并对照
			cfg := RuleConfig{
				GuestAdminEnabled:     rng.Intn(2) == 0,
				MFARequiredEnabled:    rng.Intn(2) == 0,
				PasswordExpiryEnabled: rng.Intn(2) == 0,
				MaxPasswordAgeDays:    1 + rng.Intn(3650),
			}
			check := baseTime.Add(time.Duration(rng.Int63n(600*86400)-300*86400) * time.Second)
			tenant := tenants[rng.Intn(len(tenants))]
			all := make([]User, 0, len(live))
			for _, u := range live {
				all = append(all, u)
			}
			got := d.Summarize(tenant, check, cfg)
			want := bruteForce(all, tenant, check, cfg)
			if got != want {
				t.Fatalf("step %d: got %+v, want %+v (cfg=%+v check=%v tenant=%s)",
					step, got, want, cfg, check, tenant)
			}
		}
	}
}
