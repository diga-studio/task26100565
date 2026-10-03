package compliance

import (
	"math/rand"
	"testing"
	"time"
)

func tp(sec int64) *time.Time {
	t := time.Unix(sec, 0).UTC()
	return &t
}

var allRules = RuleConfig{
	GuestAdminRule:     true,
	MFARule:            true,
	PasswordAgeRule:    true,
	MaxPasswordAgeDays: 90,
}

func checkAt(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

func mustSummarize(t *testing.T, d *Directory, tenant string, checkTime time.Time, cfg RuleConfig) Summary {
	t.Helper()
	sum, err := d.Summarize(tenant, checkTime, cfg)
	if err != nil {
		t.Fatalf("Summarize err: %v", err)
	}
	return sum
}

func TestEmptyTenantScores100(t *testing.T) {
	d := NewDirectory()
	sum := mustSummarize(t, d, "ghost", checkAt(1000), allRules)
	if sum != (Summary{Score: 100}) {
		t.Fatalf("got %+v", sum)
	}
}

func TestTripleHitCountsOnceAsCritical(t *testing.T) {
	d := NewDirectory()
	// 同时命中三条规则：访客管理员、未启用 MFA、密码已逾期。
	d.ReplaceUsers("t1", []User{
		{ID: "u1", Enabled: true, Guest: true, Admin: true, MFAEnabled: false, PasswordChangedAt: tp(0)},
	})
	sum := mustSummarize(t, d, "t1", checkAt(200*secondsPerDay), allRules)
	want := Summary{Participants: 1, Critical: 1, Score: 0}
	if sum != want {
		t.Fatalf("got %+v, want %+v", sum, want)
	}
}

func TestExactMaxAgeIsViolation(t *testing.T) {
	d := NewDirectory()
	changed := int64(1000000)
	d.ReplaceUsers("t1", []User{
		{ID: "exact", Enabled: true, MFAEnabled: true, PasswordChangedAt: tp(changed)},
		{ID: "early", Enabled: true, MFAEnabled: true, PasswordChangedAt: tp(changed + 1)},
	})
	cfg := RuleConfig{PasswordAgeRule: true, MaxPasswordAgeDays: 90}
	// 相差恰好 90 天 -> 违规；差 90 天少 1 秒 -> 不违规。
	sum := mustSummarize(t, d, "t1", checkAt(changed+90*secondsPerDay), cfg)
	want := Summary{Participants: 2, Medium: 1, Score: (200 - 10) / 2}
	if sum != want {
		t.Fatalf("got %+v, want %+v", sum, want)
	}
}

func TestFuturePasswordChangeNotExpired(t *testing.T) {
	d := NewDirectory()
	d.ReplaceUsers("t1", []User{
		{ID: "u1", Enabled: true, MFAEnabled: true, PasswordChangedAt: tp(2000)},
	})
	cfg := RuleConfig{PasswordAgeRule: true, MaxPasswordAgeDays: 1}
	sum := mustSummarize(t, d, "t1", checkAt(1000), cfg)
	if sum.Medium != 0 || sum.Score != 100 {
		t.Fatalf("got %+v", sum)
	}
}

func TestMissingPasswordTimeIsExpired(t *testing.T) {
	d := NewDirectory()
	d.ReplaceUsers("t1", []User{
		{ID: "u1", Enabled: true, MFAEnabled: true},
	})
	cfg := RuleConfig{PasswordAgeRule: true, MaxPasswordAgeDays: 3650}
	sum := mustSummarize(t, d, "t1", checkAt(0), cfg)
	if sum.Medium != 1 || sum.Score != 90 {
		t.Fatalf("got %+v", sum)
	}
}

func TestCheckTimeMovesBackward(t *testing.T) {
	d := NewDirectory()
	changed := int64(1000000)
	d.ReplaceUsers("t1", []User{
		{ID: "u1", Enabled: true, MFAEnabled: true, PasswordChangedAt: tp(changed)},
	})
	cfg := RuleConfig{PasswordAgeRule: true, MaxPasswordAgeDays: 90}
	future := mustSummarize(t, d, "t1", checkAt(changed+90*secondsPerDay), cfg)
	if future.Medium != 1 {
		t.Fatalf("future check: got %+v", future)
	}
	// 检查时刻回退后不再逾期。
	past := mustSummarize(t, d, "t1", checkAt(changed+90*secondsPerDay-1), cfg)
	if past.Medium != 0 || past.Score != 100 {
		t.Fatalf("past check: got %+v", past)
	}
}

func TestDisabledAndDeletedUsersNotScored(t *testing.T) {
	d := NewDirectory()
	d.ReplaceUsers("t1", []User{
		{ID: "off", Enabled: false, Guest: true, Admin: true, PasswordChangedAt: tp(0)},
		{ID: "gone", Enabled: true, Guest: true, Admin: true, PasswordChangedAt: tp(0)},
		{ID: "ok", Enabled: true, MFAEnabled: true, PasswordChangedAt: tp(1 << 40)},
	})
	d.DeleteUsers("t1", []string{"gone", "no-such"})
	// 检查时刻距 "ok" 的密码修改仅 1000 秒，未逾期。
	sum := mustSummarize(t, d, "t1", checkAt((1<<40)+1000), allRules)
	want := Summary{Participants: 1, Score: 100}
	if sum != want {
		t.Fatalf("got %+v, want %+v", sum, want)
	}
	// 替换为停用账号后立即不再计分。
	d.ReplaceUsers("t1", []User{{ID: "ok", Enabled: false, Guest: true, Admin: true}})
	sum = mustSummarize(t, d, "t1", checkAt((1<<40)+1000), allRules)
	if sum != (Summary{Score: 100}) {
		t.Fatalf("after disable: got %+v", sum)
	}
}

func TestRuleToggles(t *testing.T) {
	d := NewDirectory()
	d.ReplaceUsers("t1", []User{
		{ID: "ga", Enabled: true, Guest: true, Admin: true, MFAEnabled: true, PasswordChangedAt: tp(0)},
		{ID: "both", Enabled: true, Guest: true, Admin: true, MFAEnabled: false, PasswordChangedAt: tp(0)},
		{ID: "nomfa", Enabled: true, MFAEnabled: false, PasswordChangedAt: tp(0)},
	})
	now := checkAt(200 * secondsPerDay)
	// 全部停用 -> 无违规。
	sum := mustSummarize(t, d, "t1", now, RuleConfig{MaxPasswordAgeDays: 90})
	if sum != (Summary{Participants: 3, Score: 100}) {
		t.Fatalf("all off: got %+v", sum)
	}
	// 关闭 Critical 规则后，访客管理员按其余启用规则降级判定。
	cfg := RuleConfig{MFARule: true, PasswordAgeRule: true, MaxPasswordAgeDays: 90}
	sum = mustSummarize(t, d, "t1", now, cfg)
	// ga：MFA 已启用但密码逾期 -> Medium；both：未启用 MFA -> High；nomfa：High。
	want := Summary{Participants: 3, High: 2, Medium: 1, Score: (300 - 80 - 10) / 3}
	if sum != want {
		t.Fatalf("critical off: got %+v, want %+v", sum, want)
	}
	// 只开 Critical。
	cfg = RuleConfig{GuestAdminRule: true, MaxPasswordAgeDays: 90}
	sum = mustSummarize(t, d, "t1", now, cfg)
	want = Summary{Participants: 3, Critical: 2, Score: (300 - 200) / 3}
	if sum != want {
		t.Fatalf("only critical: got %+v, want %+v", sum, want)
	}
}

func TestTenantsAreIsolated(t *testing.T) {
	d := NewDirectory()
	u := User{ID: "same", Enabled: true, Guest: true, Admin: true}
	d.ReplaceUsers("a", []User{u})
	d.ReplaceUsers("b", []User{u})
	d.DeleteUsers("a", []string{"same"})
	if sum := mustSummarize(t, d, "a", checkAt(0), allRules); sum.Participants != 0 {
		t.Fatalf("tenant a: got %+v", sum)
	}
	sum := mustSummarize(t, d, "b", checkAt(0), allRules)
	if sum.Participants != 1 || sum.Critical != 1 {
		t.Fatalf("tenant b: got %+v", sum)
	}
}

func TestInvalidMaxPasswordAge(t *testing.T) {
	d := NewDirectory()
	for _, days := range []int{0, -1, 3651} {
		cfg := RuleConfig{PasswordAgeRule: true, MaxPasswordAgeDays: days}
		if _, err := d.Summarize("t", checkAt(0), cfg); err == nil {
			t.Fatalf("days=%d: want error", days)
		}
	}
	// 密码规则停用时不校验有效期。
	cfg := RuleConfig{MFARule: true, MaxPasswordAgeDays: 0}
	if _, err := d.Summarize("t", checkAt(0), cfg); err != nil {
		t.Fatalf("disabled rule should not validate: %v", err)
	}
}

func TestScoreFloorsPerCapita(t *testing.T) {
	d := NewDirectory()
	d.ReplaceUsers("t1", []User{
		{ID: "h", Enabled: true, MFAEnabled: false},
		{ID: "c1", Enabled: true, MFAEnabled: true},
		{ID: "c2", Enabled: true, MFAEnabled: true},
	})
	cfg := RuleConfig{MFARule: true, MaxPasswordAgeDays: 90}
	sum := mustSummarize(t, d, "t1", checkAt(0), cfg)
	// 人均扣分 40/3 = 13.33，100 - 13.33 = 86.67 向下取整为 86。
	if sum.Score != 86 {
		t.Fatalf("got %+v", sum)
	}
}

// bruteForce 是独立的逐用户完整计算，用于对照。
func bruteForce(users map[string]User, checkTime time.Time, cfg RuleConfig) Summary {
	var sum Summary
	deductions := 0
	for _, u := range users {
		if !u.Enabled {
			continue
		}
		sum.Participants++
		sev := severityNone
		if u.Guest && u.Admin && cfg.GuestAdminRule {
			sev = severityCritical
		} else if !u.MFAEnabled && cfg.MFARule {
			sev = severityHigh
		} else if cfg.PasswordAgeRule {
			expired := u.PasswordChangedAt == nil ||
				checkTime.UTC().Unix()-u.PasswordChangedAt.UTC().Unix() >=
					int64(cfg.MaxPasswordAgeDays)*secondsPerDay
			if expired {
				sev = severityMedium
			}
		}
		switch sev {
		case severityCritical:
			sum.Critical++
			deductions += deductCritical
		case severityHigh:
			sum.High++
			deductions += deductHigh
		case severityMedium:
			sum.Medium++
			deductions += deductMedium
		}
	}
	if sum.Participants == 0 {
		sum.Score = 100
	} else {
		sum.Score = (100*sum.Participants - deductions) / sum.Participants
	}
	return sum
}

func TestRandomizedAgainstBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	d := NewDirectory()
	tenants := []string{"big", "t1", "t2"}
	mirror := map[string]map[string]User{"big": {}, "t1": {}, "t2": {}}

	randUser := func(id string) User {
		u := User{
			ID:         id,
			Enabled:    rng.Intn(4) != 0,
			MFAEnabled: rng.Intn(2) == 0,
			Guest:      rng.Intn(3) == 0,
			Admin:      rng.Intn(3) == 0,
		}
		if rng.Intn(4) != 0 {
			u.PasswordChangedAt = tp(rng.Int63n(20000000))
		}
		return u
	}

	for step := 0; step < 4000; step++ {
		tenant := tenants[rng.Intn(len(tenants))]
		switch rng.Intn(3) {
		case 0, 1: // 新增或替换
			n := 1 + rng.Intn(5)
			batch := make([]User, n)
			for i := range batch {
				id := string(rune('a' + rng.Intn(200)))
				batch[i] = randUser(id)
				mirror[tenant][id] = batch[i]
			}
			d.ReplaceUsers(tenant, batch)
		case 2: // 删除
			var ids []string
			for id := range mirror[tenant] {
				if rng.Intn(4) == 0 {
					ids = append(ids, id)
				}
			}
			for _, id := range ids {
				delete(mirror[tenant], id)
			}
			d.DeleteUsers(tenant, ids)
		}
		// 每次变更后立即查询，配置与检查时刻随机变化（含回退）。
		cfg := RuleConfig{
			GuestAdminRule:     rng.Intn(2) == 0,
			MFARule:            rng.Intn(2) == 0,
			PasswordAgeRule:    rng.Intn(2) == 0,
			MaxPasswordAgeDays: 1 + rng.Intn(3650),
		}
		checkTime := checkAt(rng.Int63n(30000000))
		got := mustSummarize(t, d, tenant, checkTime, cfg)
		want := bruteForce(mirror[tenant], checkTime, cfg)
		if got != want {
			t.Fatalf("step %d tenant %s cfg %+v check %d:\ngot  %+v\nwant %+v",
				step, tenant, cfg, checkTime.Unix(), got, want)
		}
	}
}
