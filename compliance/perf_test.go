package compliance

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// TestPerfMillionUsers 复现验收规模：
// 100 万用户（90 万属于同一租户），初始装载后交错执行
// 20000 次单用户替换与 20000 次大租户汇总查询，
// 库操作总耗时（不含数据生成）须不超过 15 秒。
// 运行：go test ./compliance/ -run TestPerfMillionUsers -v
func TestPerfMillionUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式下跳过性能测试")
	}
	const (
		totalUsers   = 1000000
		bigTenant    = "big"
		smallTenants = 100 // 其余 10 万用户分散在 100 个小租户
		replacements = 20000
		queries      = 20000
		maxOps       = 15 * time.Second
	)
	rng := rand.New(rand.NewSource(20261005))

	// 预生成用户数据（不计入库操作耗时）。
	users := make([]User, totalUsers)
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	for i := range users {
		u := User{
			ID:         fmt.Sprintf("u%07d", i),
			Enabled:    rng.Intn(20) != 0, // 约 5% 停用
			MFAEnabled: rng.Intn(2) == 0,
			Guest:      rng.Intn(10) == 0,
			Admin:      rng.Intn(20) == 0,
		}
		if rng.Intn(10) != 0 {
			// 密码修改时刻分散在不同秒。
			u.PasswordChangedAt = tp(base + rng.Int63n(2000*secondsPerDay))
		}
		users[i] = u
	}

	d := NewDirectory()
	loadStart := time.Now()
	for i := 0; i < totalUsers; i += 10000 {
		end := i + 10000
		if end > totalUsers {
			end = totalUsers
		}
		tenant := bigTenant
		if i >= 900000 {
			tenant = fmt.Sprintf("small-%d", i/10000%smallTenants)
		}
		d.ReplaceUsers(tenant, users[i:end])
	}
	loadElapsed := time.Since(loadStart)

	// 交错执行替换与查询；每次查询的检查时刻、有效期、规则开关均变化。
	start := time.Now()
	for i := 0; i < replacements+queries; i++ {
		if i%2 == 0 {
			u := users[rng.Intn(900000)] // 替换大租户中的用户
			u.Enabled = rng.Intn(20) != 0
			u.MFAEnabled = rng.Intn(2) == 0
			u.Guest = rng.Intn(10) == 0
			u.Admin = rng.Intn(20) == 0
			if rng.Intn(10) != 0 {
				u.PasswordChangedAt = tp(base + rng.Int63n(2000*secondsPerDay))
			} else {
				u.PasswordChangedAt = nil
			}
			d.ReplaceUsers(bigTenant, []User{u})
		} else {
			cfg := RuleConfig{
				GuestAdminRule:     rng.Intn(2) == 0,
				MFARule:            rng.Intn(2) == 0,
				PasswordAgeRule:    rng.Intn(2) == 0,
				MaxPasswordAgeDays: 1 + rng.Intn(3650),
			}
			checkTime := checkAt(base + rng.Int63n(3000*secondsPerDay))
			if _, err := d.Summarize(bigTenant, checkTime, cfg); err != nil {
				t.Fatalf("Summarize err: %v", err)
			}
		}
	}
	mixedElapsed := time.Since(start)

	t.Logf("用户总量: %d（大租户 900000，其余分散在 %d 个小租户）", totalUsers, smallTenants)
	t.Logf("初始装载: %d 用户，耗时 %v", totalUsers, loadElapsed)
	t.Logf("交错操作: %d 次替换 + %d 次汇总查询，库操作总耗时 %v（上限 %v）",
		replacements, queries, mixedElapsed, maxOps)
	if mixedElapsed > maxOps {
		t.Fatalf("库操作总耗时 %v 超过上限 %v", mixedElapsed, maxOps)
	}
}
