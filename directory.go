package compliance

import "time"

const secondsPerDay = 86400

// 静态分组：按“访客且管理员”（Critical 候选，bit1）与
// “未启用 MFA”（High 候选，bit0）把启用用户分为 4 组。
// 密码逾期（Medium）与检查时刻、有效期相关，按组用 timeBag 动态统计。
const (
	groupNone   = 0 // 两条静态规则都不命中
	groupMFA    = 1 // 仅未启用 MFA
	groupAdmin  = 2 // 仅访客且管理员
	groupBoth   = 3 // 访客且管理员，且未启用 MFA
	groupCount  = 4
)

// userState 是目录中一个启用用户的计分相关状态。停用用户不保存。
type userState struct {
	group   int
	hasTime bool
	sec     int64 // LastPasswordChange 的 UTC 秒
}

// tenantData 维护单个租户的增量统计，使查询无需全量扫描。
type tenantData struct {
	total      int
	groupTotal [groupCount]int
	bags       [groupCount]timeBag // 各组有密码修改时刻的用户
	missing    [groupCount]int     // 各组缺失密码修改时刻的用户数
}

func (t *tenantData) add(s userState) {
	t.total++
	t.groupTotal[s.group]++
	if s.hasTime {
		t.bags[s.group].insert(s.sec)
	} else {
		t.missing[s.group]++
	}
}

func (t *tenantData) remove(s userState) {
	t.total--
	t.groupTotal[s.group]--
	if s.hasTime {
		t.bags[s.group].remove(s.sec)
	} else {
		t.missing[s.group]--
	}
}

// expired 返回该组在给定阈值（密码修改时刻 <= threshold 即逾期）下的逾期人数。
// 缺失密码修改时刻视为逾期。
func (t *tenantData) expired(group int, threshold int64) int {
	return t.bags[group].countLE(threshold) + t.missing[group]
}

// Directory 是进程内存中的用户目录，支持批量替换/删除用户
// 以及按当前目录即时推演租户合规汇总。
// 调用按顺序执行，不要求并发安全。
type Directory struct {
	users   map[UserKey]userState // 仅保存启用用户
	tenants map[string]*tenantData
}

// NewDirectory 创建一个空目录。
func NewDirectory() *Directory {
	return &Directory{
		users:   make(map[UserKey]userState),
		tenants: make(map[string]*tenantData),
	}
}

// staticGroup 计算用户的静态分组。
func staticGroup(u User) int {
	group := groupNone
	if u.IsGuest && u.HasAdminRole {
		group |= 2
	}
	if !u.MFAEnabled {
		group |= 1
	}
	return group
}

// ReplaceUsers 批量替换（或新增）用户，覆盖每个用户的全部信息。
// 不同租户中的相同用户标识互不影响。停用用户不进入计分结构。
func (d *Directory) ReplaceUsers(users []User) {
	for _, u := range users {
		key := u.UserKey
		if old, ok := d.users[key]; ok {
			d.tenants[key.TenantID].remove(old)
			delete(d.users, key)
		}
		if !u.AccountEnabled {
			continue
		}
		s := userState{group: staticGroup(u)}
		if u.LastPasswordChange != nil {
			s.hasTime = true
			s.sec = u.LastPasswordChange.UTC().Unix()
		}
		d.users[key] = s
		t := d.tenants[key.TenantID]
		if t == nil {
			t = &tenantData{}
			d.tenants[key.TenantID] = t
		}
		t.add(s)
	}
}

// DeleteUsers 批量删除用户，删除不存在的用户视为无操作。
func (d *Directory) DeleteUsers(keys []UserKey) {
	for _, key := range keys {
		if old, ok := d.users[key]; ok {
			d.tenants[key.TenantID].remove(old)
			delete(d.users, key)
		}
	}
}

// Summarize 按当前目录推演指定租户在 checkTime 时刻、cfg 规则配置下的合规汇总。
// 查询只使用当前目录，不恢复历史目录；检查时刻允许前后移动。
// MaxPasswordAgeDays 会被约束在 1 至 3650 之间。
func (d *Directory) Summarize(tenantID string, checkTime time.Time, cfg RuleConfig) Summary {
	t := d.tenants[tenantID]
	if t == nil || t.total == 0 {
		return Summary{Score: 100}
	}

	// 确定各静态分组被哪条启用的规则认领：
	// Critical 认领 groupAdmin/groupBoth；High 认领 groupMFA，
	// 以及 Critical 停用时认领 groupBoth；其余启用用户归入 Medium 候选。
	claimCritical := [groupCount]bool{}
	claimHigh := [groupCount]bool{}
	if cfg.GuestAdminEnabled {
		claimCritical[groupAdmin] = true
		claimCritical[groupBoth] = true
	}
	if cfg.MFARequiredEnabled {
		claimHigh[groupMFA] = true
		if !cfg.GuestAdminEnabled {
			claimHigh[groupBoth] = true
		}
	}

	var sum Summary
	sum.Participants = t.total
	mediumGroups := [groupCount]bool{}
	for g := 0; g < groupCount; g++ {
		switch {
		case claimCritical[g]:
			sum.Critical += t.groupTotal[g]
		case claimHigh[g]:
			sum.High += t.groupTotal[g]
		default:
			mediumGroups[g] = true
		}
	}

	if cfg.PasswordExpiryEnabled {
		days := cfg.MaxPasswordAgeDays
		if days < 1 {
			days = 1
		}
		if days > 3650 {
			days = 3650
		}
		// 时间精确到 UTC 整秒，一天固定 86400 秒，不按自然日取整。
		// 相差恰好达到有效期即违规；修改时刻晚于检查时刻不算逾期。
		threshold := checkTime.UTC().Unix() - int64(days)*secondsPerDay
		for g := 0; g < groupCount; g++ {
			if mediumGroups[g] {
				sum.Medium += t.expired(g, threshold)
			}
		}
	}

	deduction := 100*sum.Critical + 40*sum.High + 10*sum.Medium
	// 得分为 100 减去人均扣分后向下取整；deduction <= 100*Participants，
	// 故分子非负，整数除法即向下取整。
	sum.Score = (100*sum.Participants - deduction) / sum.Participants
	return sum
}
