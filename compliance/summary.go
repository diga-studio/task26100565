package compliance

import (
	"fmt"
	"time"
)

// 各违规等级的单人扣分。
const (
	deductCritical = 100
	deductHigh     = 40
	deductMedium   = 10
)

// secondsPerDay 一天固定为 86400 秒，不按自然日取整。
const secondsPerDay = 86400

// 密码最长有效期合法范围（整天）。
const (
	minPasswordAgeDays = 1
	maxPasswordAgeDays = 3650
)

// severity 是最终违规等级。
type severity int

const (
	severityNone severity = iota
	severityMedium
	severityHigh
	severityCritical
)

// comboSeverity 按启用的规则判定某属性桶用户的最终违规等级。
// 同一用户命中多条规则时只归入最严重的等级；停用的规则不参与判定。
func comboSeverity(guestAdmin, noMFA bool, cfg RuleConfig) severity {
	switch {
	case guestAdmin && cfg.GuestAdminRule:
		return severityCritical
	case noMFA && cfg.MFARule:
		return severityHigh
	case cfg.PasswordAgeRule:
		return severityMedium
	default:
		return severityNone
	}
}

// Summarize 使用当前目录推演指定租户在 checkTime、cfg 下的合规汇总。
// 查询只使用当前目录，不恢复历史目录；checkTime 允许前后移动。
func (d *Directory) Summarize(tenant string, checkTime time.Time, cfg RuleConfig) (Summary, error) {
	if cfg.PasswordAgeRule &&
		(cfg.MaxPasswordAgeDays < minPasswordAgeDays || cfg.MaxPasswordAgeDays > maxPasswordAgeDays) {
		return Summary{}, fmt.Errorf("compliance: MaxPasswordAgeDays 必须在 %d..%d 之间，当前为 %d",
			minPasswordAgeDays, maxPasswordAgeDays, cfg.MaxPasswordAgeDays)
	}
	s, ok := d.tenants[tenant]
	if !ok || s.participants == 0 {
		return Summary{Score: 100}, nil
	}

	// 密码逾期阈值：修改时刻 <= 阈值即逾期；缺失时刻也算逾期。
	// 修改时刻晚于检查时刻时阈值自然落在其之后，不会误判。
	threshold := checkTime.UTC().Unix() - int64(cfg.MaxPasswordAgeDays)*secondsPerDay

	var sum Summary
	sum.Participants = s.participants
	deductions := 0
	for idx := range s.combos {
		ms := &s.combos[idx]
		if ms.len() == 0 {
			continue
		}
		sev := comboSeverity(idx&1 != 0, idx&2 != 0, cfg)
		switch sev {
		case severityCritical:
			sum.Critical += ms.len()
			deductions += ms.len() * deductCritical
		case severityHigh:
			sum.High += ms.len()
			deductions += ms.len() * deductHigh
		case severityMedium:
			expired := ms.missing + ms.countLE(threshold)
			sum.Medium += expired
			deductions += expired * deductMedium
		}
	}
	// 得分 = 100 减去人均扣分后向下取整；被除数恒非负，整数除法即向下取整。
	sum.Score = (100*sum.Participants - deductions) / sum.Participants
	return sum, nil
}
