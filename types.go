// Package compliance 提供离线租户合规计分能力。
// 用户目录保存在进程内存中，由上层直接调用，调用按顺序执行，不要求并发安全。
package compliance

import "time"

// UserKey 由租户标识和用户标识共同确定一个用户。
type UserKey struct {
	TenantID string
	UserID   string
}

// User 是一个目录用户的全部信息。替换操作会覆盖该用户的全部字段。
type User struct {
	UserKey
	// AccountEnabled 为 false 的停用账号不参与计分。
	AccountEnabled bool
	MFAEnabled     bool
	IsGuest        bool
	HasAdminRole   bool
	// LastPasswordChange 为最近密码修改时刻，可缺失（nil）。
	// 时间精确到 UTC 整秒。
	LastPasswordChange *time.Time
}

// RuleConfig 是单次查询使用的规则配置，三条规则可分别启用或停用。
type RuleConfig struct {
	// GuestAdminEnabled 启用“访客拥有管理员角色”检查（Critical，扣 100 分）。
	GuestAdminEnabled bool
	// MFARequiredEnabled 启用“未启用 MFA”检查（High，扣 40 分）。
	MFARequiredEnabled bool
	// PasswordExpiryEnabled 启用“密码已满最长有效期”检查（Medium，扣 10 分）。
	PasswordExpiryEnabled bool
	// MaxPasswordAgeDays 为密码最长有效期，单位整天（1 天 = 86400 秒），
	// 取值范围 1 至 3650。仅在 PasswordExpiryEnabled 为 true 时有意义。
	MaxPasswordAgeDays int
}

// Summary 是单个租户在某检查时刻、某规则配置下的合规汇总。
type Summary struct {
	// Participants 为参与计分的启用账号人数。
	Participants int
	// Critical/High/Medium 为各最终违规等级的人数。
	// 同一用户命中多条规则时只归入最严重的等级。
	Critical int
	High     int
	Medium   int
	// Score 为租户得分：100 减去人均扣分后向下取整；没有参与用户时为 100。
	Score int
}
