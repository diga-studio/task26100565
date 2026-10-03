// Package compliance 提供离线租户合规计分能力。
// 目录保存在进程内存中，由上层直接调用，调用按顺序执行，不提供并发保证。
package compliance

import "time"

// User 描述目录中的一个用户。用户由租户标识和用户标识共同确定。
type User struct {
	ID                string     // 用户标识（租户内唯一）
	Enabled           bool       // 账号是否启用；只有启用账号参与计分
	MFAEnabled        bool       // 是否启用 MFA
	Guest             bool       // 是否为访客
	Admin             bool       // 是否拥有管理员角色
	PasswordChangedAt *time.Time // 最近密码修改时刻，可缺失；精确到 UTC 整秒
}

// RuleConfig 是单次查询携带的规则配置。三条规则可分别启用或停用。
type RuleConfig struct {
	GuestAdminRule  bool // 访客拥有管理员角色 -> Critical，扣 100 分
	MFARule         bool // 未启用 MFA -> High，扣 40 分
	PasswordAgeRule bool // 密码已满最长有效期 -> Medium，扣 10 分
	// MaxPasswordAgeDays 密码最长有效期，单位整天（1 天 = 86400 秒），取值 1..3650。
	// 仅在 PasswordAgeRule 启用时校验与使用。
	MaxPasswordAgeDays int
}

// Summary 是单个租户在某检查时刻、某规则配置下的合规汇总。
type Summary struct {
	Participants int // 参与计分的启用账号人数
	Critical     int // 最终违规等级为 Critical 的人数
	High         int // 最终违规等级为 High 的人数
	Medium       int // 最终违规等级为 Medium 的人数
	Score        int // 租户得分：100 减去人均扣分后向下取整；无参与用户时为 100
}
