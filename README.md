# compliance — 离线租户合规计分库

Go 库，由上层直接调用。用户目录保存在进程内存中，支持批量替换/删除用户，
并按当前目录即时推演指定租户在任意检查时刻、任意规则配置下的合规汇总。
变更完成后下一次查询立即反映新目录，无后台扫描、无暂存结果。

## 构建与测试

```sh
go build ./...
go test ./...                 # 全部正确性测试 + 性能测试
go test -run TestPerformance -v   # 只跑性能测试并查看耗时报告
go test -short ./...          # 跳过性能测试
```

## 快速上手

```go
d := compliance.NewDirectory()

// 批量替换（或新增）用户，覆盖每个用户的全部信息。
// 用户由 (TenantID, UserID) 共同确定，不同租户的相同用户标识互不影响。
t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
d.ReplaceUsers([]compliance.User{{
    UserKey:            compliance.UserKey{TenantID: "tenant-a", UserID: "u1"},
    AccountEnabled:     true,
    MFAEnabled:         false,
    IsGuest:            false,
    HasAdminRole:       false,
    LastPasswordChange: &t, // 可缺失（nil），缺失视为密码逾期
}})

// 批量删除。
d.DeleteUsers([]compliance.UserKey{{TenantID: "tenant-a", UserID: "u2"}})

// 查询：指定租户、检查时刻（可前后移动）和本次规则配置。
sum := d.Summarize("tenant-a", time.Now().UTC(), compliance.RuleConfig{
    GuestAdminEnabled:     true, // 访客拥有管理员角色：Critical，每人扣 100
    MFARequiredEnabled:    true, // 未启用 MFA：High，每人扣 40
    PasswordExpiryEnabled: true, // 密码已满最长有效期：Medium，每人扣 10
    MaxPasswordAgeDays:    90,   // 1..3650 个整天，1 天 = 86400 秒
})
// sum.Participants / sum.Critical / sum.High / sum.Medium / sum.Score
```

## 语义约定

- 只有启用账号参与计分；停用账号不进入人数分母，也不产生违规。
- 同一用户命中多条启用规则时，只归入最严重的等级并扣一次分
  （Critical > High > Medium）。停用的规则完全不参与判定。
- 时间精确到 UTC 整秒，不按自然日取整。检查时刻与密码修改时刻相差
  恰好达到有效期即违规；修改时刻晚于检查时刻不算逾期。
- 得分 = `floor(100 - 人均扣分)`；没有参与用户时得 100 分。
- 查询只使用当前目录做推演，不恢复历史目录。
- 调用按顺序执行，不要求并发安全，也不做重启恢复。

## 实现要点

- 每个租户按静态属性（访客且管理员 / 未启用 MFA）把启用用户分为 4 组，
  分别维护人数、缺失密码修改时刻人数，以及一棵按 UTC 秒组织的
  treap（`treap.go`，期望 O(log n) 插入/删除/阈值计数）。
- 查询时按规则开关把各组认领给 Critical/High，其余组用 treap
  统计密码逾期人数归入 Medium，单次查询 O(log n)，与租户规模基本无关。
- 性能测试实测（Apple Silicon，Go 1.27）：100 万用户（90 万同租户）
  初始装载约 1.2s；交错 20000 次单用户替换 + 20000 次大租户汇总查询，
  库操作总耗时约 63ms，远低于 15 秒上限。
