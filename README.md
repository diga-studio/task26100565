# tenant-compliance

离线租户合规计分库（Go）。目录保存在进程内存中，由上层直接调用；
调用按顺序执行，非并发安全，不提供重启恢复。每次变更完成后的下一次
查询立即反映新目录，无后台扫描、无暂存结果。

## 功能

- `ReplaceUsers`：批量替换（覆盖）租户目录中的用户，不存在则新增；
  不同租户中的相同用户标识互不影响。
- `DeleteUsers`：批量删除租户目录中的用户。
- `Summarize`：按当前目录推演指定租户在某检查时刻、某规则配置下的
  合规汇总（参与人数、各最终违规等级人数、租户得分）。

## 判定规则

- 只有启用账号参与计分；停用账号不进入人数分母，也不产生违规。
- 三条规则可分别启用或停用，停用的规则完全不参与判定：
  - 访客拥有管理员角色 → Critical，每人扣 100 分；
  - 未启用 MFA → High，每人扣 40 分；
  - 密码已满最长有效期（含缺失修改时刻）→ Medium，每人扣 10 分。
- 同一用户命中多条规则时，只归入最严重的等级并扣一次分。
- 时间精确到 UTC 整秒，一天固定 86400 秒；检查时刻与修改时刻相差
  恰好达到有效期即违规，修改时刻晚于检查时刻不算逾期。
- 得分 = 100 减去人均扣分后向下取整；没有参与用户时得 100 分。

## 使用示例

```go
d := compliance.NewDirectory()

t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
d.ReplaceUsers("tenant-a", []compliance.User{
    {ID: "u1", Enabled: true, MFAEnabled: true, PasswordChangedAt: &t},
    {ID: "u2", Enabled: true, Guest: true, Admin: true}, // 缺失密码修改时刻
})
d.DeleteUsers("tenant-a", []string{"u1"})

sum, err := d.Summarize("tenant-a", time.Now().UTC(), compliance.RuleConfig{
    GuestAdminRule:     true,
    MFARule:            true,
    PasswordAgeRule:    true,
    MaxPasswordAgeDays: 90, // 1..3650，仅密码规则启用时校验
})
// sum.Participants / sum.Critical / sum.High / sum.Medium / sum.Score
```

## 实现要点

- 每个租户按启用用户的属性（访客管理员、未启用 MFA）分为 4 个桶，
  桶内维护密码修改时刻的分块有序多重集合（块容量 1024）。
- 变更（替换/删除）O(块长) 增量更新统计；查询按规则开关确定每个桶的
  最终等级，对 Medium 桶用“不超过阈值”计数求逾期人数，
  代价 O(块数)，无需全量扫描。

## 测试

```sh
go test ./...                                # 全部正确性测试 + 性能测试
go test ./... -short                         # 跳过性能测试
go test ./compliance/ -run TestPerfMillionUsers -v   # 只跑性能测试并查看耗时
```

正确性测试包含：同一用户命中三条规则只计 Critical、恰好满有效期即违规、
检查时刻回退、缺失密码时刻算逾期、修改时刻晚于检查时刻不算逾期、
停用/删除用户不再计分、规则开关降级判定、租户隔离、得分向下取整，
以及随机混合新增/替换/删除/规则配置变化后与独立逐用户完整计算的对照。

性能测试（`TestPerfMillionUsers`）规模：100 万用户（90 万属于同一租户，
密码修改时刻分散在不同秒），初始装载后交错执行 20000 次单用户替换与
20000 次大租户汇总查询（检查时刻、有效期、规则开关每次变化）。
本机实测（Apple Silicon，Go 1.27）：初始装载约 0.3 秒，
交错操作库总耗时约 25 毫秒，远低于 15 秒上限。
