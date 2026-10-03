package compliance

// combo 数组合计 4 个桶，下标由启用用户的属性决定：
// bit0 = 访客且拥有管理员角色，bit1 = 未启用 MFA。
const (
	comboClean      = 0 // 非访客管理员 且 已启用 MFA
	comboGuestAdmin = 1 // 访客且拥有管理员角色
	comboNoMFA      = 2 // 未启用 MFA
	comboBoth       = 3 // 访客管理员 且 未启用 MFA
)

// comboIndex 计算启用用户所属的属性桶。
func comboIndex(u User) int {
	idx := 0
	if u.Guest && u.Admin {
		idx |= 1
	}
	if !u.MFAEnabled {
		idx |= 2
	}
	return idx
}

// tenantState 保存单个租户的目录与按属性分桶的增量统计。
type tenantState struct {
	users        map[string]User // 用户标识 -> 用户信息
	participants int             // 启用账号人数
	combos       [4]timeMultiset // 启用账号按属性分桶的密码时刻集合
}

func newTenantState() *tenantState {
	return &tenantState{users: make(map[string]User)}
}

// addLocked 将用户纳入统计；仅启用账号参与。
func (s *tenantState) track(u User) {
	if !u.Enabled {
		return
	}
	s.participants++
	ms := &s.combos[comboIndex(u)]
	if u.PasswordChangedAt == nil {
		ms.missing++
	} else {
		ms.add(u.PasswordChangedAt.UTC().Unix())
	}
}

// untrack 将用户移出统计；仅启用账号此前被纳入。
func (s *tenantState) untrack(u User) {
	if !u.Enabled {
		return
	}
	s.participants--
	ms := &s.combos[comboIndex(u)]
	if u.PasswordChangedAt == nil {
		ms.missing--
	} else {
		ms.remove(u.PasswordChangedAt.UTC().Unix())
	}
}

// Directory 是进程内存中的租户目录，按顺序调用，非并发安全。
type Directory struct {
	tenants map[string]*tenantState
}

// NewDirectory 创建空目录。
func NewDirectory() *Directory {
	return &Directory{tenants: make(map[string]*tenantState)}
}

func (d *Directory) tenant(tenant string) *tenantState {
	s, ok := d.tenants[tenant]
	if !ok {
		s = newTenantState()
		d.tenants[tenant] = s
	}
	return s
}

// ReplaceUsers 批量替换（覆盖）租户目录中的用户；
// 不存在的用户视为新增。替换覆盖该用户的全部信息。
func (d *Directory) ReplaceUsers(tenant string, users []User) {
	s := d.tenant(tenant)
	for _, u := range users {
		if old, ok := s.users[u.ID]; ok {
			s.untrack(old)
		}
		s.users[u.ID] = u
		s.track(u)
	}
}

// DeleteUsers 批量删除租户目录中的用户；删除不存在的用户为空操作。
func (d *Directory) DeleteUsers(tenant string, ids []string) {
	s, ok := d.tenants[tenant]
	if !ok {
		return
	}
	for _, id := range ids {
		if old, ok := s.users[id]; ok {
			s.untrack(old)
			delete(s.users, id)
		}
	}
}
