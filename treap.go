package compliance

// timeBag 是一个按 UTC 秒存储密码修改时刻的多重集合，
// 支持插入、删除单个元素以及统计不超过某阈值的元素个数。
// 内部用带子树计数的 treap 实现，操作均为期望 O(log n)。
type timeBag struct {
	root *treapNode
	size int
	seed uint64
}

type treapNode struct {
	key   int64 // UTC 秒
	count int   // 相同 key 的重复次数
	pri   uint64
	left  *treapNode
	right *treapNode
	size  int // 子树元素总数（含重复）
}

func nodeSize(n *treapNode) int {
	if n == nil {
		return 0
	}
	return n.size
}

func (n *treapNode) pull() {
	n.size = n.count + nodeSize(n.left) + nodeSize(n.right)
}

// nextPri 用 splitmix64 生成随机优先级，避免引入全局随机源。
func (b *timeBag) nextPri() uint64 {
	b.seed += 0x9e3779b97f4a7c15
	z := b.seed
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func rotateRight(n *treapNode) *treapNode {
	l := n.left
	n.left = l.right
	l.right = n
	n.pull()
	l.pull()
	return l
}

func rotateLeft(n *treapNode) *treapNode {
	r := n.right
	n.right = r.left
	r.left = n
	n.pull()
	r.pull()
	return r
}

// insert 向集合中加入一个时刻。
func (b *timeBag) insert(sec int64) {
	b.root = b.insertNode(b.root, sec)
	b.size++
}

func (b *timeBag) insertNode(n *treapNode, sec int64) *treapNode {
	if n == nil {
		return &treapNode{key: sec, count: 1, pri: b.nextPri(), size: 1}
	}
	switch {
	case sec < n.key:
		n.left = b.insertNode(n.left, sec)
		if n.left.pri > n.pri {
			return rotateRight(n)
		}
	case sec > n.key:
		n.right = b.insertNode(n.right, sec)
		if n.right.pri > n.pri {
			return rotateLeft(n)
		}
	default:
		n.count++
	}
	n.pull()
	return n
}

// remove 从集合中移除一个时刻，调用方保证该时刻存在。
func (b *timeBag) remove(sec int64) {
	b.root = b.removeNode(b.root, sec)
	b.size--
}

func (b *timeBag) removeNode(n *treapNode, sec int64) *treapNode {
	switch {
	case sec < n.key:
		n.left = b.removeNode(n.left, sec)
	case sec > n.key:
		n.right = b.removeNode(n.right, sec)
	default:
		if n.count > 1 {
			n.count--
			n.pull()
			return n
		}
		return mergeTreap(n.left, n.right)
	}
	n.pull()
	return n
}

// mergeTreap 合并两棵 treap，要求 left 中所有 key 小于 right 中所有 key。
func mergeTreap(left, right *treapNode) *treapNode {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	if left.pri > right.pri {
		left.right = mergeTreap(left.right, right)
		left.pull()
		return left
	}
	right.left = mergeTreap(left, right.left)
	right.pull()
	return right
}

// countLE 返回集合中不超过 sec 的元素个数。
func (b *timeBag) countLE(sec int64) int {
	total := 0
	for n := b.root; n != nil; {
		switch {
		case sec < n.key:
			n = n.left
		case sec > n.key:
			total += nodeSize(n.left) + n.count
			n = n.right
		default:
			return total + nodeSize(n.left) + n.count
		}
	}
	return total
}
