package compliance

import "sort"

// maxBlockSize 是分块有序结构的块容量上限，超出即分裂。
// 增删代价 O(maxBlockSize)，计数查询代价 O(块数 + log 块长)。
const maxBlockSize = 1024

// timeMultiset 是密码修改时刻（Unix 秒）的多重集合，
// 支持单点增删与“不超过阈值”的计数查询。
// 采用分块有序数组：块内有序，块间严格递增（前块元素均小于后块）。
type timeMultiset struct {
	blocks  [][]int64 // 有序块序列
	size    int       // 已记录时刻的总数（不含 missing）
	missing int       // 缺失密码修改时刻的数量
}

// locate 返回 t 应落入的块下标及块内插入位（保持块内有序）。
// 若 t 已存在，块内插入位指向首个等于 t 的位置。
func (m *timeMultiset) locate(t int64) (blockIdx, pos int) {
	// 找到最后一个“首元素 <= t”的块；不存在则返回块 0。
	blockIdx = sort.Search(len(m.blocks), func(i int) bool {
		return m.blocks[i][0] > t
	}) - 1
	if blockIdx < 0 {
		blockIdx = 0
	}
	pos = sort.Search(len(m.blocks[blockIdx]), func(i int) bool {
		return m.blocks[blockIdx][i] >= t
	})
	return blockIdx, pos
}

// add 插入一个时刻。
func (m *timeMultiset) add(t int64) {
	if len(m.blocks) == 0 {
		m.blocks = [][]int64{{t}}
		m.size = 1
		return
	}
	bi, pos := m.locate(t)
	blk := m.blocks[bi]
	blk = append(blk, 0)
	copy(blk[pos+1:], blk[pos:])
	blk[pos] = t
	m.blocks[bi] = blk
	m.size++
	if len(blk) > maxBlockSize {
		mid := len(blk) / 2
		right := make([]int64, len(blk)-mid)
		copy(right, blk[mid:])
		m.blocks[bi] = blk[:mid]
		m.blocks = append(m.blocks, nil)
		copy(m.blocks[bi+2:], m.blocks[bi+1:])
		m.blocks[bi+1] = right
	}
}

// remove 删除一个时刻；调用方保证该时刻存在。
func (m *timeMultiset) remove(t int64) {
	bi, pos := m.locate(t)
	blk := m.blocks[bi]
	copy(blk[pos:], blk[pos+1:])
	blk = blk[:len(blk)-1]
	m.size--
	if len(blk) == 0 {
		m.blocks = append(m.blocks[:bi], m.blocks[bi+1:]...)
		return
	}
	m.blocks[bi] = blk
}

// countLE 返回不超过 threshold 的时刻个数。
func (m *timeMultiset) countLE(threshold int64) int {
	// 最后一个“首元素 <= threshold”的块之前的块全部计入。
	full := sort.Search(len(m.blocks), func(i int) bool {
		return m.blocks[i][0] > threshold
	}) - 1
	if full < 0 {
		return 0
	}
	total := 0
	for _, blk := range m.blocks[:full] {
		total += len(blk)
	}
	total += sort.Search(len(m.blocks[full]), func(i int) bool {
		return m.blocks[full][i] > threshold
	})
	return total
}

// len 返回集合中元素总数（含 missing）。
func (m *timeMultiset) len() int { return m.size + m.missing }
