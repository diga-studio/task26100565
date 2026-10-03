package compliance

import (
	"math/rand"
	"sort"
	"testing"
)

func TestMultisetBasic(t *testing.T) {
	var m timeMultiset
	if m.len() != 0 || m.countLE(100) != 0 {
		t.Fatalf("empty multiset: len=%d countLE=%d", m.len(), m.countLE(100))
	}
	m.add(10)
	m.add(5)
	m.add(10)
	m.add(20)
	m.missing = 2
	if m.len() != 6 {
		t.Fatalf("len=%d, want 6", m.len())
	}
	cases := []struct {
		threshold int64
		want      int
	}{
		{4, 0}, {5, 1}, {9, 1}, {10, 3}, {19, 3}, {20, 4}, {100, 4},
	}
	for _, c := range cases {
		if got := m.countLE(c.threshold); got != c.want {
			t.Fatalf("countLE(%d)=%d, want %d", c.threshold, got, c.want)
		}
	}
	m.remove(10)
	if got := m.countLE(10); got != 2 {
		t.Fatalf("after remove countLE(10)=%d, want 2", got)
	}
	m.remove(10)
	m.remove(5)
	m.remove(20)
	if m.len() != 2 || len(m.blocks) != 0 {
		t.Fatalf("after removing all: len=%d blocks=%d", m.len(), len(m.blocks))
	}
}

func TestMultisetRandomAgainstSlice(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	var m timeMultiset
	var ref []int64
	for i := 0; i < 20000; i++ {
		op := rng.Intn(3)
		if op < 2 || len(ref) == 0 {
			v := int64(rng.Intn(5000))
			m.add(v)
			ref = append(ref, v)
		} else {
			idx := rng.Intn(len(ref))
			m.remove(ref[idx])
			ref = append(ref[:idx], ref[idx+1:]...)
		}
		if i%997 == 0 {
			sort.Slice(ref, func(a, b int) bool { return ref[a] < ref[b] })
			threshold := int64(rng.Intn(5200))
			want := sort.Search(len(ref), func(j int) bool { return ref[j] > threshold })
			if got := m.countLE(threshold); got != want {
				t.Fatalf("iter %d: countLE(%d)=%d, want %d", i, threshold, got, want)
			}
			if m.size != len(ref) {
				t.Fatalf("iter %d: size=%d, want %d", i, m.size, len(ref))
			}
		}
	}
}
