package reference

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.1.0", "2.0.0", 1},
		{"2.0.0", "2.0.0", 0},
		{"1.9.9", "2.0.0", -1},
		{"550.127.05", "550.54.15", 1},
		{"550.54.15", "550.54.15", 0},
		{"10", "9.9.9", 1},
		{"2.0", "2.0.0", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
