package jvn

import "testing"

func TestCalcNumTimesRequest(t *testing.T) {

	var testdata = []struct {
		prm      map[string]string //m
		hit      int               //h
		retMax   int               //r
		numTimes int
	}{
		{map[string]string{}, 2, 3, 1},                    // not m
		{map[string]string{"maxCountItem": "1"}, 2, 3, 1}, // m < h < r
		{map[string]string{"maxCountItem": "1"}, 3, 2, 1}, // m < r < h
		{map[string]string{"maxCountItem": "2"}, 1, 3, 1}, // h < m < r
		{map[string]string{"maxCountItem": "2"}, 3, 1, 2}, // r < m < h
		{map[string]string{"maxCountItem": "3"}, 1, 2, 1}, // h < r < m
		{map[string]string{"maxCountItem": "3"}, 2, 1, 2}, // r < h < m
		{map[string]string{"maxCountItem": "1"}, 1, 3, 1}, // m = h < r
		{map[string]string{"maxCountItem": "1"}, 2, 2, 1}, // m < h = r
		{map[string]string{"maxCountItem": "1"}, 3, 1, 1}, // m = r < h
		{map[string]string{"maxCountItem": "1"}, 2, 2, 1}, // m < r = h
		{map[string]string{"maxCountItem": "3"}, 1, 1, 1}, // h = r < m
		{map[string]string{"maxCountItem": "3"}, 1, 3, 1}, // h < r = m
		{map[string]string{"maxCountItem": "3"}, 2, 2, 1}, // r = h < m
		{map[string]string{"maxCountItem": "3"}, 3, 1, 3}, // r < h = m
		{map[string]string{"maxCountItem": "3"}, 3, 3, 1}, // r = h = m

		{map[string]string{"maxCountItem": "110"}, 5000, 50, 3}, //
	}

	for _, tt := range testdata {
		n, _ := calcNumTimesRequest(tt.prm, tt.hit, tt.retMax)
		if n != tt.numTimes {
			t.Errorf("numTimes : expected %d, actual %d, data: %v",
				tt.numTimes,
				n,
				tt,
			)
		}
	}

}

func testEq(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMakeScenario(t *testing.T) {
	var testdata = []struct {
		numTimes  int
		startItem int
		retMax    int
		scenario  []int
	}{
		{3, 1, 10, []int{1, 11, 21}},
		{3, 2, 10, []int{2, 12, 22}},
		{3, 1, 1, []int{1, 2, 3}},
		{3, 2, 1, []int{2, 3, 4}},
		{3, 100, 1, []int{100, 101, 102}},
	}

	for _, tt := range testdata {
		s := makeScenario(tt.numTimes, tt.startItem, tt.retMax)
		if !testEq(s, tt.scenario) {
			t.Errorf("scenario: expected %v, actual %v", tt.scenario, s)
		}
	}
}
