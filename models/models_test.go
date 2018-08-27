package models

import (
	"testing"
)

func TestFeedMeta(t *testing.T) {
	var tests = []struct {
		in       FeedMeta
		uptodate bool
		outdated bool
		newly    bool
	}{
		{
			in: FeedMeta{
				Hash:       "",
				LatestHash: "aaa",
			},
			uptodate: false,
			outdated: false,
			newly:    true,
		},
		{
			in: FeedMeta{
				Hash:       "abc",
				LatestHash: "def",
			},
			uptodate: false,
			outdated: true,
			newly:    false,
		},
		{
			in: FeedMeta{
				Hash:       "def",
				LatestHash: "def",
			},
			uptodate: true,
			outdated: false,
			newly:    false,
		},
	}

	for i, tt := range tests {
		aup := tt.in.UpToDate()
		if tt.uptodate != aup {
			t.Errorf("[%d] up expected: %#v\n  actual: %#v\n", i, tt.uptodate, aup)
		}
		aout := tt.in.OutDated()
		if tt.outdated != aout {
			t.Errorf("[%d] out expected: %#v\n  actual: %#v\n", i, tt.outdated, aout)
		}
		anew := tt.in.Newly()
		if tt.newly != anew {
			t.Errorf("[%d] newly expected: %#v\n  actual: %#v\n", i, tt.newly, anew)
		}
	}
}
