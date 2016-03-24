package nvd

import (
	"fmt"
	"testing"
	"time"
)

func TestMakeFeedURLs(t *testing.T) {
	year := time.Now().Year()
	format := "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz"

	urls := []string{}
	for i := 2002; i < year+1; i++ {
		urls = append(urls, fmt.Sprintf(format, i))
	}

	var testdata = []struct {
		in   bool
		urls []string
	}{
		{
			in: true,
			urls: []string{
				fmt.Sprintf(format, year),
				fmt.Sprintf(format, year-1),
			},
		},
		{
			in:   false,
			urls: urls,
		},
	}

	for _, tt := range testdata {
		urls := makeFeedURLs(tt.in)
		for i := range urls {
			if urls[i] != tt.urls[i] {
				t.Errorf("expected %s, actual %s", urls[i], tt.urls[i])
			}
		}
	}
}
