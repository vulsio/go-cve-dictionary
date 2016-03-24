package nvd

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cheggaaa/pb"
	c "github.com/kotakanbe/go-cve-dictionary/config"
	log "github.com/kotakanbe/go-cve-dictionary/log"
	"github.com/parnurzeal/gorequest"
)

// Nvd is array of Entry
type Nvd struct {
	Entries []Entry `xml:"entry"`
}

// Entry is Root Element
type Entry struct {
	CveID            string      `xml:"id,attr" json:"id"`
	PublishedDate    time.Time   `xml:"published-datetime"`
	LastModifiedDate time.Time   `xml:"last-modified-datetime"`
	Cvss             Cvss        `xml:"cvss>base_metrics" json:"cvss"`
	Products         []string    `xml:"vulnerable-software-list>product"` //CPE
	Summary          string      `xml:"summary"`
	References       []Reference `xml:"references"`
}

// Cvss is Cvss Score
type Cvss struct {
	Score                 string    `xml:"score"`
	AccessVector          string    `xml:"access-vector"`
	AccessComplexity      string    `xml:"access-complexity"`
	Authentication        string    `xml:"authentication"`
	ConfidentialityImpact string    `xml:"confidentiality-impact"`
	IntegrityImpact       string    `xml:"integrity-impact"`
	AvailabilityImpact    string    `xml:"availability-impact"`
	Source                string    `xml:"source"`
	GeneratedOnDate       time.Time `xml:"generated-on-datetime"`
}

// Reference is additional information about the CVE
type Reference struct {
	Type   string `xml:"reference_type,attr"`
	Source string `xml:"source"`
	Link   Link   `xml:"reference"`
}

// Link is additional information about the CVE
type Link struct {
	Value string `xml:",chardata" json:"value"`
	Href  string `xml:"href,attr" json:"href"`
}

// FetchFiles Fetch CVE vulnerability informatino from JVN
func FetchFiles() (entries []Entry, err error) {
	urls := makeFeedURLs(c.Conf.FetchNvdLast2Y)
	nvds, err := fetchFeedFileConcurrently(urls, c.Conf.HTTPProxy)
	if err != nil {
		return entries,
			fmt.Errorf("Failed to fetch cve data from NVD. err: %s", err)
	}
	for _, nvd := range nvds {
		entries = append(entries, nvd.Entries...)
	}
	return entries, nil
}

func makeFeedURLs(lastTwoYears bool) (urls []string) {
	//  http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.gz
	formatTemplate := "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz"
	year := time.Now().Year()
	if lastTwoYears {
		for i := 0; i < 2; i++ {
			urls = append(urls, fmt.Sprintf(formatTemplate, year-i))
		}
	} else {
		for i := 2002; i < year+1; i++ {
			urls = append(urls, fmt.Sprintf(formatTemplate, i))
		}
	}
	return
}

// TODO move to util package
func genWorkers(num int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			for f := range tasks {
				f()
			}
		}()
	}
	return tasks
}

func fetchFeedFileConcurrently(urls []string, httpProxy string) (nvds []Nvd, err error) {
	reqChan := make(chan string, len(urls))
	resChan := make(chan Nvd, len(urls))
	errChan := make(chan error, len(urls))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, url := range urls {
			reqChan <- url
		}
	}()

	//  concurrency := 10
	concurrency := len(urls)
	tasks := genWorkers(concurrency)
	for range urls {
		tasks <- func() {
			select {
			case url := <-reqChan:
				log.Infof("Fetching... %s", url)
				nvd, err := fetchFeedFile(url, httpProxy)
				if err != nil {
					errChan <- err
				}
				resChan <- nvd
			}
		}
	}

	bar := pb.StartNew(len(urls))
	timeout := time.After(10 * 60 * time.Second)
	for range urls {
		select {
		case nvd := <-resChan:
			nvds = append(nvds, nvd)
		case err := <-errChan:
			return nvds, err
		case <-timeout:
			return nvds, fmt.Errorf("Timeout Fetching Nvd")
		}
		bar.Increment()
	}
	//  bar.FinishPrint("Finished to fetch CVE information from JVN.")
	return nvds, nil
}

func fetchFeedFile(url string, httpProxy string) (nvd Nvd, err error) {
	var body string
	var errs []error
	var resp *http.Response

	resp, body, errs = gorequest.New().Proxy(httpProxy).Get(url).End()
	defer resp.Body.Close()
	if len(errs) > 0 || resp.StatusCode != 200 {
		return nvd, fmt.Errorf(
			"HTTP error. errs: %v, url: %s", errs, url)
	}

	b := bytes.NewBufferString(body)
	reader, err := gzip.NewReader(b)
	defer reader.Close()
	if err != nil {
		return nvd, fmt.Errorf(
			"Failed to decompress NVD feedfile. url: %s, err: %s", url, err)
	}

	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return nvd, fmt.Errorf(
			"Failed to Read NVD feedfile. url: %s, err: %s", url, err)
	}

	if err = xml.Unmarshal(bytes, &nvd); err != nil {
		return nvd, fmt.Errorf(
			"Failed to unmarshal. url: %s, err: %s", url, err)
	}
	return nvd, nil
}
