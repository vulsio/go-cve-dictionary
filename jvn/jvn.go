package jvn

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"unsafe"

	"github.com/cenkalti/backoff"
	"github.com/cheggaaa/pb"
	"github.com/k0kubun/pp"
	c "github.com/kotakanbe/go-cve-dictionary/config"
	"github.com/parnurzeal/gorequest"

	log "github.com/kotakanbe/go-cve-dictionary/log"
)

type status struct {
	ErrCd       string `xml:"errCd,attr"`
	ErrMsg      string `xml:"errMsg,attr"`
	FirstRes    string `xml:"firstRes,attr"`
	Lang        string `xml:"lang,attr"`
	Method      string `xml:"method,attr"`
	RetCd       string `xml:"retCd,attr"`
	RetMax      string `xml:"retMax,attr"`
	TotalRes    string `xml:"totalRes,attr"`
	TotalResRet string `xml:"totalResRet,attr"`
	Version     string `xml:"version,attr"`
}

type product struct {
	Pname string `xml:"pname,attr"`
	Cpe   string `xml:"cpe,attr"`
	Pid   string `xml:"pid,attr"`
}

type vendor struct {
	Vname    string    `xml:"vname,attr"`
	Cpe      string    `xml:"cpe,attr"`
	Vid      string    `xml:"vid,attr"`
	Products []product `xml:"Product"`
}

// VendorInfo Vendor Information
type VendorInfo struct {
	Lang    string   `xml:"xml:lang,attr"`
	Vendors []vendor `xml:"Vendor"`
}

type cpeItemMetadata struct {
	IssueDate        string `xml:"issue-date,attr"`
	ModificationDate string `xml:"modification-date,attr"`
	Authority        string `xml:"authority,attr"`
	JvnID            string `xml:"jvn-id,attr"`
}

type cpeItem struct {
	// cpe:/a:mysql:mysql
	Name string `xml:"name,attr"`
	// MySQL
	Title string `xml:"title"`
	// MySQL AB
	Vname    string          `xml:"vname"`
	Metadata cpeItemMetadata `xml:"item-metadata"`
}

type generator struct {
	Timestamp string `xml:"timestamp"`
}

// CpeList ... CPE List
type CpeList struct {
	CpeItem   []cpeItem `xml:"cpe-item"`
	Generator generator `xml:"generator"`
}

type references struct {
	ID     string `xml:"id,attr"`
	Source string `xml:"source,attr"`
	URL    string `xml:",chardata"`
}

// Cvss ... CVSS
type Cvss struct {
	Score    string `xml:"score,attr"`
	Severity string `xml:"severity,attr"`
	Vector   string `xml:"vector,attr"`
	Version  string `xml:"version,attr"`
}

// Item ... http://jvndb.jvn.jp/apis/getVulnOverviewList_api.html
type Item struct {
	About       string       `xml:"about,attr"`
	Title       string       `xml:"title"`
	Link        string       `xml:"link"`
	Description string       `xml:"description"`
	Publisher   string       `xml:"publisher"`
	Creator     string       `xml:"creator"`
	Identifier  string       `xml:"identifier"`
	References  []references `xml:"references"`
	CpeItem     []cpeItem    `xml:"cpe-item"`
	Cvss        Cvss         `xml:"cvss"`
	Date        string       `xml:"date"`
	Issued      string       `xml:"issued"`
	Modified    string       `xml:"modified"`
}

type relatedItem struct {
	Type      string `xml:"type,attr"`
	Name      string `xml:"Name"`
	VulinfoID string `xml:"VulinfoID"`
	URL       string `xml:"URL"`
}

type cvssImpact struct {
	Score    string `xml:"Score"`
	Severity string `xml:"Severity"`
	Vector   string `xml:"Vector"`
	Version  string `xml:"version,attr"`
}

type impact struct {
	Cvss       cvssImpact `xml:"Cvss"`
	Desription string     `xml:"ImpactItem>Description"`
}

type affectedItem struct {
	Name          string   `xml:"Name"`
	ProductName   string   `xml:"ProductName"`
	VersionNumber []string `xml:"VersionNumber"`
}

type vulinfoData struct {
	Title              string         `xml:"Title"`
	VulinfoDescription string         `xml:"VulinfoDescription>Overview"`
	Affected           []affectedItem `xml:"Affected>AffectedItem"`
	Impact             impact         `xml:"Impact"`
	Solution           string         `xml:"Solution>SolutionItem>Description"`
	Related            []relatedItem  `xml:"Related>RelatedItem"`
	DateFirstPublished string         `xml:"DateFirstPublished"`
	DateLastUpdated    string         `xml:"DateLastUpdated"`
	DatePublic         string         `xml:"DatePublic"`
	History            []string       `xml:"History>HistoryItem>Description"`
}

// Vulinfo ... VulnInfo
type Vulinfo struct {
	VulinfoID   string      `xml:"VulinfoID"`
	VulinfoData vulinfoData `xml:"VulinfoData"`
}

// Result ... Result data
type Result struct {
	CpeList    CpeList    `xml:"cpe-list"`
	VendorInfo VendorInfo `xml:"VendorInfo"`
	Items      []Item     `xml:"item"`
	Vulinfo    Vulinfo    `xml:"Vulinfo"`
	Status     status     `xml:"Status"`
	Errors     []error
}

// URL ... JVN URL
const URL = "http://jvndb.jvn.jp/myjvn"

var httpProxy = ""

// FetchCVEs Fetch vulnerabilty information from JVN
// http://jvndb.jvn.jp/apis/getVulnOverviewList_api.html
//TODO refresh after updatedAt in DB
func FetchCVEs() (items []Item, err error) {
	prm := map[string]string{
		"method":          "getVulnOverviewList",
		"rangeDatePublic": "n",
		//  "rangeDatePublished":      "n",
		"rangeDatePublished":      c.Conf.FetchJvnPeriodChar,
		"rangeDateFirstPublished": "n",
		"keyword":                 "",
		"maxCountItem":            "",
	}

	concurrentMax := 20
	var result []*Result
	if result, err = Request(prm, concurrentMax, c.Conf.HTTPProxy); err != nil {
		return items, fmt.Errorf("Failed to fetch data. err: %s", err)
	}
	for _, r := range result {
		items = append(items, r.Items...)
	}
	return
}

func getNumHits(
	urlValues map[string]string,
) (numHits int, retMax int, err error) {

	prms := url.Values{}
	for k, v := range urlValues {
		prms.Set(k, v)
	}
	prms.Set("maxCountItem", "1")
	url := URL + "?" + prms.Encode()

	var body string
	if body, err = httpGet(url); err != nil {
		return 0, 0, fmt.Errorf("HTTP Error: %v", err)
	}

	byteBody := *(*[]byte)(unsafe.Pointer(&body))
	r := &Result{}

	err = xml.Unmarshal(byteBody, &r)
	if err != nil {
		return 0, 0, fmt.Errorf("error: %v", err)
	}

	// check status
	if r.Status.RetCd != "0" {
		return 0, 0, fmt.Errorf("JVN API Error: %s", r.Status.ErrMsg)
	}

	numHits, _ = strconv.Atoi(r.Status.TotalRes)
	retMax, _ = strconv.Atoi(r.Status.RetMax)
	return numHits, retMax, nil
}

func calcNumTimesRequest(
	restPrms map[string]string,
	hitCount,
	maxReturnItemsPerRequest int,
) (numTimeRequest int, err error) {
	if s, ok := restPrms["maxCountItem"]; !ok {
		numTimeRequest = hitCount/maxReturnItemsPerRequest + 1
	} else if len(restPrms["maxCountItem"]) == 0 {
		numTimeRequest = hitCount/maxReturnItemsPerRequest + 1
	} else {
		maxCountItem, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("maxCountItem cannnot convert to int. :%s", s)
		}
		smaller := maxCountItem
		if hitCount < maxCountItem {
			smaller = hitCount
		}
		if maxReturnItemsPerRequest < smaller {
			if smaller%maxReturnItemsPerRequest == 0 {
				numTimeRequest = smaller / maxReturnItemsPerRequest
			} else {
				numTimeRequest = 1 + smaller/maxReturnItemsPerRequest
			}
		} else {
			numTimeRequest = 1
		}
	}
	return
}

func getStartItem(urlValues map[string]string) (startItem int, err error) {
	var a string
	var found bool
	a, found = urlValues["startItem"]
	if !found {
		return 1, nil
	}
	var i int
	if i, err = strconv.Atoi(a); err != nil {
		return 0, fmt.Errorf("startItem cannnot convert to int. :%s", a)
	}
	return i, nil
}

func makeScenario(numTimesRequest, startItem, maxReturnItemsPerRequest int) (scenario []int) {
	scenario = make([]int, numTimesRequest, numTimesRequest)
	for i := range scenario {
		scenario[i] = startItem + i*maxReturnItemsPerRequest
	}
	return
}

func httpGet(url string) (body string, err error) {
	var resp *http.Response
	var errs []error
	f := func() (err error) {
		resp, body, errs = gorequest.New().Proxy(httpProxy).Get(url).End()
		if len(errs) > 0 || resp.StatusCode != 200 {
			return fmt.Errorf("HTTP Error %s", errs)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		//TODO stdout??
		//fmt.Println(err, t)
	}
	err = backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify)
	if err != nil {
		return "", fmt.Errorf("HTTP Error: %s", err)
	}
	return
}

// Request ... Fetch CVE vulunerability informatino from JVN
func Request(
	urlValues map[string]string,
	concurrentMax int,
	httpProxyIfAny ...string,
) (result []*Result, err error) {

	if 0 < len(httpProxyIfAny) {
		httpProxy = httpProxyIfAny[0]
	}

	var numHits, maxReturnItemsPerRequest int
	if numHits, maxReturnItemsPerRequest, err = getNumHits(urlValues); err != nil {
		return nil, err
	}
	log.Debugf("numHits: %d", numHits)

	var numTimeRequest int
	if numTimeRequest, err =
		calcNumTimesRequest(urlValues, numHits, maxReturnItemsPerRequest); err != nil {
		return nil, err
	}
	log.Debugf("numTimeRequest: %d", numTimeRequest)

	var startItem int
	if startItem, err = getStartItem(urlValues); err != nil {
		return nil, err
	}
	log.Debugf("startItem: %d", startItem)

	// ex. startItem: 10, RetMax: 100 -> [10, 110, 210, 310, ...]
	scenario := makeScenario(numTimeRequest, startItem, maxReturnItemsPerRequest)
	log.Debugf("scenario: %s", pp.Sprintf("%v", scenario))

	// worker-pools pattern  https://gobyexample.com/worker-pools
	jobChan := make(chan int, len(scenario))
	resultChan := make(chan *Result, len(scenario))
	defer close(jobChan)
	defer close(resultChan)

	go func() {
		for _, startItem := range scenario {
			jobChan <- startItem
		}
	}()

	for i := 0; i < concurrentMax; i++ {
		go func() {
			for {
				select {
				case sitem, ok := <-jobChan:
					if !ok {
						// channel closed
						return
					}
					var maxCountItem int
					if _, ok := urlValues["maxCountItem"]; !ok {
						maxCountItem = maxReturnItemsPerRequest
					} else if s, _ := urlValues["maxCountItem"]; len(s) == 0 {
						maxCountItem = maxReturnItemsPerRequest
					} else {
						// When the last of scenario array,
						//  set maxCountItem to the remaining number
						if sitem == scenario[len(scenario)-1] {
							m, _ := strconv.Atoi(s)
							if m%maxReturnItemsPerRequest == 0 {
								maxCountItem = maxReturnItemsPerRequest
							} else {
								maxCountItem = m % maxReturnItemsPerRequest
							}
						} else {
							maxCountItem = maxReturnItemsPerRequest
						}
					}

					prms := url.Values{}
					for k, v := range urlValues {
						prms.Set(k, v)
					}
					prms.Set("maxCountItem", strconv.Itoa(maxCountItem))
					prms.Set("startItem", strconv.Itoa(sitem))
					url := URL + "?" + prms.Encode()
					log.Debugf("url: %s", url)

					result := &Result{}
					var body string
					if body, err = httpGet(url); err != nil {
						result.Errors = append(result.Errors, err)
						resultChan <- result
						return
					}

					byteBody := *(*[]byte)(unsafe.Pointer(&body))
					if err = xml.Unmarshal(byteBody, &result); err != nil {
						result.Errors = append(result.Errors, err)
					}
					log.Debugf("Status: %s", pp.Sprintf("%v", result.Status))

					// append to Result.Errors if error occured.
					if result.Status.RetCd != "0" {
						result.Errors = append(result.Errors,
							fmt.Errorf("JVN API Error: %s", result.Status.ErrMsg))
					}

					resultChan <- result
				}
			}
		}()
	}

	bar := pb.StartNew(len(scenario))
	//TODO  Error
	for range scenario {
		bar.Increment()
		result = append(result, <-resultChan)
	}
	//  bar.FinishPrint("Finished to fetch CVE information from JVN.")
	return result, nil
}
