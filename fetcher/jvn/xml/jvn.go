package jvn

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	c "github.com/kotakanbe/go-cve-dictionary/config"
	"github.com/kotakanbe/go-cve-dictionary/db"
	"github.com/kotakanbe/go-cve-dictionary/fetcher"
	"github.com/kotakanbe/go-cve-dictionary/log"
	"github.com/kotakanbe/go-cve-dictionary/models"
	"github.com/kotakanbe/go-cve-dictionary/util"
)

// Meta ... https://jvndb.jvn.jp/ja/feed/checksum.txt
type Meta struct {
	URL          string `json:"url"`
	Hash         string `json:"sha256"`
	LastModified string `json:"lastModified"`
}

type rdf struct {
	Items []Item `xml:"item"`
}

// Item ... http://jvndb.jvn.jp/apis/getVulnOverviewList_api.html
type Item struct {
	About       string       `xml:"about,attr"`
	Title       string       `xml:"title"`
	Link        string       `xml:"link"`
	Description string       `xml:"description"`
	Publisher   string       `xml:"publisher"`
	Identifier  string       `xml:"identifier"`
	References  []references `xml:"references"`
	Cpes        []cpe        `xml:"cpe"`
	Cvsses      []Cvss       `xml:"cvss"`
	Date        string       `xml:"date"`
	Issued      string       `xml:"issued"`
	Modified    string       `xml:"modified"`
}

type cpe struct {
	Version string `xml:"version,attr"` // cpe:/a:mysql:mysql
	Vendor  string `xml:"vendor,attr"`
	Product string `xml:"product,attr"`
	Value   string `xml:",chardata"`
}

type references struct {
	ID     string `xml:"id,attr"`
	Source string `xml:"source,attr"`
	Title  string `xml:"title,attr"`
	URL    string `xml:",chardata"`
}

// Cvss ... CVSS
type Cvss struct {
	Score    string `xml:"score,attr"`
	Severity string `xml:"severity,attr"`
	Vector   string `xml:"vector,attr"`
	Version  string `xml:"version,attr"`
}

// CertLink is a structure to temporarily store reference URLs.
type CertLink struct {
	Link string
}

// ListFetchedFeeds list fetched feeds information
func ListFetchedFeeds(driver db.DB) (metas []models.FeedMeta, err error) {
	lastMetas, err := driver.GetFetchedFeedMetas()
	if err != nil {
		return nil, fmt.Errorf("Failed to get Meta: %s", err)
	}
	if len(lastMetas) == 0 {
		log.Infof("No feeds found")
		return nil, nil
	}

	//TODO use meta.Year()
	uniqYears := map[int]bool{}
	for _, meta := range lastMetas {
		if strings.HasSuffix(meta.URL, "jvndb.rdf") ||
			strings.HasSuffix(meta.URL, "jvndb_new.rdf") {
			uniqYears[c.Latest] = true
		} else if strings.Contains(meta.URL, "jvndb") {
			yearstr := strings.TrimSuffix(strings.Split(meta.URL, "jvndb_")[1], ".rdf")
			y, err := strconv.Atoi(yearstr)
			if err != nil {
				return nil, fmt.Errorf("Unable conver to int: %s, err: %s",
					yearstr, err)
			}
			uniqYears[y] = true
		}
	}

	years := []int{}
	for y := range uniqYears {
		years = append(years, y)
	}

	if len(years) == 0 {
		return metas, nil
	}

	metas, err = FetchLatestFeedMeta(driver, years)
	if err != nil {
		return nil, err
	}
	return
}

// FetchLatestFeedMeta Fetch CVE meta information from JVN
func FetchLatestFeedMeta(driver db.DB, years []int) (metas []models.FeedMeta, err error) {
	reqs := []fetcher.FetchRequest{
		{
			URL: "https://jvndb.jvn.jp/ja/feed/checksum.txt",
		},
	}
	results, err := fetcher.FetchFeedFiles(reqs)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch. err: %s", err)
	}

	res := results[0]
	latestMetas := []Meta{}
	if err = json.Unmarshal(res.Body, &latestMetas); err != nil {
		return nil, fmt.Errorf(
			"Failed to unmarshal. url: %s, err: %s",
			res.URL, err)
	}

	urls := []string{}
	for _, year := range years {
		if year == -1 {
			urls = append(urls,
				fmt.Sprintf("https://jvndb.jvn.jp/ja/rss/jvndb.rdf"),
				fmt.Sprintf("https://jvndb.jvn.jp/ja/rss/jvndb_new.rdf"))
		} else {
			urls = append(urls,
				fmt.Sprintf("https://jvndb.jvn.jp/ja/rss/years/jvndb_%d.rdf", year))
		}
	}

	for _, url := range urls {
		meta, err := driver.GetFetchedFeedMeta(url)
		if err != nil {
			return nil, fmt.Errorf("Failed to get hash: %s, err: %s", url, err)
		}

		for _, latestMeta := range latestMetas {
			if latestMeta.URL == url {
				meta.URL = url
				meta.LatestHash = latestMeta.Hash
				meta.LatestLastModifiedDate = latestMeta.LastModified
				metas = append(metas, *meta)
			}
		}
	}
	return
}

// UpdateMeta updates meta table
func UpdateMeta(driver db.DB, metas []models.FeedMeta) error {
	for _, meta := range metas {
		meta.Hash = meta.LatestHash
		meta.LastModifiedDate = meta.LatestLastModifiedDate
		err := driver.UpsertFeedHash(meta)
		if err != nil {
			return fmt.Errorf("Failed to updte meta: %s, err: %s",
				meta.URL, err)
		}
	}
	return nil
}

// Fetch fetches vulnerability information from JVN and convert it to model
func Fetch(metas []models.FeedMeta) ([]Item, error) {
	reqs := []fetcher.FetchRequest{}
	for _, meta := range metas {
		reqs = append(reqs, fetcher.FetchRequest{
			URL: meta.URL,
		})
	}

	results, err := fetcher.FetchFeedFiles(reqs)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}

	items := []Item{}
	for _, res := range results {
		var rdf rdf
		if err = xml.Unmarshal([]byte(res.Body), &rdf); err != nil {
			return nil, fmt.Errorf(
				"Failed to unmarshal. url: %s, err: %s", res.URL, err)
		}
		items = append(items, rdf.Items...)
	}
	return items, nil

}

// FetchConvert fetches vulnerability information from JVN and convert it to model
func FetchConvert(metas []models.FeedMeta) (cves []models.CveDetail, err error) {
	items, err := Fetch(metas)
	if err != nil {
		return nil, err
	}
	return convert(items)
}

func convert(items []Item) (cves []models.CveDetail, err error) {
	reqChan := make(chan Item, len(items))
	resChan := make(chan []models.CveDetail, len(items))
	errChan := make(chan error)
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, item := range items {
			reqChan <- item
		}
	}()

	concurrency := runtime.NumCPU() + 2
	tasks := util.GenWorkers(concurrency)
	for range items {
		tasks <- func() {
			req := <-reqChan
			cves, err := convertToModel(&req)
			if err != nil {
				errChan <- err
				return
			}
			resChan <- cves
		}
	}

	errs := []error{}
	timeout := time.After(10 * 60 * time.Second)
	for range items {
		select {
		case res := <-resChan:
			cves = append(cves, res...)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, fmt.Errorf("Timeout Fetching")
		}
	}
	if 0 < len(errs) {
		return nil, fmt.Errorf("%s", errs)
	}
	return cves, nil
}

func makeJvnURLs(years []int) (urls []string) {
	latestFeeds := []string{
		"http://jvndb.jvn.jp/ja/rss/jvndb_new.rdf",
		"http://jvndb.jvn.jp/ja/rss/jvndb.rdf",
	}

	if len(years) == 0 {
		return latestFeeds
	}

	urlFormat := "http://jvndb.jvn.jp/ja/rss/years/jvndb_%d.rdf"
	for _, year := range years {
		urls = append(urls, fmt.Sprintf(urlFormat, year))

		thisYear := time.Now().Year()
		if year == thisYear {
			urls = append(urls, latestFeeds...)
		}
	}
	return
}

// ConvertJvn converts Jvn structure(got from JVN) to model structure.
func convertToModel(item *Item) (cves []models.CveDetail, err error) {
	var cvss2, cvss3 Cvss
	for _, cvss := range item.Cvsses {
		switch cvss.Version {
		case "2.0":
			cvss2 = cvss
		case "3.0":
			cvss3 = cvss
		}
	}

	//  References
	refs, links := []models.Reference{}, []CertLink{}
	for _, r := range item.References {
		ref := models.Reference{
			Source: r.Source,
			Link:   r.URL,
		}
		refs = append(refs, ref)

		if ref.Source == "JPCERT-AT" {
			links = append(links, CertLink{
				Link: r.URL,
			})
		}
	}

	certs, err := collectCertLinks(links)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to collect links. err: %s", err)
	}

	// Cpes
	cpes := []models.Cpe{}
	for _, c := range item.Cpes {
		cpeBase, err := fetcher.ParseCpeURI(c.Value)
		if err != nil {
			return nil, err
		}
		cpes = append(cpes, models.Cpe{
			CpeBase: *cpeBase,
		})
	}

	publish, err := parseJvnTime(item.Issued)
	if err != nil {
		return nil, err
	}
	modified, err := parseJvnTime(item.Modified)
	if err != nil {
		return nil, err
	}

	cveIDs := getCveIDs(*item)
	if len(cveIDs) == 0 {
		log.Debugf("No CveIDs in references. JvnID: %s, Link: %s",
			item.Identifier, item.Link)
		// ignore this item
		return nil, nil
	}

	for _, cveID := range cveIDs {
		v2elems := parseCvss2VectorStr(cvss2.Vector)
		v3elems := parseCvss3VectorStr(cvss3.Vector)
		cve := models.CveDetail{
			CveID: cveID,
			Jvn: &models.Jvn{
				CveID:   cveID,
				Title:   strings.Replace(item.Title, "\r", "", -1),
				Summary: strings.Replace(item.Description, "\r", "", -1),
				JvnLink: item.Link,
				JvnID:   item.Identifier,

				Cvss2: models.Cvss2{
					BaseScore:             fetcher.StringToFloat(cvss2.Score),
					Severity:              cvss2.Severity,
					VectorString:          cvss2.Vector,
					AccessVector:          v2elems[0],
					AccessComplexity:      v2elems[1],
					Authentication:        v2elems[2],
					ConfidentialityImpact: v2elems[3],
					IntegrityImpact:       v2elems[4],
					AvailabilityImpact:    v2elems[5],
				},

				Cvss3: models.Cvss3{
					BaseScore:             fetcher.StringToFloat(cvss3.Score),
					BaseSeverity:          cvss3.Severity,
					VectorString:          cvss3.Vector,
					AttackVector:          v3elems[0],
					AttackComplexity:      v3elems[1],
					PrivilegesRequired:    v3elems[2],
					UserInteraction:       v3elems[3],
					Scope:                 v3elems[4],
					ConfidentialityImpact: v3elems[5],
					IntegrityImpact:       v3elems[6],
					AvailabilityImpact:    v3elems[7],
				},

				References: refs,
				Cpes:       cpes,
				Certs:      certs,

				PublishedDate:    publish,
				LastModifiedDate: modified,
			},
		}
		cves = append(cves, cve)
	}
	return
}

func collectCertLinks(links []CertLink) (certs []models.Cert, err error) {
	var proxyURL *url.URL
	httpCilent := &http.Client{}
	if c.Conf.HTTPProxy != "" {
		if proxyURL, err = url.Parse(c.Conf.HTTPProxy); err != nil {
			return nil, fmt.Errorf("failed to parse proxy url: %s", err)
		}
		httpCilent = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	}

	reqChan := make(chan string, len(links))
	resChan := make(chan models.Cert, len(links))
	errChan := make(chan error, len(links))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, ref := range links {
			reqChan <- ref.Link
		}
	}()

	concurrency := runtime.NumCPU()
	tasks := util.GenWorkers(concurrency)
	for _, l := range links {
		tasks <- func() {
			url := <-reqChan
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Debugf("Failed to get %s: err: %s", url, err)
				errChan <- err
				return
			}

			res, err := httpCilent.Do(req)
			if err != nil {
				log.Debugf("Failed to get %s: err: %s", url, err)
				errChan <- err
				return
			}
			defer res.Body.Close()

			doc, err := goquery.NewDocumentFromReader(res.Body)
			if err != nil {
				log.Debugf("Failed to get %s: err: %s", url, err)
				errChan <- err
				return
			}
			title := doc.Find("title").Text()
			resChan <- models.Cert{
				Title: title,
				Link:  l.Link,
			}
		}
	}

	timeout := time.After(10 * 60 * time.Second)
	for range links {
		select {
		case res := <-resChan:
			certs = append(certs, res)
		case <-errChan:
		case <-timeout:
			return nil, fmt.Errorf("Timeout Fetching")
		}
	}
	return certs, nil
}

var cvss2VectorMap = map[string]string{
	"AV:L": "LOCAL",
	"AV:A": "ADJACENT_NETWORK",
	"AV:N": "NETWORK",

	"AC:L": "LOW",
	"AC:M": "MEDIUM",
	"AC:H": "HIGH",

	"Au:M": "MULTIPLE",
	"Au:S": "SINGLE",
	"Au:N": "NONE",

	"C:N": "NONE",
	"C:P": "PARTIAL",
	"C:C": "COMPLETE",

	"I:N": "NONE",
	"I:P": "PARTIAL",
	"I:C": "COMPLETE",

	"A:N": "NONE",
	"A:P": "PARTIAL",
	"A:C": "COMPLETE",
}

func parseCvss2VectorStr(str string) (elems []string) {
	if len(str) == 0 {
		return []string{"", "", "", "", "", ""}
	}
	for _, s := range strings.Split(str, "/") {
		elems = append(elems, cvss2VectorMap[s])
	}
	return
}

var cvss3VectorMap = map[string]string{
	"AV:N": "NETWORK",
	"AV:A": "ADJACENT_NETWORK",
	"AV:L": "LOCAL",
	"AV:P": "PHYSICAL",

	"AC:L": "LOW",
	"AC:H": "HIGH",

	"PR:N": "NONE",
	"PR:L": "LOW",
	"PR:H": "HIGH",

	"UI:N": "NONE",
	"UI:R": "REQUIRED",

	"S:U": "UNCHANGED",
	"S:C": "CHANGED",

	"C:N": "NONE",
	"C:L": "LOW",
	"C:H": "HIGH",

	"I:N": "NONE",
	"I:L": "LOW",
	"I:H": "HIGH",

	"A:N": "NONE",
	"A:L": "LOW",
	"A:H": "HIGH",
}

func parseCvss3VectorStr(str string) (elems []string) {
	if len(str) == 0 {
		return []string{"", "", "", "", "", "", "", ""}
	}
	str = strings.TrimPrefix(str, "CVSS:3.0/")
	for _, s := range strings.Split(str, "/") {
		elems = append(elems, cvss3VectorMap[s])
	}
	return
}

// convert string time to time.Time
// JVN : "2016-01-26T13:36:23+09:00",
// NVD : "2016-01-20T21:59:01.313-05:00",
func parseJvnTime(strtime string) (t time.Time, err error) {
	layout := "2006-01-02T15:04-07:00"
	t, err = time.Parse(layout, strtime)
	if err != nil {
		return t, fmt.Errorf("Failed to parse time, time: %s, err: %s",
			strtime, err)
	}
	return
}

func getCveIDs(item Item) []string {
	cveIDsMap := map[string]bool{}
	for _, ref := range item.References {
		switch ref.Source {
		case "NVD", "CVE":
			cveIDsMap[ref.ID] = true
		}
	}
	var cveIDs []string
	for cveID := range cveIDsMap {
		cveIDs = append(cveIDs, cveID)
	}
	return cveIDs
}
