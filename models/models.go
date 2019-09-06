package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jinzhu/gorm"
)

// FeedMeta has meta information about fetched feeds
type FeedMeta struct {
	gorm.Model `json:"-" xml:"-"`

	URL              string
	Hash             string
	LastModifiedDate string

	LatestHash             string `json:"-" gorm:"-"`
	LatestLastModifiedDate string `json:"-" gorm:"-"`
}

// UpToDate checks whether last fetched feed is up to date
func (f FeedMeta) UpToDate() bool {
	return !f.Newly() && f.Hash == f.LatestHash
}

// OutDated checks whether last fetched feed is out dated
func (f FeedMeta) OutDated() bool {
	return !f.Newly() && f.Hash != f.LatestHash
}

// Newly checks whether not fetched yet
func (f FeedMeta) Newly() bool {
	return f.Hash == ""
}

// StatusForStdout returns a status of fetched feed
func (f FeedMeta) StatusForStdout() string {
	if f.Newly() {
		return "Newly"
	} else if f.OutDated() {
		red := color.New(color.FgRed, color.Bold).SprintFunc()
		return red("Out-Dated")
	} else if f.UpToDate() {
		return color.GreenString("Up-to-Date")
	}
	return "Unknown"
}

const (
	nvdxml  = "NVD(XML)"
	nvdjson = "NVD(JSON)"
	jvn     = "JVN"
)

func (f FeedMeta) color(str string) string {
	if f.OutDated() {
		return color.WhiteString(str)
	} else if f.UpToDate() {
		return color.HiBlackString(str)
	}
	return str
}

func (f FeedMeta) source() string {
	if strings.Contains(f.URL, "nvdcve-2.0-") {
		return nvdxml
	} else if strings.Contains(f.URL, "nvdcve-1.0-") {
		return nvdjson
	} else if strings.Contains(f.URL, "jvndb") {
		return jvn
	}
	return "Unknown"
}

// FetchOption returns a option of fetch subcommand for list subcommand
func (f FeedMeta) FetchOption() string {
	switch f.source() {
	case nvdxml:
		return "fetchnvd -xml"
	case nvdjson:
		return "fetchnvd"
	case jvn:
		return "fetchjvn"
	default:
		return ""
	}
}

// Year returns year, whether xml or not of the feed
func (f FeedMeta) Year() (year string, xml bool, err error) {
	switch f.source() {
	case nvdxml:
		return strings.TrimSuffix(
			strings.Split(f.URL, "nvdcve-2.0-")[1], ".xml.gz"), true, nil
	case nvdjson:
		return strings.TrimSuffix(
			strings.Split(f.URL, "nvdcve-1.0-")[1], ".json.gz"), false, nil
	case jvn:
		if strings.HasSuffix(f.URL, "jvndb.rdf") {
			return "modified", true, nil
		} else if strings.HasSuffix(f.URL, "jvndb_new.rdf") {
			return "recent", true, nil
		} else {
			return strings.TrimSuffix(
				strings.Split(f.URL, "jvndb_")[1], ".rdf"), true, nil
		}
	default:
		return "", false, fmt.Errorf("Failed to parse URL: %s", f.URL)
	}
}

func (f FeedMeta) modifiedTimesToStrs() (fetched, latest string) {
	switch f.source() {
	case nvdxml, nvdjson:
		layout := "2006-01-02T15:04:05-07:00"
		last, _ := time.Parse(layout, f.LastModifiedDate)
		latest, _ := time.Parse(layout, f.LatestLastModifiedDate)
		return last.Format("2006/1/2-15:04"),
			latest.Format("2006/1/2-15:04")
	case jvn:
		layout := "2006/01/02 15:04:05"
		last, _ := time.Parse(layout, f.LastModifiedDate)
		latest, _ := time.Parse(layout, f.LatestLastModifiedDate)
		return last.Format("2006/1/2-15:04"),
			latest.Format("2006/1/2-15:04")
	default:
		return "Unknown", "Unknown"
	}
}

// ToTableWriterRow generate data for table writer
func (f FeedMeta) ToTableWriterRow() []string {
	y, _, _ := f.Year()
	fetched, latest := f.modifiedTimesToStrs()
	return []string{
		f.color(f.source()),
		f.color(y),
		f.StatusForStdout(),
		f.color(fetched),
		f.color(latest),
	}
}

// CveDetail is a parent of Jnv/Nvd model
type CveDetail struct {
	gorm.Model `json:"-" xml:"-"`

	CveID   string
	NvdXML  *NvdXML  `json:",omitempty"`
	NvdJSON *NvdJSON `json:",omitempty"`
	Jvn     *Jvn     `json:",omitempty"`
}

// NvdXML is a model of NVD
type NvdXML struct {
	gorm.Model  `json:"-" xml:"-"`
	CveDetailID uint `json:"-" xml:"-"`

	CveID   string
	Summary string `sql:"type:text"`

	Cvss2      Cvss2
	Cpes       []Cpe `json:",omitempty"`
	Cwes       []Cwe
	References []Reference

	PublishedDate    time.Time
	LastModifiedDate time.Time
}

// NvdJSON is a struct of NVD JSON
// https://scap.nist.gov/schema/nvd/feed/0.1/nvd_cve_feed_json_0.1_beta.schema
type NvdJSON struct {
	gorm.Model  `json:"-" xml:"-"`
	CveDetailID uint `json:"-" xml:"-"`

	// DataType    string
	// DataFormat  string
	// DataVersion string

	CveID        string
	Descriptions []Description

	Cvss2      Cvss2Extra
	Cvss3      Cvss3
	Cwes       []Cwe
	Cpes       []Cpe
	Affects    []Affect
	References []Reference

	// Assigner         string
	Certs            []Cert
	PublishedDate    time.Time
	LastModifiedDate time.Time
}

// Jvn is a model of JVN
type Jvn struct {
	gorm.Model  `json:"-" xml:"-"`
	CveDetailID uint `json:"-" xml:"-"`

	CveID   string
	Title   string
	Summary string `sql:"type:text"`
	JvnLink string
	JvnID   string

	Cvss2      Cvss2
	Cvss3      Cvss3
	Cpes       []Cpe `json:",omitempty"`
	References []Reference

	Certs            []Cert
	PublishedDate    time.Time
	LastModifiedDate time.Time
}

// Cwe has CweID
type Cwe struct {
	gorm.Model `json:"-" xml:"-"`
	NvdXMLID   uint `json:"-" xml:"-"`
	NvdJSONID  uint `json:"-" xml:"-"`
	JvnID      uint `json:"-" xml:"-"`

	CweID string
}

// Cpe is Child model of Jvn/Nvd.
// see https://www.ipa.go.jp/security/vuln/CPE.html
// In NVD JSON,
// configurations>nodes>cpe>valunerable: true
type Cpe struct {
	gorm.Model `json:"-" xml:"-"`
	JvnID      uint `json:"-" xml:"-"`
	NvdXMLID   uint `json:"-" xml:"-"`
	NvdJSONID  uint `json:"-" xml:"-"`

	CpeBase
	EnvCpes []EnvCpe
}

// EnvCpe is a Environmental CPE
// Only NVD JSON has this information.
// configurations>nodes>cpe>valunerable: false
type EnvCpe struct {
	gorm.Model `json:"-" xml:"-"`
	CpeID      uint `json:"-" xml:"-"`

	CpeBase
}

// CpeBase has common args of Cpe and EnvCpe
type CpeBase struct {
	URI             string
	FormattedString string
	WellFormedName  string `sql:"type:text"`
	CpeWFN

	VersionStartExcluding string
	VersionStartIncluding string
	VersionEndExcluding   string
	VersionEndIncluding   string
}

// CpeWFN has CPE Well Formed name informaiton
type CpeWFN struct {
	Part            string
	Vendor          string
	Product         string
	Version         string
	Update          string
	Edition         string
	Language        string
	SoftwareEdition string
	TargetSW        string
	TargetHW        string
	Other           string
}

// Reference is Child model of Jvn/Nvd.
// It holds reference information about the CVE.
type Reference struct {
	gorm.Model `json:"-" xml:"-"`
	NvdXMLID   uint `json:"-" xml:"-"`
	NvdJSONID  uint `json:"-" xml:"-"`
	JvnID      uint `json:"-" xml:"-"`

	Source string
	Link   string `sql:"type:text"`
}

// Cert is Child model of Jvn/Nvd.
// It holds CERT alerts.
type Cert struct {
	gorm.Model `json:"-" xml:"-"`
	JvnID      uint `json:"-" xml:"-"`
	NvdJSONID  uint `json:"-" xml:"-"`

	Title string `sql:"type:text"`
	Link  string `sql:"type:text"`
}

// Affect has vendor/product/version info in NVD JSON
type Affect struct {
	gorm.Model `json:"-" xml:"-"`
	NvdJSONID  uint `json:"-" xml:"-"`

	Vendor  string
	Product string
	Version string
}

// Cvss3 has CVSS Version 3 info
// NVD JSON and JVN has CVSS3 info
type Cvss3 struct {
	gorm.Model `json:"-" xml:"-"`
	NvdJSONID  uint `json:"-" xml:"-"`
	JVNID      uint `json:"-" xml:"-"`

	VectorString string

	AttackVector          string
	AttackComplexity      string
	PrivilegesRequired    string
	UserInteraction       string
	Scope                 string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string

	BaseScore           float64
	BaseSeverity        string
	ExploitabilityScore float64
	ImpactScore         float64
}

// Cvss2 has CVSS Version 2 info
type Cvss2 struct {
	gorm.Model `json:"-" xml:"-"`
	NvdXMLID   uint `json:"-" xml:"-"`
	JvnID      uint `json:"-" xml:"-"`

	VectorString          string
	AccessVector          string
	AccessComplexity      string
	Authentication        string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
	BaseScore             float64

	// NVD JSON and JVN has severity (Not in NVD XML)
	Severity string
}

// Cvss2Extra has extra CVSS V2 info
type Cvss2Extra struct {
	NvdJSONID uint `json:"-" xml:"-"`

	Cvss2
	ExploitabilityScore     float64
	ImpactScore             float64
	ObtainAllPrivilege      bool
	ObtainUserPrivilege     bool
	ObtainOtherPrivilege    bool
	UserInteractionRequired bool
}

// Description has description of the CVE
type Description struct {
	gorm.Model `json:"-" xml:"-"`
	NvdJSONID  uint `json:"-" xml:"-"`

	Lang  string
	Value string `sql:"type:text"`
}
