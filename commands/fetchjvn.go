package commands

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/go-cve-dictionary/config"
	db "github.com/kotakanbe/go-cve-dictionary/db"
	"github.com/kotakanbe/go-cve-dictionary/jvn"
	log "github.com/kotakanbe/go-cve-dictionary/log"
	"golang.org/x/net/context"
)

// FetchJvnCmd is Subcommand for fetch JVN information.
type FetchJvnCmd struct {
	debug    bool
	debugSQL bool

	dbpath   string
	dumpPath string

	week  bool
	month bool
	//  year         bool
	entirePeriod bool
}

// Name return subcommand name
func (*FetchJvnCmd) Name() string { return "fetchjvn" }

// Synopsis return synopsis
func (*FetchJvnCmd) Synopsis() string { return "Fetch Vulnerability dictionary from JVN" }

// Usage return usage
func (*FetchJvnCmd) Usage() string {
	return `fetchjvn:
	fetchjvn
		[-dump-path=/path/to/cve.json]
		[-dpath=$PWD/cve.sqlite3]
		[-week]
		[-month]
		[-entire]
		[-debug]
		[-debug-sql]

`
}

// SetFlags set flag
func (p *FetchJvnCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.debug, "debug", false,
		"debug mode")
	f.BoolVar(&p.debugSQL, "debug-sql", false,
		"SQL debug mode")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.dbpath, "dbpath", pwd+"/cve.sqlite3", "/path/to/sqlite3")

	f.StringVar(&p.dumpPath, "dump-path", "",
		"/path/to/cve.json (default: empty(nodump))")

	f.BoolVar(&p.week, "week", false,
		"Fetch data in the last week")
	f.BoolVar(&p.month, "month", false,
		"Fetch data in the last month")
	//  f.BoolVar(&p.year, "lastY", false,
	//      "Fetch data in the last year. (default: false)")
	f.BoolVar(&p.entirePeriod, "entire", false,
		"Fetch data for entire period.(This operation is time-consuming) (default: false)")
}

// Execute execute
func (p *FetchJvnCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	c.Conf.Debug = p.debug
	c.Conf.DebugSQL = p.debugSQL

	if c.Conf.Debug {
		log.SetDebug()
	}

	c.Conf.DBPath = p.dbpath
	c.Conf.DumpPath = p.dumpPath

	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	dump := false
	if 0 < len(p.dumpPath) {
		dump = true
		if _, err := os.Stat(p.dumpPath); err == nil {
			log.Errorf("Already exists. dumppath: %s", p.dumpPath)
			return subcommands.ExitUsageError
		}
	}

	if !(p.week || p.month || p.entirePeriod) {
		log.Errorf("Specify in either [--week|--month|--entire].")
		return subcommands.ExitUsageError
	}
	switch {
	case p.week:
		c.Conf.FetchJvnPeriodChar = "w"
	case p.month:
		c.Conf.FetchJvnPeriodChar = "m"
	case p.entirePeriod:
		c.Conf.FetchJvnPeriodChar = "n"
	}

	log.Infof("Fetching CVE information from JVN.")
	items, err := jvn.FetchCVEs()
	if err != nil {
		return subcommands.ExitFailure
	}
	log.Infof("Fetched %d CVEs", len(items))

	if dump {
		log.Infof("Dumping JSON to %s", c.Conf.DumpPath)
		b, err := json.Marshal(items)
		if err != nil {
			log.Errorf("Failed to Marshall. err: %s", err)
			return subcommands.ExitFailure
		}
		if err := ioutil.WriteFile(c.Conf.DumpPath, b, 0644); err != nil {
			log.Errorf("Failed to dump. dump: %s, err: %s", c.Conf.DumpPath, err)
			return subcommands.ExitFailure
		}
	}

	log.Infof("Opening DB. datafile: %s", c.Conf.DBPath)
	if err := db.OpenDB(); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	log.Info("Migrating DB")
	if err := db.MigrateDB(); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	if err := db.InsertJvn(items); err != nil {
		log.Fatalf("Failed to inert. dbpath: %s, err: %s", c.Conf.DBPath, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
