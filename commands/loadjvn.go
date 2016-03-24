package commands

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/google/subcommands"
	c "github.com/kotakanbe/go-cve-dictionary/config"
	"github.com/kotakanbe/go-cve-dictionary/db"
	"github.com/kotakanbe/go-cve-dictionary/jvn"
	"golang.org/x/net/context"
)

// LoadJvnCmd is Subcommand for load JVN information from local JSON file.
type LoadJvnCmd struct {
	debug    bool
	debugSQL bool

	dbpath   string
	loadFrom string
}

// Name return subcommand name
func (*LoadJvnCmd) Name() string { return "loadjvn" }

// Synopsis return synopsis
func (*LoadJvnCmd) Synopsis() string { return "Start CVE dictionary HTTP server" }

// Usage return usage
func (*LoadJvnCmd) Usage() string {
	return `load:
	load
		[-load-from=$PWD/cve.json]
		[-dbpath=$PWD/cve.sqlite3]
		[-debug]
		[-debug-sql]

`
}

// SetFlags set flag
func (p *LoadJvnCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.debug, "debug", false,
		"debug mode")
	f.BoolVar(&p.debugSQL, "debug-sql", false,
		"SQL debug mode")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.dbpath, "dbpath", pwd+"/cve.sqlite3", "/path/to/sqlite3")

	f.StringVar(&p.loadFrom, "load-from", pwd+"/cve.json", "/path/to/cve.json")
}

// Execute execute
func (p *LoadJvnCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	c.Conf.Debug = p.debug
	c.Conf.DebugSQL = p.debugSQL

	if c.Conf.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	c.Conf.DBPath = p.dbpath
	c.Conf.DumpPath = p.loadFrom

	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	if _, err := os.Stat(c.Conf.DumpPath); os.IsNotExist(err) {
		log.Errorf("JSON file Not found. dump-path: %s", c.Conf.DumpPath)
		return subcommands.ExitUsageError
	}

	log.Infof("Loading CVE Information from %s.", c.Conf.DumpPath)
	raw, err := ioutil.ReadFile(c.Conf.DumpPath)
	if err != nil {
		log.Fatalf("Failed to read JSON. path: %s, err: %s", c.Conf.DumpPath, err)
		return subcommands.ExitFailure
	}

	var items []jvn.Item
	if err := json.Unmarshal(raw, &items); err != nil {
		log.Fatalf("Failed to unmarshall JSON. pash: %s, err: %s", c.Conf.DumpPath, err)
		return subcommands.ExitFailure
	}
	log.Infof("Loaded %d CVEs", len(items))

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
