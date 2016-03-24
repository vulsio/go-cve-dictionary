package commands

import (
	"flag"
	"os"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/go-cve-dictionary/config"
	db "github.com/kotakanbe/go-cve-dictionary/db"
	log "github.com/kotakanbe/go-cve-dictionary/log"
	"github.com/kotakanbe/go-cve-dictionary/nvd"
	"golang.org/x/net/context"
)

// FetchNvdCmd is Subcommand for fetch Nvd information.
type FetchNvdCmd struct {
	debug    bool
	debugSQL bool

	dbpath string
	last2Y bool
}

// Name return subcommand name
func (*FetchNvdCmd) Name() string { return "fetchnvd" }

// Synopsis return synopsis
func (*FetchNvdCmd) Synopsis() string { return "Fetch Vulnerability dictionary from NVD" }

// Usage return usage
func (*FetchNvdCmd) Usage() string {
	//TODO
	return `fetchnvd:
	fetchnvd
		[-last2y]
		[-dbpath=/path/to/cve.sqlite3]
		[-debug]
		[-debug-sql]

`
}

// SetFlags set flag
func (p *FetchNvdCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.debug, "debug", false,
		"debug mode")
	f.BoolVar(&p.debugSQL, "debug-sql", false,
		"SQL debug mode")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.dbpath, "dbpath", pwd+"/cve.sqlite3", "/path/to/sqlite3")

	f.BoolVar(&p.last2Y, "last2y", false,
		"Refresh NVD data in the last two years.")
}

// Execute execute
func (p *FetchNvdCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	c.Conf.Debug = p.debug
	c.Conf.DebugSQL = p.debugSQL

	if c.Conf.Debug {
		log.SetDebug()
	}

	c.Conf.DBPath = p.dbpath
	c.Conf.FetchNvdLast2Y = p.last2Y

	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	entries, err := nvd.FetchFiles()
	if err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	log.Infof("Fetched %d CVEs", len(entries))

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

	if err := db.InsertNvd(entries); err != nil {
		log.Errorf("Failed to inert. dbpath: %s, err: %s",
			c.Conf.DBPath, err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
