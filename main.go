package main

import (
	"flag"
	"os"

	"golang.org/x/net/context"

	"github.com/google/subcommands"
	"github.com/kotakanbe/go-cve-dictionary/commands"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&commands.ServerCmd{}, "server")
	subcommands.Register(&commands.FetchJvnCmd{}, "fetchjvn")
	subcommands.Register(&commands.LoadJvnCmd{}, "loadjvn")
	subcommands.Register(&commands.FetchNvdCmd{}, "fetchnvd")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
