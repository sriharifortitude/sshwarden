// Command sshwarden audits an sshd_config the way sshd reads it.
package main

import (
	"os"

	"github.com/sriharifortitude/sshwarden/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
