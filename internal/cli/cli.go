// Package cli is sshwarden's command line.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sriharifortitude/sshwarden/internal/rules"
	"github.com/sriharifortitude/sshwarden/internal/sshd"
)

// Version is the release.
var Version = "0.1.0"

const usage = `sshwarden: audit an sshd_config the way sshd reads it.

usage: sshwarden [flags] FILE

FILE is an sshd_config (its Include lines are followed), the output of "sshd -T", or - for
standard input (Include is not followed there).

flags:
  --root DIR             prefix for absolute Include paths, to audit a copy of another machine's /etc
  --defaults FILE        take default values from "sshd -T -f /dev/null" output instead of OpenSSH 9.6's
  --openssh-version V    the server's OpenSSH version, such as 9.2; enables the Terrapin check
  --fail-on LEVEL        exit 1 at or above: critical, high, medium (default), low, info, none
  --effective            print the effective global settings in "sshd -T" form, with where each came from
  --json                 machine-readable findings
  --version

exit status: 0 nothing at or above --fail-on, 1 at least one finding is, 2 usage error or unreadable file
`

// Run executes the command and returns the exit status.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sshwarden", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", "", "")
	defaultsFile := fs.String("defaults", "", "")
	version := fs.String("openssh-version", "", "")
	failOn := fs.String("fail-on", "medium", "")
	effective := fs.Bool("effective", false, "")
	asJSON := fs.Bool("json", false, "")
	showVersion := fs.Bool("version", false, "")
	help := fs.Bool("help", false, "")

	var paths []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			fmt.Fprintf(stderr, "sshwarden: %v\n\n%s", err, usage)
			return 2
		}
		rest = fs.Args()
		if len(rest) > 0 {
			paths = append(paths, rest[0])
			rest = rest[1:]
		}
	}
	switch {
	case *help:
		fmt.Fprint(stdout, usage)
		return 0
	case *showVersion:
		fmt.Fprintf(stdout, "sshwarden %s\n", Version)
		return 0
	case len(paths) != 1:
		fmt.Fprint(stderr, usage)
		return 2
	case *failOn != "none" && rules.Rank(*failOn) == len(rules.Severities):
		fmt.Fprintf(stderr, "sshwarden: --fail-on must be critical, high, medium, low, info or none, not %q\n", *failOn)
		return 2
	}

	defaults := sshd.BuiltinDefaults()
	if *defaultsFile != "" {
		data, err := os.ReadFile(*defaultsFile)
		if err != nil {
			fmt.Fprintf(stderr, "sshwarden: %v\n", err)
			return 2
		}
		if defaults.FromDump(data) == 0 {
			fmt.Fprintf(stderr, "sshwarden: %s has no sshd -T values\n", *defaultsFile)
			return 2
		}
	}

	var cfg *sshd.Config
	if paths[0] == "-" {
		data, err := io.ReadAll(io.LimitReader(stdin, 1<<20+1))
		if err != nil || len(data) > 1<<20 {
			fmt.Fprintln(stderr, "sshwarden: standard input is unreadable or over 1 MiB")
			return 2
		}
		cfg = sshd.Parse("(stdin)", data)
	} else {
		var err error
		cfg, err = sshd.Load(paths[0], sshd.Options{Root: *root})
		if err != nil {
			fmt.Fprintf(stderr, "sshwarden: %v\n", err)
			return 2
		}
	}
	eff := sshd.Resolve(cfg, defaults)

	if *effective {
		fmt.Fprint(stdout, Effective(eff))
		return 0
	}

	findings := rules.Check(cfg, eff, rules.Options{OpenSSHVersion: *version})
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if findings == nil {
			findings = []rules.Finding{}
		}
		if err := enc.Encode(map[string]any{"files": cfg.Files, "findings": findings}); err != nil {
			return 2
		}
	} else {
		fmt.Fprint(stdout, Render(cfg, findings))
	}
	for _, f := range findings {
		if *failOn != "none" && rules.Rank(f.Severity) <= rules.Rank(*failOn) {
			return 1
		}
	}
	return 0
}

// Render formats findings as text.
func Render(cfg *sshd.Config, findings []rules.Finding) string {
	var b strings.Builder
	for _, f := range findings {
		where := "(default)"
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		scope := ""
		if f.Scope != "global" {
			scope = " [" + f.Scope + "]"
		}
		fmt.Fprintf(&b, "%s  %s %-8s %s%s\n", where, f.ID, f.Severity, f.Message, scope)
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range rules.Severities {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	summary := "no findings"
	if len(parts) > 0 {
		summary = strings.Join(parts, ", ")
	}
	fmt.Fprintf(&b, "%d file(s) read; %s\n", len(cfg.Files), summary)
	return b.String()
}

// effectiveKeys are printed by --effective, in sshd -T's spelling.
var effectiveKeys = []string{
	"permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication",
	"permitemptypasswords", "authenticationmethods", "usepam", "x11forwarding", "allowtcpforwarding",
	"allowagentforwarding", "permittunnel", "gatewayports", "permituserenvironment", "strictmodes",
	"maxauthtries", "logingracetime", "hostbasedauthentication", "ignorerhosts", "loglevel",
	"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "pubkeyacceptedalgorithms",
}

// Effective prints the global settings sshd would use, one per line as sshd -T does, with
// the file and line each came from.
func Effective(e *sshd.Effective) string {
	var b strings.Builder
	keys := append([]string(nil), effectiveKeys...)
	sort.Strings(keys)
	for _, k := range keys {
		var value string
		var from *sshd.Directive
		switch k {
		case "ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "pubkeyacceptedalgorithms":
			var list []string
			list, from = e.Algorithms(e.Global, k)
			value = strings.Join(list, ",")
		default:
			value, from = e.Get(e.Global, k)
			value = dumpForm(k, value)
		}
		origin := "default"
		if from != nil {
			origin = fmt.Sprintf("%s:%d", from.File, from.Line)
		}
		fmt.Fprintf(&b, "%s %s\t# %s\n", k, value, origin)
	}
	return b.String()
}

// dumpForm writes a value the way sshd -T prints it.
func dumpForm(k, v string) string {
	switch k {
	case "permitrootlogin":
		if strings.EqualFold(v, "prohibit-password") {
			return "without-password"
		}
	case "loglevel":
		return strings.ToUpper(v)
	case "logingracetime":
		return fmt.Sprint(rules.Seconds(v))
	}
	return strings.ToLower(v)
}
