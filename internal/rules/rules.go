// Package rules judges an effective sshd configuration.
package rules

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/sriharifortitude/sshwarden/internal/sshd"
)

// Severities, most serious first.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// Rank orders severities: critical is 0.
func Rank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return len(Severities)
}

// Finding is one problem, located at the line that causes it (or at no line, for a default).
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	// Scope is "global" or the Match criteria the finding applies to.
	Scope   string `json:"scope"`
	Message string `json:"message"`
}

// Options carry facts the configuration file cannot tell.
type Options struct {
	// OpenSSHVersion such as "9.4"; when given and older than 9.6, the Terrapin check runs.
	OpenSSHVersion string
}

type check struct {
	f   func(v view) []Finding
	all bool // also run in Match scopes
}

type view struct {
	e     *sshd.Effective
	scope *sshd.Scope
	opt   Options
}

func (v view) get(k string) (string, *sshd.Directive) { return v.e.Get(v.scope, k) }

func (v view) find(id, sev string, from *sshd.Directive, format string, args ...any) Finding {
	f := Finding{ID: id, Severity: sev, Scope: "global", Message: fmt.Sprintf(format, args...)}
	if from != nil {
		f.File, f.Line = from.File, from.Line
	}
	if v.scope != nil && v.scope.Match != nil {
		f.Scope = "Match " + v.scope.Match.Criteria
	}
	return f
}

func is(value string, options ...string) bool {
	value = strings.ToLower(value)
	for _, o := range options {
		if value == o {
			return true
		}
	}
	return false
}

func setOrDefault(d *sshd.Directive, k string) string {
	if d == nil {
		return sshd.DisplayName(k) + " is not set, and the default is"
	}
	return sshd.DisplayName(k) + " is"
}

var checks = []check{
	{all: true, f: func(v view) []Finding {
		val, d := v.get("permitrootlogin")
		if is(val, "yes") {
			return []Finding{v.find("SSH001", "high", d, "PermitRootLogin yes lets root log in by any enabled method, passwords included; use prohibit-password, forced-commands-only or no")}
		}
		return nil
	}},
	{all: true, f: func(v view) []Finding {
		methods, _ := v.get("authenticationmethods")
		if !is(methods, "any") && !strings.Contains(methods, "password") && !strings.Contains(methods, "keyboard-interactive") {
			return nil // AuthenticationMethods rules out passwords whatever else says
		}
		var out []Finding
		if val, d := v.get("passwordauthentication"); is(val, "yes") {
			out = append(out, v.find("SSH002", "medium", d, "%s yes: passwords can be guessed, phished and reused; prefer keys or certificates",
				setOrDefault(d, "passwordauthentication")))
		}
		kbd, kd := v.get("kbdinteractiveauthentication")
		pam, _ := v.get("usepam")
		if is(kbd, "yes") && is(pam, "yes") {
			out = append(out, v.find("SSH002", "medium", kd,
				"%s yes with UsePAM yes: PAM will ask for a password, so turning PasswordAuthentication off is not enough",
				setOrDefault(kd, "kbdinteractiveauthentication")))
		}
		return out
	}},
	{all: true, f: func(v view) []Finding {
		if val, d := v.get("permitemptypasswords"); is(val, "yes") {
			return []Finding{v.find("SSH003", "critical", d, "PermitEmptyPasswords yes lets accounts without a password log in")}
		}
		return nil
	}},
	{f: func(v view) []Finding { return weakAlgorithms(v, "ciphers", "SSH004", weakCiphers) }},
	{f: func(v view) []Finding { return weakAlgorithms(v, "macs", "SSH005", weakMACs) }},
	{f: func(v view) []Finding { return weakAlgorithms(v, "kexalgorithms", "SSH006", weakKex) }},
	{f: func(v view) []Finding { return weakAlgorithms(v, "hostkeyalgorithms", "SSH007", weakSignatures) }},
	{all: true, f: func(v view) []Finding { return weakAlgorithms(v, "pubkeyacceptedalgorithms", "SSH007", weakSignatures) }},
	{all: true, f: func(v view) []Finding { return weakAlgorithms(v, "casignaturealgorithms", "SSH007", weakSignatures) }},
	{f: func(v view) []Finding {
		var out []Finding
		for _, d := range v.e.Multi["hostkey"] {
			base := strings.ToLower(path.Base(strings.ReplaceAll(d.Value(), `\`, "/")))
			if strings.Contains(base, "_dsa_") || strings.HasSuffix(base, "_dsa_key") {
				out = append(out, v.find("SSH008", "high", d, "HostKey %s is a DSA key: 1024-bit, removed from OpenSSH 10", d.Value()))
			}
		}
		return out
	}},
	{f: terrapin},
	{all: true, f: func(v view) []Finding {
		if val, d := v.get("x11forwarding"); is(val, "yes") {
			return []Finding{v.find("SSH010", "low", d, "X11Forwarding yes exposes the client's display to a compromised server; enable it only where needed")}
		}
		return nil
	}},
	{all: true, f: func(v view) []Finding {
		var out []Finding
		if val, d := v.get("gatewayports"); is(val, "yes", "clientspecified") {
			out = append(out, v.find("SSH011", "medium", d, "GatewayPorts %s lets forwarded ports listen on all interfaces, not just loopback", val))
		}
		if val, d := v.get("permittunnel"); is(val, "yes", "point-to-point", "ethernet") {
			out = append(out, v.find("SSH011", "low", d, "PermitTunnel %s allows tun device forwarding: a VPN into this host's network", val))
		}
		return out
	}},
	{all: true, f: func(v view) []Finding {
		if val, d := v.get("permituserenvironment"); !is(val, "no") {
			return []Finding{v.find("SSH012", "medium", d, "PermitUserEnvironment %s lets users set variables such as LD_PRELOAD for their sessions, which can bypass ForceCommand", val)}
		}
		return nil
	}},
	{f: func(v view) []Finding {
		if val, d := v.get("strictmodes"); is(val, "no") {
			return []Finding{v.find("SSH013", "medium", d, "StrictModes no accepts world-writable home directories and key files")}
		}
		return nil
	}},
	{all: true, f: func(v view) []Finding {
		var out []Finding
		if val, d := v.get("hostbasedauthentication"); is(val, "yes") {
			out = append(out, v.find("SSH014", "medium", d, "HostbasedAuthentication yes trusts other hosts' word for who a user is"))
		}
		if val, d := v.get("ignorerhosts"); is(val, "no") {
			out = append(out, v.find("SSH014", "medium", d, "IgnoreRhosts no honours .rhosts and .shosts files"))
		}
		return out
	}},
	{all: true, f: func(v view) []Finding {
		var out []Finding
		if val, d := v.get("maxauthtries"); atoi(val) > 6 {
			out = append(out, v.find("SSH015", "low", d, "MaxAuthTries %s allows more guesses per connection than the default of 6", val))
		}
		return out
	}},
	{f: func(v view) []Finding {
		if val, d := v.get("logingracetime"); val == "0" || Seconds(val) > 600 {
			return []Finding{v.find("SSH015", "low", d, "LoginGraceTime %s keeps unauthenticated connections open %s", val,
				map[bool]string{true: "without limit", false: "for over ten minutes"}[val == "0"])}
		}
		return nil
	}},
	{all: true, f: func(v view) []Finding {
		if val, d := v.get("loglevel"); is(val, "quiet", "fatal", "error") {
			return []Finding{v.find("SSH016", "low", d, "LogLevel %s does not record logins; INFO or VERBOSE is needed for an audit trail", val)}
		}
		return nil
	}},
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// Seconds reads sshd's time format: 90, 2m, 1h30m.
func Seconds(s string) int {
	total, n := 0, 0
	for _, c := range strings.ToLower(s) {
		switch {
		case c >= '0' && c <= '9':
			n = n*10 + int(c-'0')
		case c == 's':
			total, n = total+n, 0
		case c == 'm':
			total, n = total+n*60, 0
		case c == 'h':
			total, n = total+n*3600, 0
		case c == 'd':
			total, n = total+n*86400, 0
		case c == 'w':
			total, n = total+n*604800, 0
		default:
			return 0
		}
	}
	return total + n
}

type weakness struct {
	pattern, severity, why string
}

var weakCiphers = []weakness{
	{"3des-cbc", "high", "64-bit block cipher (Sweet32)"},
	{"blowfish-cbc", "high", "64-bit block cipher (Sweet32)"},
	{"cast128-cbc", "high", "64-bit block cipher (Sweet32)"},
	{"arcfour*", "high", "RC4 has known biases"},
	{"*-cbc", "medium", "CBC mode in SSH is open to plaintext-recovery attacks"},
	{"rijndael-cbc@lysator.liu.se", "medium", "CBC mode in SSH is open to plaintext-recovery attacks"},
	{"none", "critical", "no encryption"},
}

var weakMACs = []weakness{
	{"hmac-md5*", "high", "MD5"},
	{"hmac-sha1-96*", "medium", "SHA-1 truncated to 96 bits"},
	{"hmac-ripemd160*", "medium", "RIPEMD-160, removed from OpenSSH 7.6"},
	{"umac-32*", "medium", "32-bit tag"},
	{"none", "critical", "no integrity protection"},
}

var weakKex = []weakness{
	{"diffie-hellman-group1-sha1", "high", "1024-bit group (Logjam-era) and SHA-1"},
	{"diffie-hellman-group14-sha1", "medium", "SHA-1"},
	{"diffie-hellman-group-exchange-sha1", "medium", "SHA-1, and the client cannot verify the group"},
	{"gss-*-sha1-*", "medium", "SHA-1"},
}

var weakSignatures = []weakness{
	{"ssh-dss*", "high", "DSA, 1024-bit, removed from OpenSSH 10"},
	{"ssh-rsa", "medium", "RSA with SHA-1 signatures, disabled by default since OpenSSH 8.8"},
	{"ssh-rsa-cert-v01@openssh.com", "medium", "RSA with SHA-1 signatures"},
}

// weakAlgorithms reports weak entries in the list sshd would use. The built-in OpenSSH 9.6
// defaults contain none, but defaults taken from an older sshd with --defaults may, and then
// they are enabled on that server and are reported at "(default)".
func weakAlgorithms(v view, keyword, id string, table []weakness) []Finding {
	list, from := v.e.Algorithms(v.scope, keyword)
	var out []Finding
	for _, alg := range list {
		for _, w := range table {
			if ok, _ := path.Match(w.pattern, alg); ok {
				out = append(out, v.find(id, w.severity, from, "%s enables %s: %s", sshd.DisplayName(keyword), alg, w.why))
				break
			}
		}
	}
	return out
}

// terrapin reports CVE-2023-48795 when the version is known to lack the strict key exchange fix.
func terrapin(v view) []Finding {
	if v.opt.OpenSSHVersion == "" || !olderThan(v.opt.OpenSSHVersion, 9, 6) {
		return nil
	}
	ciphers, cf := v.e.Algorithms(v.scope, "ciphers")
	macs, mf := v.e.Algorithms(v.scope, "macs")
	var reasons []string
	for _, c := range ciphers {
		if c == "chacha20-poly1305@openssh.com" {
			reasons = append(reasons, c)
		}
	}
	hasCBC := false
	for _, c := range ciphers {
		if strings.HasSuffix(c, "-cbc") {
			hasCBC = true
		}
	}
	if hasCBC {
		for _, m := range macs {
			if strings.HasSuffix(m, "-etm@openssh.com") {
				reasons = append(reasons, "CBC ciphers with "+m)
				break
			}
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	from := cf
	if from == nil {
		from = mf
	}
	return []Finding{v.find("SSH009", "medium", from,
		"OpenSSH %s predates the strict key exchange fix (9.6) and %s is enabled: the Terrapin attack (CVE-2023-48795) can drop messages at the start of the session",
		v.opt.OpenSSHVersion, strings.Join(reasons, ", "))}
}

func olderThan(version string, major, minor int) bool {
	v := strings.TrimPrefix(strings.ToLower(version), "openssh_")
	maj, mi, _ := strings.Cut(v, ".")
	if i := strings.IndexFunc(mi, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		mi = mi[:i]
	}
	a, b := atoi(maj), atoi(mi)
	return a < major || a == major && b < minor
}

// Check runs every rule over the global section and every Match block, and adds the problems
// found while reading the files and the values sshd ignores.
func Check(cfg *sshd.Config, e *sshd.Effective, opt Options) []Finding {
	var out []Finding
	for _, p := range cfg.Problems {
		out = append(out, Finding{ID: p.ID, Severity: p.Severity, File: p.File, Line: p.Line, Scope: "global", Message: p.Message})
	}
	for _, c := range checks {
		out = append(out, c.f(view{e: e, scope: e.Global, opt: opt})...)
		if !c.all {
			continue
		}
		for _, m := range e.Matches {
			for _, f := range c.f(view{e: e, scope: m, opt: opt}) {
				if f.Line != 0 && inBlock(f, m) {
					out = append(out, f)
				}
			}
		}
	}
	out = append(out, ignored(e)...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func inBlock(f Finding, s *sshd.Scope) bool {
	for _, st := range s.Set {
		if st.From.File == f.File && st.From.Line == f.Line {
			return true
		}
	}
	return false
}

// ignored reports values sshd never uses because the same keyword was set earlier in the same
// scope. The usual cause is an Include of drop-in files at the top of sshd_config: whatever
// the drop-ins set wins, and later edits to the main file do nothing.
func ignored(e *sshd.Effective) []Finding {
	var out []Finding
	report := func(s *sshd.Scope) {
		for k, st := range s.Set {
			for _, d := range st.Ignored {
				scope := "global"
				if s.Match != nil {
					scope = "Match " + s.Match.Criteria
				}
				out = append(out, Finding{ID: "SSH020", Severity: "medium", File: d.File, Line: d.Line, Scope: scope,
					Message: fmt.Sprintf("%s %s has no effect: sshd uses the first value it reads, %s, from %s:%d",
						sshd.DisplayName(k), d.Value(), st.From.Value(), st.From.File, st.From.Line)})
			}
		}
	}
	report(e.Global)
	for _, m := range e.Matches {
		report(m)
	}
	return out
}
