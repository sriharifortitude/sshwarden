package sshd

import (
	"bufio"
	"bytes"
	"path"
	"strings"
)

// Defaults holds the value sshd uses when a keyword is not set. Built-in values are those of
// upstream OpenSSH 9.6 (Ubuntu 24.04 LTS); FromDump replaces them with what a real sshd prints.
type Defaults map[string]string

// BuiltinDefaults returns the upstream OpenSSH 9.6 defaults for the keywords this tool checks.
func BuiltinDefaults() Defaults {
	hostKeyAlgs := "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384," +
		"ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256"
	return Defaults{
		"permitrootlogin":              "prohibit-password",
		"passwordauthentication":       "yes",
		"kbdinteractiveauthentication": "yes",
		"permitemptypasswords":         "no",
		"pubkeyauthentication":         "yes",
		"usepam":                       "no",
		"authenticationmethods":        "any",
		"x11forwarding":                "no",
		"allowtcpforwarding":           "yes",
		"allowagentforwarding":         "yes",
		"allowstreamlocalforwarding":   "yes",
		"permittunnel":                 "no",
		"gatewayports":                 "no",
		"disableforwarding":            "no",
		"permituserenvironment":        "no",
		"strictmodes":                  "yes",
		"maxauthtries":                 "6",
		"logingracetime":               "120",
		"hostbasedauthentication":      "no",
		"ignorerhosts":                 "yes",
		"loglevel":                     "INFO",
		"usedns":                       "no",
		"compression":                  "yes",
		"ciphers":                      "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
		"macs": "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com," +
			"hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
		"kexalgorithms": "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256," +
			"ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512," +
			"diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
		"hostkeyalgorithms":           hostKeyAlgs,
		"pubkeyacceptedalgorithms":    hostKeyAlgs,
		"hostbasedacceptedalgorithms": hostKeyAlgs,
		"casignaturealgorithms": "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521," +
			"sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256",
	}
}

// FromDump reads `sshd -T` output and takes every value it prints as the default. Keywords it
// does not print keep the built-in default.
func (d Defaults) FromDump(data []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		canon, _, known := Canonical(k)
		if !known {
			continue
		}
		if _, tracked := d[canon]; tracked {
			d[canon] = strings.TrimSpace(v)
			n++
		}
	}
	return n
}

// Setting is the value in force for a keyword and where it came from.
type Setting struct {
	// From is the directive that set it, or nil when the default applies.
	From *Directive
	// Ignored lists later directives with a different value, which sshd does not use.
	Ignored []*Directive
}

// Scope is the effective configuration for the global section or for one Match block.
type Scope struct {
	// Match is nil for the global section.
	Match *Match
	// Set holds the first directive for each single-valued keyword set in this scope.
	Set map[string]*Setting
}

// Effective is the configuration as sshd would use it.
type Effective struct {
	Global   *Scope
	Matches  []*Scope
	Defaults Defaults
	// Multi holds every directive of keywords where all occurrences count.
	Multi map[string][]*Directive
}

// Resolve applies sshd's rules: the first value of a keyword wins within a scope, and a Match
// block's values override the global section for the connections it matches.
func Resolve(c *Config, defaults Defaults) *Effective {
	e := &Effective{Global: &Scope{Set: map[string]*Setting{}}, Defaults: defaults, Multi: map[string][]*Directive{}}
	scopes := map[*Match]*Scope{}
	for _, m := range c.Matches {
		s := &Scope{Match: m, Set: map[string]*Setting{}}
		scopes[m] = s
		e.Matches = append(e.Matches, s)
	}
	for i := range c.Directives {
		d := &c.Directives[i]
		if keywords[d.Keyword].Multi {
			e.Multi[d.Keyword] = append(e.Multi[d.Keyword], d)
			continue
		}
		s := e.Global
		if d.Match != nil {
			s = scopes[d.Match]
		}
		if first, ok := s.Set[d.Keyword]; ok {
			if !sameValue(d.Keyword, first.From.Value(), d.Value()) {
				first.Ignored = append(first.Ignored, d)
			}
			continue
		}
		s.Set[d.Keyword] = &Setting{From: d}
	}
	return e
}

func sameValue(keyword, a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		if keyword == "permitrootlogin" && s == "without-password" {
			return "prohibit-password"
		}
		return s
	}
	return norm(a) == norm(b)
}

// Get returns the value of a keyword in a scope, falling back to the global section and then
// the default, with the directive that set it (nil for a default).
func (e *Effective) Get(s *Scope, keyword string) (string, *Directive) {
	if s != nil {
		if st, ok := s.Set[keyword]; ok {
			return st.From.Value(), st.From
		}
	}
	if st, ok := e.Global.Set[keyword]; ok {
		return st.From.Value(), st.From
	}
	return e.Defaults[keyword], nil
}

// Algorithms returns the list sshd would use for an algorithm keyword, applying the "+"
// (append), "-" (remove, wildcards allowed) and "^" (put first) forms to the default.
func (e *Effective) Algorithms(s *Scope, keyword string) ([]string, *Directive) {
	value, from := e.Get(s, keyword)
	return ApplyList(e.Defaults[keyword], value), from
}

// ApplyList evaluates an algorithm list against its default.
func ApplyList(def, value string) []string {
	split := func(v string) []string {
		var out []string
		for _, a := range strings.Split(v, ",") {
			if a = strings.TrimSpace(a); a != "" {
				out = append(out, a)
			}
		}
		return out
	}
	base := split(def)
	if value == "" {
		return base
	}
	switch value[0] {
	case '+':
		return appendNew(base, split(value[1:]))
	case '^':
		return appendNew(split(value[1:]), base)
	case '-':
		var out []string
		remove := split(value[1:])
		for _, a := range base {
			drop := false
			for _, pat := range remove {
				if ok, _ := path.Match(pat, a); ok || pat == a {
					drop = true
					break
				}
			}
			if !drop {
				out = append(out, a)
			}
		}
		return out
	}
	return split(value)
}

func appendNew(list, add []string) []string {
	out := append([]string(nil), list...)
	for _, a := range add {
		dup := false
		for _, b := range out {
			if a == b {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, a)
		}
	}
	return out
}
