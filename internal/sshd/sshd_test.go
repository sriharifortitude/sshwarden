package sshd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func parse(t *testing.T, text string) (*Config, *Effective) {
	t.Helper()
	c := Parse("t", []byte(text))
	return c, Resolve(c, BuiltinDefaults())
}

func ids(c *Config) []string {
	var out []string
	for _, p := range c.Problems {
		out = append(out, p.ID)
	}
	return out
}

func TestKeywordForms(t *testing.T) {
	c, e := parse(t, "PasswordAuthentication=no\nPermitRootLogin = yes\n  maxauthtries\t3\nBanner \"/etc/issue net\"\n")
	if len(c.Problems) != 0 {
		t.Fatal(c.Problems)
	}
	for k, want := range map[string]string{"passwordauthentication": "no", "permitrootlogin": "yes", "maxauthtries": "3", "banner": "/etc/issue net"} {
		if got, _ := e.Get(e.Global, k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestCommentsAndHashArguments(t *testing.T) {
	_, e := parse(t, "# PermitRootLogin yes\n   # indented comment\nMaxAuthTries 3 # trailing\n")
	if got, d := e.Get(e.Global, "permitrootlogin"); got != "prohibit-password" || d != nil {
		t.Fatalf("a comment set a value: %q", got)
	}
	if got, _ := e.Get(e.Global, "maxauthtries"); got != "3" {
		t.Fatalf("got %q", got)
	}
}

func TestUnterminatedQuoteAndMissingValue(t *testing.T) {
	c, _ := parse(t, "Banner \"/etc/issue\nPermitRootLogin\n")
	if got := ids(c); !reflect.DeepEqual(got, []string{"SSH040", "SSH040"}) {
		t.Fatal(c.Problems)
	}
}

func TestUnknownRemovedAndAliasKeywords(t *testing.T) {
	c, e := parse(t, "PermitRootLgin no\nProtocol 2\nChallengeResponseAuthentication no\n")
	if got := ids(c); !reflect.DeepEqual(got, []string{"SSH040", "SSH041", "SSH041"}) {
		t.Fatal(c.Problems)
	}
	if got, d := e.Get(e.Global, "kbdinteractiveauthentication"); got != "no" || d == nil {
		t.Fatalf("the alias did not set KbdInteractiveAuthentication: %q", got)
	}
}

func TestFirstValueWins(t *testing.T) {
	_, e := parse(t, "PasswordAuthentication yes\nPasswordAuthentication no\nPasswordAuthentication yes\n")
	st := e.Global.Set["passwordauthentication"]
	if st.From.Value() != "yes" || len(st.Ignored) != 1 || st.Ignored[0].Line != 2 {
		t.Fatalf("%+v", st)
	}
}

func TestTheSameValueTwiceIsNotReportedAsIgnored(t *testing.T) {
	_, e := parse(t, "PermitRootLogin prohibit-password\nPermitRootLogin without-password\nX11Forwarding no\nX11Forwarding NO\n")
	for k, st := range e.Global.Set {
		if len(st.Ignored) != 0 {
			t.Errorf("%s: %+v", k, st.Ignored)
		}
	}
}

func TestAnAliasAndItsTargetShareFirstWins(t *testing.T) {
	_, e := parse(t, "ChallengeResponseAuthentication no\nKbdInteractiveAuthentication yes\n")
	st := e.Global.Set["kbdinteractiveauthentication"]
	if st.From.Value() != "no" || len(st.Ignored) != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestMultiValuedKeywordsAccumulate(t *testing.T) {
	_, e := parse(t, "Port 22\nPort 2222\nHostKey /a\nHostKey /b\nAllowUsers alice\nAllowUsers bob\n")
	if len(e.Multi["port"]) != 2 || len(e.Multi["hostkey"]) != 2 || len(e.Multi["allowusers"]) != 2 {
		t.Fatalf("%+v", e.Multi)
	}
	if _, ok := e.Global.Set["port"]; ok {
		t.Fatal("Port treated as first-wins")
	}
}

func TestMatchOverridesGlobal(t *testing.T) {
	c, e := parse(t, "PasswordAuthentication no\nMatch Address 10.0.0.0/8\n  PasswordAuthentication yes\n  X11Forwarding yes\nMatch all\n  MaxAuthTries 2\n")
	if len(c.Matches) != 2 || c.Matches[0].Criteria != "Address 10.0.0.0/8" {
		t.Fatalf("%+v", c.Matches)
	}
	if got, _ := e.Get(e.Global, "passwordauthentication"); got != "no" {
		t.Fatalf("global: %q", got)
	}
	if got, d := e.Get(e.Matches[0], "passwordauthentication"); got != "yes" || d.Match != c.Matches[0] {
		t.Fatalf("match: %q", got)
	}
	if got, _ := e.Get(e.Matches[0], "maxauthtries"); got != "6" {
		t.Fatalf("a later block leaked into an earlier one: %q", got)
	}
}

func TestGlobalOnlyKeywordInMatch(t *testing.T) {
	c, e := parse(t, "Match User bob\n  Ciphers aes128-ctr\n  PasswordAuthentication yes\n")
	if got := ids(c); !reflect.DeepEqual(got, []string{"SSH042"}) {
		t.Fatal(c.Problems)
	}
	if _, ok := e.Matches[0].Set["ciphers"]; ok {
		t.Fatal("a rejected line still set a value")
	}
}

func TestMatchWithoutCriteria(t *testing.T) {
	if c, _ := parse(t, "Match\n"); !reflect.DeepEqual(ids(c), []string{"SSH040"}) {
		t.Fatal(c.Problems)
	}
}

func TestApplyList(t *testing.T) {
	def := "a-ctr,b-cbc,c-gcm,d-cbc"
	for value, want := range map[string]string{
		"":             "a-ctr,b-cbc,c-gcm,d-cbc",
		"x,y":          "x,y",
		"+e,a-ctr":     "a-ctr,b-cbc,c-gcm,d-cbc,e",
		"-*-cbc":       "a-ctr,c-gcm",
		"-c-gcm,a-ctr": "b-cbc,d-cbc",
		"^d-cbc,z":     "d-cbc,z,a-ctr,b-cbc,c-gcm",
	} {
		if got := strings.Join(ApplyList(def, value), ","); got != want {
			t.Errorf("%q: got %s want %s", value, got, want)
		}
	}
}

func TestDefaultsFromDump(t *testing.T) {
	d := BuiltinDefaults()
	n := d.FromDump([]byte("port 22\npasswordauthentication no\nciphers aes256-gcm@openssh.com\nnotakeyword x\nmaxauthtries\n"))
	if n != 2 || d["passwordauthentication"] != "no" || d["ciphers"] != "aes256-gcm@openssh.com" {
		t.Fatalf("%d %v %v", n, d["passwordauthentication"], d["ciphers"])
	}
}

// --- Include ---------------------------------------------------------------------------------

func write(t *testing.T, dir, rel, text string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIncludeAtTheTopWinsOverTheMainFile(t *testing.T) {
	root := t.TempDir()
	main := write(t, root, "etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n")
	write(t, root, "etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	write(t, root, "etc/ssh/sshd_config.d/10-first.conf", "X11Forwarding yes\n")
	write(t, root, "etc/ssh/sshd_config.d/ignored.txt", "PermitRootLogin yes\n")
	c, err := Load(main, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	e := Resolve(c, BuiltinDefaults())
	st := e.Global.Set["passwordauthentication"]
	if st.From.Value() != "yes" || !strings.HasSuffix(st.From.File, "50-cloud-init.conf") || len(st.Ignored) != 1 {
		t.Fatalf("%+v", st)
	}
	if len(c.Files) != 3 || !strings.HasSuffix(c.Files[1], "10-first.conf") {
		t.Fatalf("files read, in order: %v", c.Files)
	}
	if _, ok := e.Global.Set["permitrootlogin"]; ok {
		t.Fatal("a file not matching the pattern was read")
	}
}

func TestRelativeIncludeUsesTheSSHDirectory(t *testing.T) {
	root := t.TempDir()
	main := write(t, root, "etc/ssh/sshd_config", "Include conf.d/*.conf\n")
	write(t, root, "etc/ssh/conf.d/a.conf", "MaxAuthTries 2\n")
	c, err := Load(main, Options{Root: root})
	if err != nil || len(c.Files) != 2 {
		t.Fatalf("%v %v", err, c)
	}
}

func TestAMatchBlockEndsWithItsFile(t *testing.T) {
	dir := t.TempDir()
	main := write(t, dir, "sshd_config", "Include a.conf\nPasswordAuthentication no\n")
	write(t, dir, "a.conf", "Match User bob\n  X11Forwarding yes\n")
	c, err := Load(main, Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := Resolve(c, BuiltinDefaults())
	if st, ok := e.Global.Set["passwordauthentication"]; !ok || st.From.Match != nil {
		t.Fatal("a line after the Include was put inside the included file's Match block")
	}
}

func TestAnIncludeInsideAMatchBlockStaysInIt(t *testing.T) {
	dir := t.TempDir()
	main := write(t, dir, "sshd_config", "Match User bob\n  Include bob.conf\n")
	write(t, dir, "bob.conf", "X11Forwarding yes\n")
	c, err := Load(main, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Directives) != 1 || c.Directives[0].Match == nil {
		t.Fatalf("%+v", c.Directives)
	}
}

func TestIncludeProblems(t *testing.T) {
	dir := t.TempDir()
	main := write(t, dir, "sshd_config", "Include missing/*.conf\nInclude self.conf\nInclude ~/.ssh/x\nInclude [\n")
	write(t, dir, "self.conf", "Include self.conf\n")
	c, err := Load(main, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range c.Problems {
		got = append(got, p.Severity)
	}
	if !reflect.DeepEqual(got, []string{"info", "high", "info", "high"}) {
		t.Fatalf("%+v", c.Problems)
	}
	if !strings.Contains(c.Problems[1].Message, "includes itself") {
		t.Fatalf("a cycle must be named as one, not left to the depth limit: %s", c.Problems[1].Message)
	}
}

func TestIncludeDepthLimit(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < MaxIncludeDepth+2; i++ {
		write(t, dir, "f"+string(rune('a'+i))+".conf", "Include f"+string(rune('a'+i+1))+".conf\n")
	}
	c, err := Load(filepath.Join(dir, "fa.conf"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range c.Problems {
		found = found || strings.Contains(p.Message, "deeper than")
	}
	if !found {
		t.Fatalf("%+v", c.Problems)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "nope"), Options{}); err == nil {
		t.Error("missing file")
	}
	if _, err := Load(dir, Options{}); err == nil {
		t.Error("directory")
	}
	big := write(t, dir, "big", strings.Repeat("#", 1<<20+1))
	if _, err := Load(big, Options{}); err == nil {
		t.Error("oversized file")
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"PasswordAuthentication yes\n", "Match User a\n X11Forwarding yes\n", "Ciphers -*\n", "Banner \"x\n", "a=b=c\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c := Parse("f", []byte(s))
		e := Resolve(c, BuiltinDefaults())
		for _, m := range append([]*Scope{e.Global}, e.Matches...) {
			for _, k := range []string{"ciphers", "macs", "permitrootlogin"} {
				e.Get(m, k)
				e.Algorithms(m, k)
			}
		}
	})
}
