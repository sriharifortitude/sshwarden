package rules

import (
	"strings"
	"testing"

	"github.com/sriharifortitude/sshwarden/internal/sshd"
)

func run(t *testing.T, text string, opt Options) []Finding {
	t.Helper()
	c := sshd.Parse("t", []byte(text))
	return Check(c, sshd.Resolve(c, sshd.BuiltinDefaults()), opt)
}

// has reports whether a finding with this ID, severity and (if given) message fragment exists.
func has(fs []Finding, id, sev, fragment string) bool {
	for _, f := range fs {
		if f.ID == id && f.Severity == sev && strings.Contains(f.Message, fragment) {
			return true
		}
	}
	return false
}

func idsOf(fs []Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+"/"+f.Severity)
	}
	return strings.Join(out, " ")
}

const keysOnly = "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"

func TestAKeysOnlyConfigurationIsClean(t *testing.T) {
	if fs := run(t, keysOnly, Options{}); len(fs) != 0 {
		t.Fatal(idsOf(fs))
	}
}

func TestTheDefaultAllowsPasswords(t *testing.T) {
	fs := run(t, "", Options{})
	if len(fs) != 1 || !has(fs, "SSH002", "medium", "not set, and the default is") || fs[0].Line != 0 {
		t.Fatal(idsOf(fs), fs)
	}
}

func TestKeyboardInteractiveThroughPAM(t *testing.T) {
	fs := run(t, "PasswordAuthentication no\nUsePAM yes\n", Options{})
	if !has(fs, "SSH002", "medium", "PAM will ask") {
		t.Fatal(idsOf(fs))
	}
	if fs := run(t, "PasswordAuthentication no\nUsePAM no\n", Options{}); has(fs, "SSH002", "medium", "PAM") {
		t.Fatal("without PAM, keyboard-interactive has no password to ask for")
	}
}

func TestAuthenticationMethodsRulesOutPasswords(t *testing.T) {
	if fs := run(t, "AuthenticationMethods publickey\n", Options{}); len(fs) != 0 {
		t.Fatal(idsOf(fs))
	}
	if fs := run(t, "AuthenticationMethods publickey,password\n", Options{}); !has(fs, "SSH002", "medium", "") {
		t.Fatal(idsOf(fs))
	}
}

func TestEachSettingRule(t *testing.T) {
	cases := []struct{ line, id, sev string }{
		{"PermitRootLogin yes", "SSH001", "high"},
		{"PermitEmptyPasswords yes", "SSH003", "critical"},
		{"X11Forwarding yes", "SSH010", "low"},
		{"GatewayPorts clientspecified", "SSH011", "medium"},
		{"PermitTunnel point-to-point", "SSH011", "low"},
		{"PermitUserEnvironment LANG,LC_*", "SSH012", "medium"},
		{"StrictModes no", "SSH013", "medium"},
		{"HostbasedAuthentication yes", "SSH014", "medium"},
		{"IgnoreRhosts no", "SSH014", "medium"},
		{"MaxAuthTries 7", "SSH015", "low"},
		{"LoginGraceTime 0", "SSH015", "low"},
		{"LoginGraceTime 11m", "SSH015", "low"},
		{"LogLevel QUIET", "SSH016", "low"},
		{"LogLevel ERROR", "SSH016", "low"},
		{"HostKey /etc/ssh/ssh_host_dsa_key", "SSH008", "high"},
	}
	for _, c := range cases {
		fs := run(t, keysOnly+c.line+"\n", Options{})
		if !has(fs, c.id, c.sev, "") || len(fs) != 1 {
			t.Errorf("%s: want only %s/%s, got %s", c.line, c.id, c.sev, idsOf(fs))
		}
	}
}

func TestSafeValuesPass(t *testing.T) {
	for _, line := range []string{"PermitRootLogin prohibit-password", "PermitRootLogin forced-commands-only", "PermitRootLogin no",
		"MaxAuthTries 6", "LoginGraceTime 10m", "LogLevel VERBOSE", "GatewayPorts no", "PermitTunnel no",
		"HostKey /etc/ssh/ssh_host_ed25519_key", "X11Forwarding no", "PermitUserEnvironment no"} {
		if fs := run(t, keysOnly+line+"\n", Options{}); len(fs) != 0 {
			t.Errorf("%s: %s", line, idsOf(fs))
		}
	}
}

func TestWeakAlgorithms(t *testing.T) {
	cases := []struct{ line, id, sev, alg string }{
		{"Ciphers +3des-cbc", "SSH004", "high", "3des-cbc"},
		{"Ciphers aes128-ctr,aes256-cbc", "SSH004", "medium", "aes256-cbc"},
		{"Ciphers +arcfour256", "SSH004", "high", "arcfour256"},
		{"MACs +hmac-md5-96", "SSH005", "high", "hmac-md5-96"},
		{"MACs hmac-sha2-256,hmac-sha1-96", "SSH005", "medium", "hmac-sha1-96"},
		{"KexAlgorithms +diffie-hellman-group1-sha1", "SSH006", "high", "group1-sha1"},
		{"KexAlgorithms ^diffie-hellman-group-exchange-sha1", "SSH006", "medium", "group-exchange-sha1"},
		{"HostKeyAlgorithms +ssh-rsa", "SSH007", "medium", "ssh-rsa"},
		{"PubkeyAcceptedKeyTypes +ssh-dss", "SSH007", "high", "ssh-dss"},
		{"CASignatureAlgorithms +ssh-rsa", "SSH007", "medium", "ssh-rsa"},
	}
	for _, c := range cases {
		fs := run(t, keysOnly+c.line+"\n", Options{})
		if !has(fs, c.id, c.sev, c.alg) {
			t.Errorf("%s: want %s/%s for %s, got %s", c.line, c.id, c.sev, c.alg, idsOf(fs))
		}
	}
}

func TestWeakDefaultsFromAnOlderSshdAreReported(t *testing.T) {
	d := sshd.BuiltinDefaults()
	d.FromDump([]byte("ciphers aes128-ctr,aes128-cbc,3des-cbc\n"))
	c := sshd.Parse("t", []byte(keysOnly))
	fs := Check(c, sshd.Resolve(c, d), Options{})
	if !has(fs, "SSH004", "high", "3des-cbc") || fs[0].Line != 0 {
		t.Fatal(idsOf(fs))
	}
	if fs := run(t, keysOnly, Options{}); len(fs) != 0 {
		t.Fatal("the built-in defaults contain nothing weak:", idsOf(fs))
	}
}

func TestRemovingAWeakAlgorithmClearsIt(t *testing.T) {
	fs := run(t, keysOnly+"Ciphers aes128-ctr,aes256-cbc\nMACs -hmac-sha1*\nCiphers -*-cbc\n", Options{})
	// The first Ciphers line wins, so the CBC cipher stays; the later removal is ignored.
	if !has(fs, "SSH004", "medium", "aes256-cbc") || !has(fs, "SSH020", "medium", "first value") {
		t.Fatal(idsOf(fs))
	}
	if fs := run(t, keysOnly+"Ciphers -*-cbc\nMACs -hmac-sha1*\n", Options{}); len(fs) != 0 {
		t.Fatal(idsOf(fs))
	}
}

func TestMatchBlocksAreReportedWhereTheyWeaken(t *testing.T) {
	fs := run(t, keysOnly+"PermitRootLogin no\nMatch Address 10.0.0.0/8\n  PermitRootLogin yes\n  PasswordAuthentication yes\nMatch User ci\n  MaxAuthTries 3\n", Options{})
	var scoped []Finding
	for _, f := range fs {
		if f.Scope != "global" {
			scoped = append(scoped, f)
		}
	}
	if len(fs) != 2 || len(scoped) != 2 || scoped[0].Scope != "Match Address 10.0.0.0/8" || scoped[0].Line != 5 {
		t.Fatal(idsOf(fs), fs)
	}
}

func TestAMatchBlockDoesNotRepeatGlobalFindings(t *testing.T) {
	fs := run(t, "PermitRootLogin yes\n"+keysOnly+"Match User ci\n  X11Forwarding no\n", Options{})
	if len(fs) != 1 || fs[0].Scope != "global" {
		t.Fatal(idsOf(fs))
	}
}

func TestIgnoredValuesAreReported(t *testing.T) {
	fs := run(t, "PasswordAuthentication yes\nKbdInteractiveAuthentication no\nPasswordAuthentication no\n", Options{})
	if !has(fs, "SSH020", "medium", "PasswordAuthentication no has no effect") || !has(fs, "SSH020", "medium", "t:1") {
		t.Fatal(idsOf(fs), fs)
	}
}

func TestTerrapinNeedsAKnownOldVersion(t *testing.T) {
	if fs := run(t, keysOnly, Options{}); has(fs, "SSH009", "medium", "") {
		t.Fatal("no version, no Terrapin finding")
	}
	if fs := run(t, keysOnly, Options{OpenSSHVersion: "9.6"}); has(fs, "SSH009", "medium", "") {
		t.Fatal("9.6 has the fix")
	}
	if fs := run(t, keysOnly, Options{OpenSSHVersion: "9.3p2"}); !has(fs, "SSH009", "medium", "chacha20") {
		t.Fatal(idsOf(fs))
	}
	if fs := run(t, keysOnly+"Ciphers aes128-ctr,aes128-cbc\n", Options{OpenSSHVersion: "OpenSSH_8.9"}); !has(fs, "SSH009", "medium", "CBC ciphers with") {
		t.Fatal(idsOf(fs))
	}
	if fs := run(t, keysOnly+"Ciphers aes128-ctr,aes256-gcm@openssh.com\n", Options{OpenSSHVersion: "8.9"}); has(fs, "SSH009", "medium", "") {
		t.Fatal("no chacha20 and no CBC: not vulnerable")
	}
}

func TestOlderThan(t *testing.T) {
	for v, want := range map[string]bool{"9.5": true, "9.6": false, "9.6p1": false, "8.10": true, "10.0": false, "OpenSSH_9.3p2": true, "9": true} {
		if got := olderThan(v, 9, 6); got != want {
			t.Errorf("%s: got %v", v, got)
		}
	}
}

func TestSeconds(t *testing.T) {
	for s, want := range map[string]int{"90": 90, "2m": 120, "1h30m": 5400, "1m30s": 90, "x": 0, "1w": 604800} {
		if got := Seconds(s); got != want {
			t.Errorf("%s: %d", s, got)
		}
	}
}
