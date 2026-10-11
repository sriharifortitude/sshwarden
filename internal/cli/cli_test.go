package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

const td = "../../testdata/"

func TestTheUbuntuLayout(t *testing.T) {
	code, out, _ := run(t, "", "--root", td+"ubuntu", td+"ubuntu/etc/ssh/sshd_config")
	if code != 1 || !strings.Contains(out, "PasswordAuthentication no has no effect") || !strings.Contains(out, "2 file(s) read") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestWithoutRootTheDropInIsNotFound(t *testing.T) {
	// /etc/ssh/sshd_config.d does not exist on the test machine (or is not this fixture's).
	_, out, _ := run(t, "", "--json", td+"ubuntu/etc/ssh/sshd_config")
	if strings.Contains(out, "50-cloud-init") {
		t.Fatalf("absolute Include resolved without --root:\n%s", out)
	}
}

func TestHardenedIsClean(t *testing.T) {
	code, out, _ := run(t, "", td+"hardened/sshd_config", "--fail-on", "info")
	if code != 0 || !strings.Contains(out, "no findings") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestFailOn(t *testing.T) {
	cfg := "PasswordAuthentication no\nKbdInteractiveAuthentication no\nX11Forwarding yes\n"
	for level, want := range map[string]int{"medium": 0, "low": 1, "info": 1, "none": 0, "critical": 0} {
		if code, _, _ := run(t, cfg, "-", "--fail-on", level); code != want {
			t.Errorf("--fail-on %s: exit %d, want %d", level, code, want)
		}
	}
}

func TestJSON(t *testing.T) {
	_, out, _ := run(t, "", "--json", td+"legacy/sshd_config")
	var res struct {
		Files    []string `json:"files"`
		Findings []struct {
			ID, Severity, File, Scope, Message string
			Line                               int
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || len(res.Findings) < 10 || res.Findings[0].Line == 0 {
		t.Fatalf("%+v", res)
	}
}

func TestEffective(t *testing.T) {
	code, out, _ := run(t, "", "--effective", td+"differential/sshd_config")
	if code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{
		"permitrootlogin without-password\t# ", "kbdinteractiveauthentication no\t# ", "logingracetime 90\t# ",
		"x11forwarding yes\t# ", "ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\t# ",
		"loglevel VERBOSE\t# ", "pubkeyauthentication yes\t# default",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestEffectivePrintsWithoutPasswordAsSshdDoes(t *testing.T) {
	if _, out, _ := run(t, "PermitRootLogin prohibit-password\n", "--effective", "-"); !strings.Contains(out, "permitrootlogin without-password\t# (stdin):1") {
		t.Fatal(out)
	}
}

func TestDefaultsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "defaults.txt")
	if err := os.WriteFile(p, []byte("passwordauthentication no\nkbdinteractiveauthentication no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run(t, "", "--defaults", p, "-"); code != 0 || !strings.Contains(out, "no findings") {
		t.Fatalf("defaults from the dump should make an empty config clean: %d %s", code, out)
	}
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, "", "--defaults", empty, "-"); code != 2 || errOut == "" {
		t.Fatalf("a dump with no values must be refused: %d", code)
	}
}

func TestOpenSSHVersionFlag(t *testing.T) {
	cfg := "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
	if _, out, _ := run(t, cfg, "-", "--openssh-version", "9.2p1"); !strings.Contains(out, "SSH009") {
		t.Fatal(out)
	}
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no file":      {},
		"two files":    {"a", "b"},
		"bad fail-on":  {"--fail-on", "severe", "-"},
		"unknown flag": {"--nope", "-"},
		"missing":      {filepath.Join(t.TempDir(), "nope")},
		"bad defaults": {"--defaults", filepath.Join(t.TempDir(), "nope"), "-"},
	} {
		if code, _, errOut := run(t, "", args...); code != 2 || errOut == "" {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
}

func TestStdinOverLimit(t *testing.T) {
	if code, _, _ := run(t, strings.Repeat("#\n", 1<<19+1), "-"); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := run(t, "", "--version"); code != 0 || !strings.HasPrefix(out, "sshwarden ") {
		t.Fatal(out)
	}
	if code, out, _ := run(t, "", "--help"); code != 0 || !strings.Contains(out, "usage:") {
		t.Fatal(out)
	}
}
