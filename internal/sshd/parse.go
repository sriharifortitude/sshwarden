package sshd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// MaxIncludeDepth is the nesting limit sshd itself uses.
	MaxIncludeDepth = 16
	maxFileBytes    = 1 << 20
	maxFiles        = 256
)

// Directive is one keyword line.
type Directive struct {
	// Keyword is canonical and lower case: ChallengeResponseAuthentication becomes
	// kbdinteractiveauthentication.
	Keyword string
	// Spelled is how the line wrote it.
	Spelled string
	Args    []string
	File    string
	Line    int
	// Match is the block the line belongs to, or nil for the global section.
	Match *Match
}

// Value is the arguments joined as sshd -T prints them.
func (d Directive) Value() string { return strings.Join(d.Args, " ") }

// Match is a Match block.
type Match struct {
	Criteria string
	File     string
	Line     int
}

// Problem is something wrong with the file itself rather than with its settings.
type Problem struct {
	ID       string
	Severity string
	File     string
	Line     int
	Message  string
}

// Config is a parsed configuration with its includes resolved.
type Config struct {
	Directives []Directive
	Matches    []*Match
	Problems   []Problem
	Files      []string
}

// Options say how to find included files.
type Options struct {
	// Root is prefixed to absolute Include paths, for auditing a copy of another machine's /etc.
	Root string
	// SSHDir is where relative Include paths are resolved; sshd uses /etc/ssh. Empty means
	// Root + /etc/ssh when Root is set, else the directory of the main file.
	SSHDir string
}

type parser struct {
	opt   Options
	cfg   *Config
	stack []string
}

// Load parses path and every file it includes.
func Load(path string, opt Options) (*Config, error) {
	if opt.SSHDir == "" {
		if opt.Root != "" {
			opt.SSHDir = filepath.Join(opt.Root, "etc", "ssh")
		} else {
			opt.SSHDir = filepath.Dir(path)
		}
	}
	data, err := readCapped(path)
	if err != nil {
		return nil, err
	}
	p := &parser{opt: opt, cfg: &Config{}}
	p.file(path, data, nil, 0)
	return p.cfg, nil
}

// Parse reads configuration text that includes no other files, for tests and standard input.
func Parse(name string, data []byte) *Config {
	p := &parser{opt: Options{SSHDir: "."}, cfg: &Config{}}
	p.file(name, data, nil, 0)
	return p.cfg
}

func readCapped(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if info.Size() > maxFileBytes {
		return nil, fmt.Errorf("%s is %d bytes; a configuration file over 1 MiB is not read", path, info.Size())
	}
	return os.ReadFile(path)
}

func (p *parser) problem(id, sev, file string, line int, format string, args ...any) {
	p.cfg.Problems = append(p.cfg.Problems, Problem{ID: id, Severity: sev, File: file, Line: line, Message: fmt.Sprintf(format, args...)})
}

// file parses one file. A Match block opened in a file ends with that file; directives in an
// included file start out in whatever block the Include line was in.
func (p *parser) file(name string, data []byte, outer *Match, depth int) {
	name = filepath.ToSlash(name)
	p.cfg.Files = append(p.cfg.Files, name)
	current := outer
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), maxFileBytes)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || text[0] == '#' {
			continue
		}
		word, rest := splitKeyword(text)
		args, err := splitArgs(rest)
		if err != nil {
			p.problem("SSH040", "high", name, line, "%s: %v; sshd refuses to start", word, err)
			continue
		}
		canon, sp, known := Canonical(word)
		switch {
		case !known:
			p.problem("SSH040", "high", name, line, "%q is not an sshd_config keyword in OpenSSH 9.x or 10.x; sshd refuses to start on an unknown keyword", word)
			continue
		case sp.Removed:
			p.problem("SSH041", "info", name, line, "%s was removed from OpenSSH and is ignored", sp.Name)
			continue
		case sp.Alias != "":
			p.problem("SSH041", "info", name, line, "%s is an old name for %s", sp.Name, sp.Alias)
		}
		if canon == "match" {
			if len(args) == 0 {
				p.problem("SSH040", "high", name, line, "Match with no criteria; sshd refuses to start")
				continue
			}
			current = &Match{Criteria: strings.Join(args, " "), File: name, Line: line}
			p.cfg.Matches = append(p.cfg.Matches, current)
			continue
		}
		if current != nil && !keywords[canon].InMatch {
			p.problem("SSH042", "high", name, line, "%s is not allowed inside a Match block (line %d of %s); sshd refuses to start",
				DisplayName(canon), current.Line, current.File)
			continue
		}
		if len(args) == 0 {
			p.problem("SSH040", "high", name, line, "%s has no value; sshd refuses to start", DisplayName(canon))
			continue
		}
		if canon == "include" {
			p.include(name, line, args, current, depth)
			continue
		}
		p.cfg.Directives = append(p.cfg.Directives, Directive{Keyword: canon, Spelled: word, Args: args, File: name, Line: line, Match: current})
	}
	if err := sc.Err(); err != nil {
		p.problem("SSH040", "high", name, line+1, "cannot be read past this line: %v", err)
	}
}

func (p *parser) include(from string, line int, patterns []string, current *Match, depth int) {
	if depth+1 > MaxIncludeDepth {
		p.problem("SSH043", "high", from, line, "Include nested deeper than %d levels; sshd refuses to start", MaxIncludeDepth)
		return
	}
	for _, pat := range patterns {
		resolved := pat
		switch {
		case strings.HasPrefix(pat, "~"):
			p.problem("SSH043", "info", from, line, "Include %s refers to a home directory, which this tool does not follow", pat)
			continue
		case filepath.IsAbs(pat) || strings.HasPrefix(pat, "/"):
			resolved = filepath.Join(p.opt.Root, filepath.FromSlash(pat))
		default:
			resolved = filepath.Join(p.opt.SSHDir, filepath.FromSlash(pat))
		}
		matches, err := filepath.Glob(resolved)
		if err != nil {
			p.problem("SSH043", "high", from, line, "Include %s is not a valid pattern: %v", pat, err)
			continue
		}
		sort.Strings(matches)
		if len(matches) == 0 {
			p.problem("SSH043", "info", from, line, "Include %s matches no file (looked for %s)", pat, filepath.ToSlash(resolved))
			continue
		}
		for _, m := range matches {
			abs, _ := filepath.Abs(m)
			if contains(p.stack, abs) {
				p.problem("SSH043", "high", from, line, "Include %s includes itself through %s; sshd refuses to start", pat, filepath.ToSlash(m))
				continue
			}
			if len(p.cfg.Files) >= maxFiles {
				p.problem("SSH043", "high", from, line, "more than %d included files; the rest were not read", maxFiles)
				return
			}
			data, err := readCapped(m)
			if err != nil {
				p.problem("SSH043", "high", from, line, "Include %s: %v", pat, err)
				continue
			}
			p.stack = append(p.stack, abs)
			p.file(m, data, current, depth+1)
			p.stack = p.stack[:len(p.stack)-1]
		}
	}
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

// splitKeyword separates the keyword from its arguments; sshd accepts "Key value",
// "Key=value" and "Key = value".
func splitKeyword(text string) (string, string) {
	i := strings.IndexAny(text, " \t=")
	if i < 0 {
		return text, ""
	}
	word, rest := text[:i], strings.TrimLeft(text[i:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	return word, rest
}

// splitArgs splits on blanks, keeps double-quoted runs together, and stops at an argument that
// begins with #, which sshd treats as the start of a comment.
func splitArgs(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote && c == '"':
			inQuote = false
		case inQuote:
			cur.WriteByte(c)
		case c == '"':
			inQuote, have = true, true
		case c == ' ' || c == '\t':
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		case c == '#' && !have:
			return out, nil
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote")
	}
	if have {
		out = append(out, cur.String())
	}
	return out, nil
}
