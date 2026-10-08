package setup

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// IO is the terminal the prompts use; *console.Terminal implements it.
type IO interface {
	Println(s string)
	Ask(ctx context.Context, prompt string, timeout time.Duration) (string, bool)
}

// ErrAborted reports Ctrl-D, Ctrl-C or a closed terminal during the prompts.
var ErrAborted = errors.New("setup aborted")

const answerTimeout = 30 * time.Minute

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

var engines = []string{"postgres", "mysql", "mariadb", "sqlite"}

// Prompt asks for one database profile. taken lists the profile names
// already visible, to pick a free default name.
func Prompt(ctx context.Context, io IO, cwd string, taken []string) (Answers, error) {
	ask := func(p string) (string, error) {
		l, ok := io.Ask(ctx, p, answerTimeout)
		if !ok {
			return "", ErrAborted
		}
		return strings.TrimSpace(l), nil
	}
	var a Answers
	for {
		l, err := ask("Database URL (or Enter to answer step by step)\n> ")
		if err != nil {
			return Answers{}, err
		}
		if l == "" {
			if a.Target, err = stepByStep(ask, cwd); err != nil {
				return Answers{}, err
			}
			break
		}
		t, perr := ParseURL(l, cwd)
		if perr == nil {
			a.Target = t
			break
		}
		io.Println("  " + perr.Error())
	}

	def := "dev"
	for i := 2; slices.Contains(taken, def); i++ {
		def = "dev" + strconv.Itoa(i)
	}
	for {
		l, err := ask(fmt.Sprintf("Profile name [%s]: ", def))
		if err != nil {
			return Answers{}, err
		}
		if l == "" {
			l = def
		}
		switch {
		case !nameRe.MatchString(l):
			io.Println("  use letters, digits, '_', '-' or '.', starting with a letter or digit")
		case slices.Contains(taken, l):
			io.Println("  profile " + l + " already exists")
		default:
			a.Name = l
		}
		if a.Name != "" {
			break
		}
	}
	for {
		l, err := ask("Access: read / write / ddl  [read]: ")
		if err != nil {
			return Answers{}, err
		}
		if l == "" {
			l = "read"
		}
		if l == "read" || l == "write" || l == "ddl" {
			a.Tier = l
			break
		}
		io.Println("  answer read, write or ddl (admin is set by editing the config)")
	}
	var err error
	if a.Production, err = yesNo(ask, "Production database? [y/N]: ", false); err != nil {
		return Answers{}, err
	}
	if a.Production && (len(a.Name) < 2 || slices.Contains([]string{"y", "yes", "n", "no", "ok"}, strings.ToLower(a.Name))) {
		return Answers{}, errors.New("a production profile needs a name of 2 characters or more that is not y, yes, n, no or ok")
	}
	if a.Keychain, err = yesNo(ask, "Remember the password in the OS keychain? [Y/n]: ", true); err != nil {
		return Answers{}, err
	}
	return a, nil
}

func yesNo(ask func(string) (string, error), p string, def bool) (bool, error) {
	for {
		l, err := ask(p)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(l) {
		case "":
			return def, nil
		case "y", "yes", "o", "oui":
			return true, nil
		case "n", "no", "non":
			return false, nil
		}
	}
}

func stepByStep(ask func(string) (string, error), cwd string) (Target, error) {
	var t Target
	for t.Engine == "" {
		l, err := ask("Engine: 1) postgres 2) mysql 3) mariadb 4) sqlite\n> ")
		if err != nil {
			return Target{}, err
		}
		if n, err := strconv.Atoi(l); err == nil && n >= 1 && n <= len(engines) {
			t.Engine = engines[n-1]
		} else if slices.Contains(engines, l) {
			t.Engine = l
		}
	}
	if t.Engine == "sqlite" {
		for t.Path == "" {
			l, err := ask("Database file path: ")
			if err != nil {
				return Target{}, err
			}
			if l != "" {
				if pt, err := ParseURL("sqlite://"+l, cwd); err == nil {
					t.Path = pt.Path
				}
			}
		}
		return t, nil
	}
	var err error
	if t.Host, err = ask("Host [127.0.0.1]: "); err != nil {
		return Target{}, err
	}
	if t.Host == "" {
		t.Host = "127.0.0.1"
	}
	for t.Port == 0 {
		l, err := ask(fmt.Sprintf("Port [%d]: ", DefaultPort(t.Engine)))
		if err != nil {
			return Target{}, err
		}
		if l == "" {
			t.Port = DefaultPort(t.Engine)
		} else if n, err := strconv.Atoi(l); err == nil && n >= 1 && n <= 65535 {
			t.Port = n
		}
	}
	if t.User, err = ask("User (empty: asked at console start): "); err != nil {
		return Target{}, err
	}
	if t.Database, err = ask("Database (empty: chosen per query): "); err != nil {
		return Target{}, err
	}
	return t, nil
}
