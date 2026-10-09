// Package setup builds a locksql profile from a database URL or from
// step-by-step answers, and appends it to the user config.
package setup

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// Target is where a profile points.
type Target struct {
	Engine, Host, Path, User, Database string
	Port                               int
}

var schemes = map[string]string{
	"postgres": config.EnginePostgres, "postgresql": config.EnginePostgres,
	"mysql": config.EngineMySQL, "mariadb": config.EngineMariaDB,
}

// DefaultPort is the port of a network engine when the URL names none.
func DefaultPort(engine string) int {
	if engine == config.EnginePostgres {
		return 5432
	}
	return 3306
}

// ParseURL reads postgres://, postgresql://, mysql://, mariadb:// and
// sqlite:// URLs. A password, any query parameter or a fragment is refused;
// errors never quote the URL.
func ParseURL(s, cwd string) (Target, error) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i > 0 {
		s = strings.ToLower(s[:i]) + s[i:]
	}
	if rest, ok := strings.CutPrefix(s, "sqlite://"); ok {
		local := strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "./") || strings.HasPrefix(rest, "../")
		if !local || strings.ContainsAny(rest, "?#@") {
			return Target{}, errors.New("sqlite URL: want sqlite:///absolute/path or sqlite://./relative/path")
		}
		if !filepath.IsAbs(rest) {
			rest = filepath.Join(cwd, rest)
		}
		return Target{Engine: config.EngineSQLite, Path: filepath.Clean(rest)}, nil
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return Target{}, errors.New("not a database URL: want postgres://user@host:port/db, mysql://, mariadb:// or sqlite://")
	}
	engine, ok := schemes[strings.ToLower(u.Scheme)]
	if !ok {
		return Target{}, errors.New("unsupported scheme: want postgres, postgresql, mysql, mariadb or sqlite")
	}
	if _, set := u.User.Password(); set {
		return Target{}, errors.New("the URL carries a password: leave it out, the console asks for it")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return Target{}, errors.New("URL parameters are not supported (a password never goes in the URL); remove everything after ? or #")
	}
	db := strings.TrimPrefix(u.Path, "/")
	if strings.Contains(db, "/") {
		return Target{}, errors.New("the URL path must be a single database name")
	}
	t := Target{Engine: engine, Host: u.Hostname(), User: u.User.Username(), Database: db, Port: DefaultPort(engine)}
	// A password with a '/' or an encoded ':' parses as a port, a path or a
	// user name: the step-by-step checks catch what it leaves behind.
	switch {
	case !validUser(t.User):
		return Target{}, errors.New("the URL user name holds '@', ':', '/' or spaces: leave any password out, the console asks for it")
	case !validHost(t.Host):
		return Target{}, errors.New("the URL host is not a name or an address")
	case !validDatabase(t.Database):
		return Target{}, errors.New("the URL database name holds '/', '@', ';' or spaces: leave any password out, the console asks for it")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Target{}, fmt.Errorf("port out of range")
		}
		t.Port = n
	}
	return t, nil
}
