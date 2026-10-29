package console

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// sessionOptional are the optional interfaces of package engine that the
// console finds on a session by a type assertion. A wrapper that embeds
// engine.Session hides them unless it passes each on.
//
// The console's own optional interfaces, DBUser and CredentialsExpire,
// are not here: only vaultSession has them, and it is the outermost
// wrapper (connect wraps it last). Passing them through other wrappers
// would change what a session without them reports.
var sessionOptional = []reflect.Type{
	reflect.TypeFor[engine.Noticer](),
	reflect.TypeFor[engine.FunctionShadows](),
	reflect.TypeFor[engine.ObjectGuard](),
}

// notSessionOptional are the other interfaces of package engine.
var notSessionOptional = []string{"Session", "Engine", "TLSProber"}

// wrapperGaps parses the Go files of src (file name -> source) and lists,
// for each struct type that embeds engine.Session, the methods of the
// optional interfaces it does not declare.
func wrapperGaps(t *testing.T, src map[string]string) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	wrappers := map[string]bool{}
	methods := map[string]map[string]bool{}
	for name, code := range src {
		f, err := parser.ParseFile(fset, name, code, 0)
		if err != nil {
			t.Fatal(err)
		}
		// The name the file gives package engine, alias included.
		pkg := "engine"
		for _, im := range f.Imports {
			if strings.Trim(im.Path.Value, `"`) == "github.com/DavidGodefroid/locksql/internal/engine" && im.Name != nil {
				pkg = im.Name.Name
			}
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, fl := range st.Fields.List {
						ft := fl.Type
						if star, ok := ft.(*ast.StarExpr); ok {
							ft = star.X
						}
						if sel, ok := ft.(*ast.SelectorExpr); ok && len(fl.Names) == 0 && sel.Sel.Name == "Session" {
							if id, ok := sel.X.(*ast.Ident); ok && id.Name == pkg {
								wrappers[ts.Name.Name] = true
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) == 0 {
					continue
				}
				rt := d.Recv.List[0].Type
				if star, ok := rt.(*ast.StarExpr); ok {
					rt = star.X
				}
				if id, ok := rt.(*ast.Ident); ok {
					if methods[id.Name] == nil {
						methods[id.Name] = map[string]bool{}
					}
					methods[id.Name][d.Name.Name] = true
				}
			}
		}
	}
	gaps := map[string][]string{}
	for w := range wrappers {
		for _, it := range sessionOptional {
			for i := 0; i < it.NumMethod(); i++ {
				if m := it.Method(i).Name; !methods[w][m] {
					gaps[w] = append(gaps[w], it.Name()+"."+m)
				}
			}
		}
	}
	return gaps
}

func packageSources(t *testing.T, dir string, tests bool) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range files {
		if !tests && strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[f] = string(b)
	}
	return out
}

// Every session wrapper of the console (SSH tunnel, proxy_command, Vault
// login, ...) passes each optional engine interface on: one that does not
// hides it, and the console then fails closed on every statement (#80).
func TestSessionWrappersPassOptionalInterfacesOn(t *testing.T) {
	gaps := wrapperGaps(t, packageSources(t, ".", false))
	for _, w := range slices.Sorted(maps.Keys(gaps)) {
		t.Errorf("%s embeds engine.Session but does not declare %s: pass it on like tunneledSession", w, strings.Join(gaps[w], ", "))
	}
}

// Every interface of package engine is placed: a new optional session
// interface must join sessionOptional.
func TestEngineInterfacesPlaced(t *testing.T) {
	fset := token.NewFileSet()
	var found []string
	for name, code := range packageSources(t, filepath.Join("..", "engine"), false) {
		f, err := parser.ParseFile(fset, name, code, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if ts, ok := n.(*ast.TypeSpec); ok {
				if _, ok := ts.Type.(*ast.InterfaceType); ok && ts.Name.IsExported() {
					found = append(found, ts.Name.Name)
				}
			}
			return true
		})
	}
	sort.Strings(found)
	for _, name := range found {
		placed := slices.Contains(notSessionOptional, name)
		for _, it := range sessionOptional {
			placed = placed || it.Name() == name
		}
		if !placed {
			t.Errorf("engine.%s: add it to sessionOptional (sessions may implement it) or notSessionOptional", name)
		}
	}
}

// The guard catches a wrapper that misses an interface.
func TestWrapperGapsDetects(t *testing.T) {
	src := map[string]string{"x.go": `package console
type fullWrap struct{ engine.Session }
func (s *fullWrap) Notices() []string { return nil }
func (s *fullWrap) ShadowedFunctions() {}
func (s *fullWrap) ShadowedOperators() {}
func (s *fullWrap) ObjectState() {}
func (s *fullWrap) RunGuarded() {}
type halfWrap struct {
	engine.Session
	host string
}
func (s halfWrap) Notices() []string { return nil }
type notWrap struct{ s engine.Session }
`, "y.go": `package console
import eng "github.com/DavidGodefroid/locksql/internal/engine"
type aliasWrap struct{ *eng.Session }
func (s *aliasWrap) Notices() []string { return nil }
`}
	gaps := wrapperGaps(t, src)
	want := []string{"FunctionShadows.ShadowedFunctions", "FunctionShadows.ShadowedOperators", "ObjectGuard.ObjectState", "ObjectGuard.RunGuarded"}
	if len(gaps) != 2 || !slices.Equal(gaps["halfWrap"], want) || !slices.Equal(gaps["aliasWrap"], want) {
		t.Fatalf("gaps = %v", gaps)
	}
}
