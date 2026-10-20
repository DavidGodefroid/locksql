package sqlrefusal

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// constructors are the functions that build a refusal, and the index of
// their code argument.
var constructors = map[string]int{
	"refuse":       0, // sqlclass, sqlast
	"refusef":      0,
	"refuseAt":     1, // sqlclass: refuseAt(tok, code, reason)
	"refusal.New":  0,
	"refusal.Newf": 0,
	"New":          0, // inside this package
	"Newf":         0,
}

// codeNames reads the Code constants declared in refusal.go.
func codeNames(t *testing.T) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "refusal.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, sp := range g.Specs {
			vs := sp.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); ok && id.Name == "Code" {
				for _, n := range vs.Names {
					names[n.Name] = true
				}
			}
		}
	}
	// A retired code is declared but never emitted: a site passing it
	// fails below.
	delete(names, "KAnon")
	if len(names) != len(Codes()) {
		t.Fatalf("refusal.go declares %d codes, Codes lists %d", len(names), len(Codes()))
	}
	return names
}

func callName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
	}
	return ""
}

// TestEveryRefusalSiteHasACode enumerates every place the code base builds
// a refusal: each passes a declared code other than the fail-closed
// Policy, no refusal is built as a bare struct, and only the console's
// refusedResp answers with ipc.CodeRefused. A refusal path without a code
// fails here.
func TestEveryRefusalSiteHasACode(t *testing.T) {
	codes := codeNames(t)
	sites := 0
	fset := token.NewFileSet()
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "site" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && path != "../.." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		inRefusal := f.Name.Name == "refusal"
		var fn string
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				fn = n.Name.Name
			case *ast.CallExpr:
				name := callName(n)
				i, ok := constructors[name]
				if !ok || (!inRefusal && (name == "New" || name == "Newf")) || (inRefusal && fn != "" && strings.HasPrefix(name, "refuse")) {
					return true
				}
				if fn == "refuse" || fn == "refusef" || fn == "refuseAt" || (inRefusal && (fn == "New" || fn == "Newf" || fn == "From")) {
					return true // the constructors themselves pass their argument on
				}
				sites++
				pos := fset.Position(n.Pos())
				if len(n.Args) <= i {
					t.Errorf("%s: %s without a code", pos, name)
					return true
				}
				var code string
				switch a := n.Args[i].(type) {
				case *ast.SelectorExpr:
					if x, ok := a.X.(*ast.Ident); ok && x.Name == "refusal" {
						code = a.Sel.Name
					}
				case *ast.Ident:
					if inRefusal {
						code = a.Name
					}
				}
				if !codes[code] || code == "Policy" {
					t.Errorf("%s: %s with code %q: pass a declared refusal code", pos, name, code)
				}
			case *ast.CompositeLit:
				if inRefusal {
					return true
				}
				var typ string
				switch x := n.Type.(type) {
				case *ast.Ident:
					typ = x.Name
				case *ast.SelectorExpr:
					typ = x.Sel.Name
				}
				if typ == "Refusal" || typ == "Error" && strings.Contains(path, "refusal") {
					t.Errorf("%s: a refusal built as a struct: use a constructor with a code", fset.Position(n.Pos()))
				}
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok && x.Name == "ipc" && n.Sel.Name == "CodeRefused" &&
					strings.Contains(path, "internal/console") && fn != "refusedResp" {
					t.Errorf("%s: ipc.CodeRefused outside refusedResp: every refusal goes through it", fset.Position(n.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if sites < 200 {
		t.Fatalf("only %d refusal sites found: the walk misses files", sites)
	}
	t.Logf("%d refusal sites", sites)
}
