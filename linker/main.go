package main

// WARNING: currently this is just a prototype for feedback on an eventual contribution.
// it is not intended to be fully functional, nor is the code design/layout production-ready.

// We need to disallow unknown imports, e.g. data.lib[_].dupe[a]
// as it will be hard to rewrite those into the appropriate
// anonymous rules.

// We should ignore prefixes like data.inventory and disallow
// package statements using those reserved prefixes

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/util"
)

var localReg = regexp.MustCompile(`__local([0-9]+)__`)

type uniquifier struct {
	idx   int
	rules map[string]string
}

func newUniquifier() *uniquifier {
	return &uniquifier{
		rules: map[string]string{},
	}
}

// This should take a hint from the Rego compiler's local var generator.
// We should keep an index of existing vars in the un-mangled code
// to prevent conflicts: https://github.com/open-policy-agent/opa/blob/575f6df8e2276a1597fc45cc14cab5f74f1a5be6/ast/compile.go#L1899
func (u *uniquifier) get(s string) string {
	if a, ok := u.rules[s]; ok {
		return a
	}
	a := fmt.Sprintf("__deprule%d__", u.idx)
	u.rules[s] = a
	u.idx++
	return a
}

type depsByPath struct {
	deps map[string]map[*ast.Rule]bool
}

func (d *depsByPath) add(s string, r *ast.Rule) {
	if _, ok := d.deps[s]; ok {
		d.deps[s][r] = true
		return
	}
	d.deps[s] = map[*ast.Rule]bool{}
	d.deps[s][r] = true
}

func newDepsByPath() *depsByPath {
	return &depsByPath{
		deps: map[string]map[*ast.Rule]bool{},
	}
}

func main() {
	files := []string{
		"lib.rego",
		"lib2.rego",
		"src.rego",
	}

	// Read source files
	modules := map[string]*ast.Module{}
	for _, v := range files {
		s, err := ioutil.ReadFile(v)
		if err != nil {
			panic(err)
		}
		p, err := ast.ParseModule(v, string(s))
		if err != nil {
			panic(err)
		}
		modules[v] = p
	}
	c := ast.NewCompiler()
	c.Compile(modules)
	if c.Failed() {
		panic(c.Errors)
	}

	// Gather dependencies by their fully-qualified path. Note that
	// because of overloading, there may be multiple rules on the
	// same path.
	depsByPath := newDepsByPath()
	var entryPoints []*ast.Rule
	c.RuleTree.DepthFirst(func(n *ast.TreeNode) bool {
		for _, val := range n.Values {
			r := val.(*ast.Rule)

			// Entry point is a rule name and would likely be provided
			// by the user. In GK all entry points are currently "violation".
			// Note that it is possible to overload the
			// entry point, causing more than one rule to match
			if r.Path().String() == "data.src.entry" {
				entryPoints = append(entryPoints, r)
				// I made the NewGraphTraversal function public
				tr := ast.NewGraphTraversal(c.Graph)
				util.DFS(tr, func(u util.T) bool {
					if dep, ok := u.(*ast.Rule); ok {
						// No self-reference
						if dep == r {
							return false
						}
						// fmt.Println(dep.Path().String())
						// fmt.Println(dep.String())
						// fmt.Println("\n\n=======\n\n")
						depsByPath.add(dep.Path().String(), dep)
					}
					return false
				}, r)
			}
		}
		return false
	})

	// Replace every reference to a dependency with a globally unique name
	uniquifier := newUniquifier()
	for _, deps := range depsByPath.deps {
		for dep := range deps {
			ast.WalkTerms(dep, func(t *ast.Term) bool {
				switch ref := t.Value.(type) {
				case ast.Var:
					// Renaming __local#__ variables in case it would cause issues with the compiler.
					// Looking at the local variable generation code, this shouldn't be the case, though
					// preserving __locall#__ could cause a performance hit as the compiler iterates until it
					// finds a unique value. We should also be sure our re-written variables are locally unique
					// (not currently happening)
					if localReg.Match([]byte(ref.String())) {
						ref = ast.Var(string(localReg.ReplaceAll([]byte(ref.String()), []byte(`__l${1}__`))))
						t.Value = ref
					}
				case ast.Ref:
					if ref, ok := t.Value.(ast.Ref); ok {
						// It's possible to have a valid variable ref like data.library.my_rule[x]
						prefix := ref.ConstantPrefix()
						if _, ok := depsByPath.deps[prefix.String()]; ok {
							r := ast.EmptyRef()
							r = r.Append(ast.VarTerm(uniquifier.get(prefix.String())))
							if len(ref) > len(prefix) {
								suffix := ref[len(prefix):]
								r = r.Concat(suffix)
							}
							t.Value = r
						}
					}
				}
				return false
			})
		}
	}

	// should use a string builder here, instead of appending strings
	output := "package arbitrary_name\n\n"

	// Rewrite references to dependencies on the entry point. The entry point's name should be unchanged
	for _, r := range entryPoints {
		ast.WalkTerms(r, func(t *ast.Term) bool {
			switch ref := t.Value.(type) {
			case ast.Var:
				// same concern about __local#__ vars
				if localReg.Match([]byte(ref.String())) {
					ref = ast.Var(string(localReg.ReplaceAll([]byte(ref.String()), []byte(`__l${1}__`))))
					t.Value = ref
				}
			case ast.Ref:
				if ref, ok := t.Value.(ast.Ref); ok {
					prefix := ref.ConstantPrefix()
					if _, ok := depsByPath.deps[prefix.String()]; ok {
						r := ast.EmptyRef()
						r = r.Append(ast.VarTerm(uniquifier.get(prefix.String())))
						if len(ref) > len(prefix) {
							suffix := ref[len(prefix):]
							r = r.Concat(suffix)
						}
						t.Value = r
					}
				}
			}
			return false
		})
		// Entry point is done. Place at top of output
		output += r.String() + "\n\n"
	}

	// Rename dependencies with their new unique name and add to output
	for path, deps := range depsByPath.deps {
		for dep := range deps {
			dep.Head.Name = ast.Var(uniquifier.get(path))
			output += dep.String() + "\n\n"
		}
	}

	// Done! ... ?
	fmt.Println(output)
}
