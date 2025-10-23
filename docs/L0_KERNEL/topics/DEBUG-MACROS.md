# L0 Topic: Debug Macros

CEP wraps much of its diagnostic scaffolding in macros so release builds stay lean while debug builds keep every guardrail. This topic explains how those wrappers behave so you can keep your control flow predictable when toggling between debug and non-debug configurations.

## Technical Details

- `CEP_DEBUG(code)` lives in `src/l0_kernel/cep_molecule.h` and compiles the wrapped `code` only when `NDEBUG` is *not* defined. In non-debug builds it disappears entirely, so never rely on it to run cleanup paths, advance state machines, or mutate data structures that must execute in production.
- `CEP_ASSERT(expr)` always evaluates `expr` and returns its boolean value so you can keep it inside `if`, `while`, or ternary clauses. Debug builds assert on failure via `<assert.h>`; non-debug builds simply forward the expression so control-flow semantics stay identical.
- `CEP_NOT_ASSERT(expr)` inverts `CEP_ASSERT(expr)` and is a drop-in replacement for `!(expr)` when you want the same assertion checks in debug builds. There is no `CEP_NON_ASSERT` alias; code should use `CEP_NOT_ASSERT` consistently.
- Because `CEP_ASSERT` returns the expression's truthiness, prefer side-effect-free predicates. If the predicate must perform work (e.g., calling a validator), make sure that work is safe to repeat and remains required in production.

## Global Q&A

- **Can I gate a whole debug-only block with `if (CEP_DEBUG(...))`?** No. `CEP_DEBUG` has no return value and removes its payload in non-debug builds; wrap the block directly in `CEP_DEBUG({ ...; })` instead.
- **Is it safe to keep release-critical logic inside `CEP_DEBUG`?** Only if losing that logic in production is acceptable. Anything that must happen in every build should live outside the macro.
- **How do I log without tripping compile-time guards?** Use `CEP_DEBUG_PRINTF*` helpers; they follow the same `CEP_ENABLE_DEBUG` switch and keep format strings available only when needed.
- **Why do conditions like `if CEP_NOT_ASSERT(data)` compile?** The macro expands to a boolean expression, so it slots into control-flow syntax. During debug runs it will assert if `data` resolves truthy, mirroring the intent while still returning a value you can branch on.
