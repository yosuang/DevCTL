### STRUCTURE
```
devctl/
├── cmd/devctl/            # Application entry points
├── internal/              # Private application code
│   ├── cmd/               # Command implementations (Cobra)
│   └── logging/           # Custom logging infrastructure
├── pkg/                   # Public library code (reusable)
│   ├── cli/               # CLI utilities
│   └── cmdutil/           # Command utilities
└── scripts/               # Build and automation scripts
```

## TDD (Test-Driven Development)

**MANDATORY for new features and bug fixes.** Follow RED-GREEN-REFACTOR:

```
1. RED    - Write failing test first (test MUST fail)
2. GREEN  - Write MINIMAL code to pass (nothing more)
3. REFACTOR - Clean up while tests stay GREEN
4. REPEAT - Next test case
```

| Phase | Action | Verification                         |
|-------|--------|--------------------------------------|
| **RED** | Write test describing expected behavior | `go test` -> FAIL (expected)         |
| **GREEN** | Implement minimum code to pass | `go test` -> PASS                    |
| **REFACTOR** | Improve code quality, remove duplication | `go test` -> PASS (must stay green) |

**Rules:**
- NEVER write implementation before test
- NEVER delete failing tests to "pass" - fix the code
- One test at a time - don't batch
- Test file naming: `*_test.go` alongside source
- BDD comments: `#given`, `#when`, `#then` (same as AAA)

## CONVENTIONS

- **Build**: `go run scripts/build.go`
- **Testing**: BDD comments `#given/#when/#then`, TDD workflow (RED-GREEN-REFACTOR)
