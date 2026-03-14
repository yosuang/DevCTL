package kit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"devctl/pkg/home"
)

// SecretGetter retrieves a secret value by key.
type SecretGetter func(ctx context.Context, key string) (string, error)

var (
	placeholderRe = regexp.MustCompile(`\{\{([^}]+)\}\}`)
	validInnerRe  = regexp.MustCompile(`^(var|vault|env)\.([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)$`)
)

const escapeSentinel = "\x00DEVCTL_ESC\x00"

// CompileTemplate compiles a template string by replacing placeholders with values.
func CompileTemplate(ctx context.Context, content string, vars map[string]string, getSecret SecretGetter) (string, error) {
	// Step 1: Replace escaped \{{ with sentinel
	work := strings.ReplaceAll(content, `\{{`, escapeSentinel)

	// Step 2: Validate all placeholders
	var syntaxErrors []string
	for _, match := range placeholderRe.FindAllStringSubmatch(work, -1) {
		if !validInnerRe.MatchString(match[1]) {
			syntaxErrors = append(syntaxErrors, "{{"+match[1]+"}}")
		}
	}
	if len(syntaxErrors) > 0 {
		return "", fmt.Errorf("%w: %s", ErrInvalidPlaceholder, strings.Join(syntaxErrors, ", "))
	}

	// Step 3: Resolve placeholders
	var missing []string
	result := placeholderRe.ReplaceAllStringFunc(work, func(m string) string {
		inner := placeholderRe.FindStringSubmatch(m)[1]
		parts := strings.SplitN(inner, ".", 2)
		prefix, varName := parts[0], parts[1]

		switch prefix {
		case "var":
			if val, ok := vars[varName]; ok {
				return val
			}
			missing = append(missing, "var."+varName)
		case "vault":
			if getSecret == nil {
				missing = append(missing, "vault."+varName)
				return m
			}
			val, err := getSecret(ctx, varName)
			if err != nil {
				missing = append(missing, "vault."+varName)
				return m
			}
			return val
		case "env":
			if val, ok := os.LookupEnv(varName); ok {
				return val
			}
			missing = append(missing, "env."+varName)
		}
		return m
	})

	if len(missing) > 0 {
		return "", fmt.Errorf("%w: %s", ErrMissingVariables, strings.Join(missing, ", "))
	}

	// Step 4: Replace sentinel back with {{
	result = strings.ReplaceAll(result, escapeSentinel, "{{")

	return result, nil
}

// Compile compiles a single tracked config by name.
func (k *Kit) Compile(ctx context.Context, name string, getSecret SecretGetter) error {
	m, err := k.Load()
	if err != nil {
		return err
	}

	cfg, ok := m.Configs[name]
	if !ok {
		return ErrNotTracked
	}

	state, _ := k.loadCompileState()
	if state == nil {
		state = compileState{}
	}

	if err := k.compileEntry(ctx, name, cfg, m.Vars, getSecret, state); err != nil {
		return err
	}
	return k.saveCompileState(state)
}

// CompileAll compiles all tracked configs independently.
// Failures in one template do not block others.
func (k *Kit) CompileAll(ctx context.Context, getSecret SecretGetter) (successes []string, failures map[string]error) {
	m, err := k.Load()
	if err != nil {
		return nil, map[string]error{"manifest": err}
	}

	state, _ := k.loadCompileState()
	if state == nil {
		state = compileState{}
	}

	failures = make(map[string]error)
	for name, cfg := range m.Configs {
		if err := k.compileEntry(ctx, name, cfg, m.Vars, getSecret, state); err != nil {
			failures[name] = err
		} else {
			successes = append(successes, name)
		}
	}

	if err := k.saveCompileState(state); err != nil {
		failures["compile-state"] = err
	}

	sort.Strings(successes)
	return successes, failures
}

func (k *Kit) compileEntry(ctx context.Context, name string, cfg ConfigEntry, vars map[string]string, getSecret SecretGetter, state compileState) error {
	sourcePath := filepath.Join(k.dir, cfg.Source)
	targetPath := home.Long(cfg.Target)

	info, err := os.Stat(sourcePath)
	if err != nil {
		return fmt.Errorf("reading source %s: %w", cfg.Source, err)
	}

	var allContent []byte
	if info.IsDir() {
		allContent, err = k.compileDirFiles(ctx, sourcePath, targetPath, vars, getSecret)
	} else {
		allContent, err = k.compileSingleFile(ctx, sourcePath, targetPath, vars, getSecret)
	}
	if err != nil {
		return err
	}

	hash := sha256.Sum256(allContent)
	state[name] = compileRecord{
		Hash:       fmt.Sprintf("sha256:%x", hash),
		CompiledAt: time.Now().UTC().Format(time.RFC3339),
	}
	return nil
}

func (k *Kit) compileSingleFile(ctx context.Context, source, target string, vars map[string]string, getSecret SecretGetter) ([]byte, error) {
	content, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("reading template: %w", err)
	}

	compiled, err := CompileTemplate(ctx, string(content), vars, getSecret)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(target), dirPerm); err != nil {
		return nil, fmt.Errorf("creating target directory: %w", err)
	}
	if err := os.WriteFile(target, []byte(compiled), filePerm); err != nil {
		return nil, fmt.Errorf("writing target: %w", err)
	}

	return []byte(compiled), nil
}

func (k *Kit) compileDirFiles(ctx context.Context, sourceDir, targetDir string, vars map[string]string, getSecret SecretGetter) ([]byte, error) {
	var allContent bytes.Buffer
	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, _ := filepath.Rel(sourceDir, path)
		targetPath := filepath.Join(targetDir, rel)

		if d.IsDir() {
			return os.MkdirAll(targetPath, dirPerm)
		}

		compiled, err := k.compileSingleFile(ctx, path, targetPath, vars, getSecret)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		allContent.Write(compiled)
		return nil
	})
	return allContent.Bytes(), err
}

// ConfigState represents the compilation state of a config.
type ConfigState string

const (
	ConfigStateCompiled   ConfigState = "compiled"
	ConfigStateOutdated   ConfigState = "outdated"
	ConfigStateUncompiled ConfigState = "uncompiled"
)

// ConfigStatus represents the compilation status of a tracked config.
type ConfigStatus struct {
	Name   string
	Source string
	Target string
	State  ConfigState
}

// ConfigStatuses returns the compilation status of all tracked configs.
func (k *Kit) ConfigStatuses() ([]ConfigStatus, error) {
	m, err := k.Load()
	if err != nil {
		return nil, err
	}

	state, err := k.loadCompileState()
	if err != nil {
		return nil, err
	}

	var statuses []ConfigStatus
	for name, cfg := range m.Configs {
		s := ConfigStatus{
			Name:   name,
			Source: cfg.Source,
			Target: cfg.Target,
		}

		record, ok := state[name]
		if !ok {
			s.State = ConfigStateUncompiled
		} else {
			compiledAt, err := time.Parse(time.RFC3339, record.CompiledAt)
			if err != nil {
				s.State = ConfigStateUncompiled
			} else {
				sourcePath := filepath.Join(k.dir, cfg.Source)
				if isOutdated(sourcePath, compiledAt) {
					s.State = ConfigStateOutdated
				} else {
					s.State = ConfigStateCompiled
				}
			}
		}
		statuses = append(statuses, s)
	}

	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Name < statuses[j].Name
	})
	return statuses, nil
}

func isOutdated(path string, compiledAt time.Time) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}

	if !info.IsDir() {
		// Truncate to second precision to match RFC3339 stored timestamps
		return info.ModTime().Truncate(time.Second).After(compiledAt)
	}

	outdated := false
	filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if fi.ModTime().Truncate(time.Second).After(compiledAt) {
			outdated = true
			return filepath.SkipAll
		}
		return nil
	})
	return outdated
}
