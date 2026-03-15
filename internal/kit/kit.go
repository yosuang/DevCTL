package kit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"devctl/pkg/pkgmgr"
)

const (
	manifestFile     = "kit.json"
	compileStateFile = ".compile-state.json"
	configsDir       = "configs"
	dirPerm          = 0755
	filePerm         = 0644
)

var keyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)

type Manifest struct {
	Vars     map[string]string         `json:"vars"`
	Packages map[string][]PackageEntry `json:"packages"`
	Configs  map[string]ConfigEntry    `json:"configs"`
}

type PackageEntry struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Manager string `json:"manager,omitempty"`
}

type ConfigEntry struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type compileState map[string]compileRecord

type compileRecord struct {
	Hash       string `json:"hash"`
	CompiledAt string `json:"compiled_at"`
}

type Kit struct {
	dir string
}

func New(dir string) *Kit {
	return &Kit{dir: dir}
}

func (k *Kit) Dir() string {
	return k.dir
}

func (k *Kit) ManifestPath() string {
	return filepath.Join(k.dir, manifestFile)
}

func (k *Kit) ConfigsDir() string {
	return filepath.Join(k.dir, configsDir)
}

func (k *Kit) compileStatePath() string {
	return filepath.Join(k.dir, compileStateFile)
}

func (k *Kit) Load() (*Manifest, error) {
	data, err := os.ReadFile(k.ManifestPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrManifestNotFound
		}
		return nil, fmt.Errorf("reading kit manifest: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing kit manifest: %w", err)
	}
	if m.Vars == nil {
		m.Vars = make(map[string]string)
	}
	if m.Packages == nil {
		m.Packages = make(map[string][]PackageEntry)
	}
	if m.Configs == nil {
		m.Configs = make(map[string]ConfigEntry)
	}
	return &m, nil
}

func (k *Kit) Save(m *Manifest) error {
	if err := os.MkdirAll(k.dir, dirPerm); err != nil {
		return fmt.Errorf("creating kit directory: %w", err)
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling kit manifest: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(k.ManifestPath(), data, filePerm); err != nil {
		return fmt.Errorf("writing kit manifest: %w", err)
	}
	return nil
}

func (k *Kit) loadOrInit() (*Manifest, error) {
	m, err := k.Load()
	if errors.Is(err, ErrManifestNotFound) {
		return &Manifest{
			Vars:     make(map[string]string),
			Packages: make(map[string][]PackageEntry),
			Configs:  make(map[string]ConfigEntry),
		}, nil
	}
	return m, err
}

func (k *Kit) SetVar(key, value string) error {
	if !keyPattern.MatchString(key) {
		return ErrInvalidKeyName
	}

	m, err := k.loadOrInit()
	if err != nil {
		return err
	}
	m.Vars[key] = value
	return k.Save(m)
}

func (k *Kit) UnsetVar(key string) error {
	if !keyPattern.MatchString(key) {
		return ErrInvalidKeyName
	}

	m, err := k.Load()
	if err != nil {
		return err
	}
	if _, ok := m.Vars[key]; !ok {
		return fmt.Errorf("variable %s not found", key)
	}
	delete(m.Vars, key)
	return k.Save(m)
}

func (k *Kit) AddPackage(name, version, group, manager string) error {
	if group == "" {
		group = "base"
	}

	m, err := k.loadOrInit()
	if err != nil {
		return err
	}

	for _, p := range m.Packages[group] {
		if p.Name == name {
			return ErrPackageExists
		}
	}

	m.Packages[group] = append(m.Packages[group], PackageEntry{
		Name:    name,
		Version: version,
		Manager: manager,
	})
	return k.Save(m)
}

func (k *Kit) RemovePackage(name, group string) error {
	if group == "" {
		group = "base"
	}

	m, err := k.Load()
	if err != nil {
		return err
	}

	packages, ok := m.Packages[group]
	if !ok {
		return ErrPackageNotFound
	}

	found := false
	filtered := make([]PackageEntry, 0, len(packages))
	for _, p := range packages {
		if p.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, p)
	}
	if !found {
		return ErrPackageNotFound
	}

	if len(filtered) == 0 {
		delete(m.Packages, group)
	} else {
		m.Packages[group] = filtered
	}
	return k.Save(m)
}

// PackageStatus represents the install status of a package.
type PackageStatus struct {
	Name             string
	Version          string
	Installed        bool
	InstalledVersion string
}

// CheckPackageStatuses compares desired packages against installed ones.
func CheckPackageStatuses(desired []PackageEntry, installed []pkgmgr.Package) []PackageStatus {
	installedMap := make(map[string]string, len(installed))
	for _, p := range installed {
		installedMap[p.Name] = p.Version
	}

	statuses := make([]PackageStatus, 0, len(desired))
	for _, d := range desired {
		s := PackageStatus{
			Name:    d.Name,
			Version: d.Version,
		}
		if v, ok := installedMap[d.Name]; ok {
			s.Installed = true
			s.InstalledVersion = v
		}
		statuses = append(statuses, s)
	}
	return statuses
}

func (k *Kit) loadCompileState() (compileState, error) {
	data, err := os.ReadFile(k.compileStatePath())
	if err != nil {
		if os.IsNotExist(err) {
			return compileState{}, nil
		}
		return nil, fmt.Errorf("reading compile state: %w", err)
	}

	var state compileState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing compile state: %w", err)
	}
	return state, nil
}

func (k *Kit) saveCompileState(state compileState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling compile state: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(k.compileStatePath(), data, filePerm)
}

// ListVars returns sorted variable keys and their values.
func (k *Kit) ListVars() (keys []string, vals []string, err error) {
	m, err := k.Load()
	if err != nil {
		return nil, nil, err
	}

	keys = make([]string, 0, len(m.Vars))
	for key := range m.Vars {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	vals = make([]string, 0, len(keys))
	for _, key := range keys {
		vals = append(vals, m.Vars[key])
	}
	return keys, vals, nil
}
