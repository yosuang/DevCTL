package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"filippo.io/age"
)

const (
	identityFile = "identity"
	vaultFile    = "vault.age"
	dirPerm      = 0700
	filePerm     = 0600
	envSecretKey = "DEVCTL_SECRET_KEY"
)

var keyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)

type Vault struct {
	dir string
}

func New(dir string) *Vault {
	return &Vault{dir: dir}
}

func (v *Vault) Init() error {
	if _, err := os.Stat(v.vaultPath()); err == nil {
		return ErrVaultExists
	}

	if err := os.MkdirAll(v.dir, dirPerm); err != nil {
		return fmt.Errorf("creating vault directory: %w", err)
	}

	// Skip generating identity file when env var provides the key
	if os.Getenv(envSecretKey) == "" {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return fmt.Errorf("generating identity: %w", err)
		}

		identityData := identity.String() + "\n"
		if err := os.WriteFile(v.identityPath(), []byte(identityData), filePerm); err != nil {
			return fmt.Errorf("writing identity: %w", err)
		}
	}

	empty := map[string]string{}
	return v.save(empty)
}

func (v *Vault) Set(key, value string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := v.requireInitialized(); err != nil {
		return err
	}

	secrets, err := v.load()
	if err != nil {
		return err
	}

	secrets[key] = value
	return v.save(secrets)
}

func (v *Vault) Get(_ context.Context, key string) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	if err := v.requireInitialized(); err != nil {
		return "", err
	}

	secrets, err := v.load()
	if err != nil {
		return "", err
	}

	val, ok := secrets[key]
	if !ok {
		return "", ErrKeyNotFound
	}
	return val, nil
}

func (v *Vault) Delete(key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := v.requireInitialized(); err != nil {
		return err
	}

	secrets, err := v.load()
	if err != nil {
		return err
	}

	if _, ok := secrets[key]; !ok {
		return ErrKeyNotFound
	}

	delete(secrets, key)
	return v.save(secrets)
}

func (v *Vault) List() ([]string, error) {
	if err := v.requireInitialized(); err != nil {
		return nil, err
	}

	secrets, err := v.load()
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// --- internal helpers ---

func validateKey(key string) error {
	if !keyPattern.MatchString(key) {
		return ErrInvalidKeyName
	}
	return nil
}

func (v *Vault) identityPath() string {
	return filepath.Join(v.dir, identityFile)
}

func (v *Vault) vaultPath() string {
	return filepath.Join(v.dir, vaultFile)
}

func (v *Vault) loadIdentity() (*age.X25519Identity, error) {
	if envKey := os.Getenv(envSecretKey); envKey != "" {
		return parseIdentity([]byte(envKey))
	}

	data, err := os.ReadFile(v.identityPath())
	if err != nil {
		return nil, fmt.Errorf("reading identity: %w", err)
	}
	return parseIdentity(data)
}

func parseIdentity(data []byte) (*age.X25519Identity, error) {
	identities, err := age.ParseIdentities(bytes.NewReader(bytes.TrimSpace(data)))
	if err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}

	id, ok := identities[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("unexpected identity type")
	}
	return id, nil
}

func (v *Vault) encrypt(data []byte) ([]byte, error) {
	identity, err := v.loadIdentity()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, identity.Recipient())
	if err != nil {
		return nil, fmt.Errorf("creating encryptor: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalizing encryption: %w", err)
	}
	return buf.Bytes(), nil
}

func (v *Vault) decrypt(data []byte) ([]byte, error) {
	identity, err := v.loadIdentity()
	if err != nil {
		return nil, err
	}

	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
	}
	return plain, nil
}

func (v *Vault) load() (map[string]string, error) {
	ciphertext, err := os.ReadFile(v.vaultPath())
	if err != nil {
		return nil, fmt.Errorf("reading vault: %w", err)
	}

	plaintext, err := v.decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("parsing vault data: %w", err)
	}
	return secrets, nil
}

func (v *Vault) save(secrets map[string]string) error {
	data, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("marshaling secrets: %w", err)
	}

	ciphertext, err := v.encrypt(data)
	if err != nil {
		return err
	}

	return atomicWrite(v.vaultPath(), ciphertext)
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vault-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Chmod(tmpName, filePerm); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("setting file permissions: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming temp file: %w", err)
	}
	return nil
}

func (v *Vault) requireInitialized() error {
	hasIdentity := os.Getenv(envSecretKey) != ""
	if !hasIdentity {
		_, err := os.Stat(v.identityPath())
		hasIdentity = err == nil
	}
	if !hasIdentity {
		return ErrIdentityNotFound
	}

	if _, err := os.Stat(v.vaultPath()); err != nil {
		return ErrVaultNotFound
	}
	return nil
}
