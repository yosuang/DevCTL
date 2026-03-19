package vault

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	// #given: 一个空目录
	t.Setenv(envSecretKey, "")
	v := New(filepath.Join(t.TempDir(), "vault"))

	// #when: 初始化 vault
	err := v.Init()

	// #then: 成功且文件存在
	require.NoError(t, err)
	require.FileExists(t, v.identityPath())
	require.FileExists(t, v.vaultPath())
}

func TestInit_VaultExists(t *testing.T) {
	// #given: a vault that already exists
	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())

	// #when: init again
	err := v.Init()

	// #then: returns ErrVaultExists
	require.ErrorIs(t, err, ErrVaultExists)
}

func TestSetGet(t *testing.T) {
	// #given: 一个已初始化的 vault
	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())

	// #when: 设置并获取一个 key
	require.NoError(t, v.Set("MY_TOKEN", "secret123"))
	got, err := v.Get(context.Background(), "MY_TOKEN")

	// #then: 返回设置的值
	require.NoError(t, err)
	require.Equal(t, "secret123", got)
}

func TestSet_OverwriteExisting(t *testing.T) {
	// #given: 一个已设置值的 vault
	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())
	require.NoError(t, v.Set("MY_TOKEN", "old_value"))

	// #when: 覆盖已有的 key
	require.NoError(t, v.Set("MY_TOKEN", "new_value"))
	got, err := v.Get(context.Background(), "MY_TOKEN")

	// #then: 返回新值
	require.NoError(t, err)
	require.Equal(t, "new_value", got)
}

func TestSet_EmptyValue(t *testing.T) {
	// #given: 一个已初始化的 vault
	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())

	// #when: 设置空值
	require.NoError(t, v.Set("EMPTY_KEY", ""))
	got, err := v.Get(context.Background(), "EMPTY_KEY")

	// #then: 成功返回空字符串
	require.NoError(t, err)
	require.Equal(t, "", got)
}

func TestDelete(t *testing.T) {
	// #given: 一个包含 key 的 vault
	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())
	require.NoError(t, v.Set("MY_TOKEN", "secret"))

	// #when: 删除该 key
	err := v.Delete("MY_TOKEN")

	// #then: 删除成功，再次获取返回 ErrKeyNotFound
	require.NoError(t, err)
	_, err = v.Get(context.Background(), "MY_TOKEN")
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestDelete_NotFound(t *testing.T) {
	// #given: 一个空的 vault
	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())

	// #when: 删除不存在的 key
	err := v.Delete("MISSING_KEY")

	// #then: 返回 ErrKeyNotFound
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestList(t *testing.T) {
	// #given: 一个包含多个 key 的 vault
	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())
	require.NoError(t, v.Set("CHARLIE", "c"))
	require.NoError(t, v.Set("ALPHA", "a"))
	require.NoError(t, v.Set("BRAVO", "b"))

	// #when: 列出所有 key
	keys, err := v.List()

	// #then: 按字母排序返回
	require.NoError(t, err)
	require.Equal(t, []string{"ALPHA", "BRAVO", "CHARLIE"}, keys)
}

func TestList_Empty(t *testing.T) {
	// #given: 一个空的 vault
	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())

	// #when: 列出所有 key
	keys, err := v.List()

	// #then: 返回空切片
	require.NoError(t, err)
	require.Empty(t, keys)
}

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{name: "simple key", key: "TOKEN", wantErr: false},
		{name: "key with underscore", key: "MY_TOKEN", wantErr: false},
		{name: "key with numbers", key: "API_KEY_2", wantErr: false},
		{name: "single letter", key: "A", wantErr: false},
		{name: "multiple underscores", key: "A_B_C_D", wantErr: false},
		{name: "lowercase", key: "my_token", wantErr: true},
		{name: "mixed case", key: "My_Token", wantErr: true},
		{name: "kebab case", key: "MY-TOKEN", wantErr: true},
		{name: "starts with number", key: "2FA_CODE", wantErr: true},
		{name: "starts with underscore", key: "_TOKEN", wantErr: true},
		{name: "trailing underscore", key: "TOKEN_", wantErr: true},
		{name: "double underscore", key: "MY__TOKEN", wantErr: true},
		{name: "empty string", key: "", wantErr: true},
		{name: "space in key", key: "MY TOKEN", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// #given: 一个 key 名称
			// #when: 校验 key 格式
			err := validateKey(tt.key)

			// #then: 根据格式返回对应结果
			if tt.wantErr {
				require.ErrorIs(t, err, ErrInvalidKeyName)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestInit_WithEnvKey(t *testing.T) {
	// #given: DEVCTL_SECRET_KEY is set
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	t.Setenv(envSecretKey, identity.String())

	v := New(filepath.Join(t.TempDir(), "vault"))

	// #when: init vault
	err = v.Init()

	// #then: succeeds, vault.age exists but no identity file
	require.NoError(t, err)
	require.NoFileExists(t, v.identityPath())
	require.FileExists(t, v.vaultPath())
}

func TestSetGet_WithEnvKey(t *testing.T) {
	// #given: a vault initialized with DEVCTL_SECRET_KEY
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	t.Setenv(envSecretKey, identity.String())

	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())

	// #when: set and get a key
	require.NoError(t, v.Set("MY_TOKEN", "secret123"))
	got, err := v.Get(context.Background(), "MY_TOKEN")

	// #then: returns the stored value
	require.NoError(t, err)
	require.Equal(t, "secret123", got)
}

func TestInit_WithEnvKey_NoIdentityFile(t *testing.T) {
	// #given: DEVCTL_SECRET_KEY is set
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	t.Setenv(envSecretKey, identity.String())

	v := New(filepath.Join(t.TempDir(), "vault"))

	// #when: init vault
	require.NoError(t, v.Init())

	// #then: vault.age exists but no identity file
	require.NoFileExists(t, v.identityPath())
	require.FileExists(t, v.vaultPath())
}

func TestEnvKey_OverridesFile(t *testing.T) {
	// #given: a vault initialized with file-based identity
	v := New(filepath.Join(t.TempDir(), "vault"))
	require.NoError(t, v.Init())
	require.NoError(t, v.Set("MY_TOKEN", "secret123"))

	// #given: now set a different key via env var
	newIdentity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	t.Setenv(envSecretKey, newIdentity.String())

	// #when: try to decrypt with the env key (which is different from file key)
	_, err = v.Get(context.Background(), "MY_TOKEN")

	// #then: decryption fails because env key overrides file key
	require.Error(t, err)
}

func TestOperations_IdentityNotFound(t *testing.T) {
	// #given: no identity and no vault
	t.Setenv(envSecretKey, "")
	v := New(filepath.Join(t.TempDir(), "vault"))

	// #when/#then: all operations return ErrIdentityNotFound
	require.ErrorIs(t, v.Set("KEY", "val"), ErrIdentityNotFound)

	_, err := v.Get(context.Background(), "KEY")
	require.ErrorIs(t, err, ErrIdentityNotFound)

	require.ErrorIs(t, v.Delete("KEY"), ErrIdentityNotFound)

	_, err = v.List()
	require.ErrorIs(t, err, ErrIdentityNotFound)
}

func TestOperations_VaultNotFound(t *testing.T) {
	// #given: identity file exists but no vault file
	dir := filepath.Join(t.TempDir(), "vault")
	require.NoError(t, os.MkdirAll(dir, dirPerm))
	v := New(dir)

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(v.identityPath(), []byte(identity.String()+"\n"), filePerm))

	// #when/#then: all operations return ErrVaultNotFound
	require.ErrorIs(t, v.Set("KEY", "val"), ErrVaultNotFound)

	_, err = v.Get(context.Background(), "KEY")
	require.ErrorIs(t, err, ErrVaultNotFound)

	require.ErrorIs(t, v.Delete("KEY"), ErrVaultNotFound)

	_, err = v.List()
	require.ErrorIs(t, err, ErrVaultNotFound)
}
