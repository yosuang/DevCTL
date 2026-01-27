package config

import (
	"devctl/pkg/pkgmgr"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindPackage(t *testing.T) {
	tests := []struct {
		name     string
		packages []PackageConfig
		findName string
		want     *PackageConfig
	}{
		{
			name: "find existing package",
			packages: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
				{Name: "node", Version: "18.0.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			findName: "git",
			want:     &PackageConfig{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
		},
		{
			name: "package not found",
			packages: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			findName: "node",
			want:     nil,
		},
		{
			name:     "empty package list",
			packages: []PackageConfig{},
			findName: "git",
			want:     nil,
		},
		{
			name:     "nil package list",
			packages: nil,
			findName: "git",
			want:     nil,
		},
		{
			name: "find package with all fields",
			packages: []PackageConfig{
				{
					Name:        "custom-tool",
					Version:     "1.0.0",
					InstalledBy: pkgmgr.ManagerTypePwsh,
					Script:      "install.ps1",
					HomeDir:     "/home/user/.custom",
				},
			},
			findName: "custom-tool",
			want: &PackageConfig{
				Name:        "custom-tool",
				Version:     "1.0.0",
				InstalledBy: pkgmgr.ManagerTypePwsh,
				Script:      "install.ps1",
				HomeDir:     "/home/user/.custom",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// #given: 一个包列表和要查找的包名
			// #when: 调用 FindPackage 函数
			got := FindPackage(tt.packages, tt.findName)

			// #then: 返回找到的包或 nil
			if tt.want == nil {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				require.Equal(t, tt.want.Name, got.Name)
				require.Equal(t, tt.want.Version, got.Version)
				require.Equal(t, tt.want.InstalledBy, got.InstalledBy)
				require.Equal(t, tt.want.Script, got.Script)
				require.Equal(t, tt.want.HomeDir, got.HomeDir)
			}
		})
	}
}

func TestMergePackages(t *testing.T) {
	tests := []struct {
		name     string
		existing []PackageConfig
		new      []PackageConfig
		want     []PackageConfig
	}{
		{
			name:     "merge empty lists",
			existing: []PackageConfig{},
			new:      []PackageConfig{},
			want:     []PackageConfig{},
		},
		{
			name:     "merge empty existing with new packages",
			existing: []PackageConfig{},
			new: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			want: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
		},
		{
			name: "merge existing with empty new",
			existing: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			new: []PackageConfig{},
			want: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
		},
		{
			name: "append new package to existing",
			existing: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			new: []PackageConfig{
				{Name: "node", Version: "18.0.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			want: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
				{Name: "node", Version: "18.0.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
		},
		{
			name: "update existing package with different version",
			existing: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			new: []PackageConfig{
				{Name: "git", Version: "2.41.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			want: []PackageConfig{
				{Name: "git", Version: "2.41.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
		},
		{
			name: "preserve all fields when merging",
			existing: []PackageConfig{
				{
					Name:        "custom-tool",
					Version:     "1.0.0",
					InstalledBy: pkgmgr.ManagerTypePwsh,
					Script:      "install.ps1",
					HomeDir:     "/home/user/.custom",
				},
			},
			new: []PackageConfig{
				{
					Name:        "custom-tool",
					Version:     "2.0.0",
					InstalledBy: pkgmgr.ManagerTypePwsh,
					Script:      "install-v2.ps1",
					HomeDir:     "/home/user/.custom-v2",
				},
			},
			want: []PackageConfig{
				{
					Name:        "custom-tool",
					Version:     "2.0.0",
					InstalledBy: pkgmgr.ManagerTypePwsh,
					Script:      "install-v2.ps1",
					HomeDir:     "/home/user/.custom-v2",
				},
			},
		},
		{
			name: "merge multiple packages with updates and additions",
			existing: []PackageConfig{
				{Name: "git", Version: "2.40.0", InstalledBy: pkgmgr.ManagerTypeScoop},
				{Name: "node", Version: "18.0.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			new: []PackageConfig{
				{Name: "git", Version: "2.41.0", InstalledBy: pkgmgr.ManagerTypeScoop},
				{Name: "python", Version: "3.11.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
			want: []PackageConfig{
				{Name: "git", Version: "2.41.0", InstalledBy: pkgmgr.ManagerTypeScoop},
				{Name: "node", Version: "18.0.0", InstalledBy: pkgmgr.ManagerTypeScoop},
				{Name: "python", Version: "3.11.0", InstalledBy: pkgmgr.ManagerTypeScoop},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// #given: 两个包列表（existing 和 new）
			// #when: 调用 MergePackages 函数
			got := MergePackages(tt.existing, tt.new)

			// #then: 返回合并后的包列表
			require.Len(t, got, len(tt.want))

			// 创建 map 用于验证（因为顺序可能不同）
			gotMap := make(map[string]PackageConfig)
			for _, pkg := range got {
				gotMap[pkg.Name] = pkg
			}

			for _, wantPkg := range tt.want {
				gotPkg, exists := gotMap[wantPkg.Name]
				require.True(t, exists, "package %s should exist", wantPkg.Name)
				require.Equal(t, wantPkg.Version, gotPkg.Version)
				require.Equal(t, wantPkg.InstalledBy, gotPkg.InstalledBy)
				require.Equal(t, wantPkg.Script, gotPkg.Script)
				require.Equal(t, wantPkg.HomeDir, gotPkg.HomeDir)
			}
		})
	}
}
