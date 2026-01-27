package version

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "add v prefix to version without prefix",
			input: "1.0.0",
			want:  "v1.0.0",
		},
		{
			name:  "keep v prefix if already present",
			input: "v1.0.0",
			want:  "v1.0.0",
		},
		{
			name:  "add v prefix to complex version",
			input: "2.3.4",
			want:  "v2.3.4",
		},
		{
			name:  "keep v prefix for complex version",
			input: "v2.3.4",
			want:  "v2.3.4",
		},
		{
			name:  "empty string returns empty",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// #given: 一个版本字符串
			// #when: 调用 Normalize 函数
			got := Normalize(tt.input)

			// #then: 返回标准化的版本字符串
			require.Equal(t, tt.want, got)
		})
	}
}

func TestEqual(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want bool
	}{
		{
			name: "equal versions without prefix",
			v1:   "1.0.0",
			v2:   "1.0.0",
			want: true,
		},
		{
			name: "equal versions with prefix",
			v1:   "v1.0.0",
			v2:   "v1.0.0",
			want: true,
		},
		{
			name: "equal versions mixed prefix",
			v1:   "1.0.0",
			v2:   "v1.0.0",
			want: true,
		},
		{
			name: "equal versions mixed prefix reversed",
			v1:   "v1.0.0",
			v2:   "1.0.0",
			want: true,
		},
		{
			name: "different versions",
			v1:   "1.0.0",
			v2:   "1.0.1",
			want: false,
		},
		{
			name: "different versions with prefix",
			v1:   "v2.0.0",
			v2:   "v2.0.1",
			want: false,
		},
		{
			name: "major version difference",
			v1:   "1.0.0",
			v2:   "2.0.0",
			want: false,
		},
		{
			name: "empty versions are equal",
			v1:   "",
			v2:   "",
			want: true,
		},
		{
			name: "empty vs non-empty",
			v1:   "",
			v2:   "1.0.0",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// #given: 两个版本字符串
			// #when: 调用 Equal 函数比较
			got := Equal(tt.v1, tt.v2)

			// #then: 返回是否相等的布尔值
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "empty string is empty",
			input: "",
			want:  true,
		},
		{
			name:  "version string is not empty",
			input: "1.0.0",
			want:  false,
		},
		{
			name:  "version with prefix is not empty",
			input: "v1.0.0",
			want:  false,
		},
		{
			name:  "whitespace only is not empty",
			input: "   ",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// #given: 一个版本字符串
			// #when: 调用 IsEmpty 函数
			got := IsEmpty(tt.input)

			// #then: 返回是否为空的布尔值
			require.Equal(t, tt.want, got)
		})
	}
}
