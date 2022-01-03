// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2021 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package option

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	. "gopkg.in/check.v1"
)

func TestGetEnvName(t *testing.T) {
	type args struct {
		option string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Normal option",
			args: args{
				option: "foo",
			},
			want: "BPFLOCK_FOO",
		},
		{
			name: "Capital option",
			args: args{
				option: "FOO",
			},
			want: "BPFLOCK_FOO",
		},
		{
			name: "with numbers",
			args: args{
				option: "2222",
			},
			want: "BPFLOCK_2222",
		},
		{
			name: "mix numbers small letters",
			args: args{
				option: "22ada22",
			},
			want: "BPFLOCK_22ADA22",
		},
		{
			name: "mix numbers small letters and dashes",
			args: args{
				option: "22ada2------2",
			},
			want: "BPFLOCK_22ADA2______2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getEnvName(tt.args.option); got != tt.want {
				t.Errorf("getEnvName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func (s *OptionSuite) TestReadDirConfig(c *C) {
	var dirName string
	type args struct {
		dirName string
	}
	type want struct {
		allSettings        map[string]interface{}
		allSettingsChecker Checker
		err                error
		errChecker         Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "empty configuration",
			preTestRun: func() {
				dirName = c.MkDir()

				fs := flag.NewFlagSet("empty configuration", flag.ContinueOnError)
				viper.BindPFlags(fs)
			},
			setupArgs: func() args {
				return args{
					dirName: dirName,
				}
			},
			setupWant: func() want {
				return want{
					allSettings:        map[string]interface{}{},
					allSettingsChecker: DeepEquals,
					err:                nil,
					errChecker:         Equals,
				}
			},
			postTestRun: func() {
				os.RemoveAll(dirName)
			},
		},
		{
			name: "single file configuration",
			preTestRun: func() {
				dirName = c.MkDir()

				fullPath := filepath.Join(dirName, "test")
				err := os.WriteFile(fullPath, []byte(`"1"
`), os.FileMode(0644))
				c.Assert(err, IsNil)
				fs := flag.NewFlagSet("single file configuration", flag.ContinueOnError)
				fs.String("test", "", "")
				BindEnv("test")
				viper.BindPFlags(fs)

				fmt.Println(fullPath)
			},
			setupArgs: func() args {
				return args{
					dirName: dirName,
				}
			},
			setupWant: func() want {
				return want{
					allSettings:        map[string]interface{}{"test": `"1"`},
					allSettingsChecker: DeepEquals,
					err:                nil,
					errChecker:         Equals,
				}
			},
			postTestRun: func() {
				os.RemoveAll(dirName)
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		m, err := ReadDirConfig(args.dirName)
		c.Assert(err, want.errChecker, want.err, Commentf("Test Name: %s", tt.name))
		err = MergeConfig(m)
		c.Assert(err, IsNil)
		c.Assert(viper.AllSettings(), want.allSettingsChecker, want.allSettings, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *OptionSuite) TestBindEnv(c *C) {
	optName1 := "foo-bar"
	os.Setenv("LEGACY_FOO_BAR", "legacy")
	os.Setenv(getEnvName(optName1), "new")
	BindEnvWithLegacyEnvFallback(optName1, "LEGACY_FOO_BAR")
	c.Assert(viper.GetString(optName1), Equals, "new")

	optName2 := "bar-foo"
	BindEnvWithLegacyEnvFallback(optName2, "LEGACY_FOO_BAR")
	c.Assert(viper.GetString(optName2), Equals, "legacy")

	viper.Reset()
}

func (s *OptionSuite) TestEnabledFunctions(c *C) {
	d := &DaemonConfig{}
	c.Assert(d.IPv4Enabled(), Equals, false)
	c.Assert(d.IPv6Enabled(), Equals, false)
	d = &DaemonConfig{EnableIPv4: true}
	c.Assert(d.IPv4Enabled(), Equals, true)
	c.Assert(d.IPv6Enabled(), Equals, false)
	d = &DaemonConfig{EnableIPv6: true}
	c.Assert(d.IPv4Enabled(), Equals, false)
	c.Assert(d.IPv6Enabled(), Equals, true)
}

func (s *OptionSuite) Test_backupFiles(c *C) {
	tempDir := c.MkDir()
	fileNames := []string{"test.json", "test-1.json", "test-2.json"}

	backupFiles(tempDir, fileNames)
	files, err := os.ReadDir(tempDir)
	c.Assert(err, IsNil)
	// No files should have been created
	c.Assert(len(files), Equals, 0)

	_, err = os.Create(filepath.Join(tempDir, "test.json"))
	c.Assert(err, IsNil)

	backupFiles(tempDir, fileNames)
	files, err = os.ReadDir(tempDir)
	c.Assert(err, IsNil)
	c.Assert(len(files), Equals, 1)
	c.Assert(files[0].Name(), Equals, "test-1.json")

	backupFiles(tempDir, fileNames)
	files, err = os.ReadDir(tempDir)
	c.Assert(err, IsNil)
	c.Assert(len(files), Equals, 1)
	c.Assert(files[0].Name(), Equals, "test-2.json")

	_, err = os.Create(filepath.Join(tempDir, "test.json"))
	c.Assert(err, IsNil)

	backupFiles(tempDir, fileNames)
	files, err = os.ReadDir(tempDir)
	c.Assert(err, IsNil)
	c.Assert(len(files), Equals, 2)
	c.Assert(files[0].Name(), Equals, "test-1.json")
	c.Assert(files[1].Name(), Equals, "test-2.json")
}
