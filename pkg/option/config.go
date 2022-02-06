// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2016-2021 Authors of Cilium

package option

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/linux-lock/bpflock/api/v1/models"
	"github.com/linux-lock/bpflock/pkg/components"
	"github.com/linux-lock/bpflock/pkg/defaults"
	"github.com/linux-lock/bpflock/pkg/lock"
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/linux-lock/bpflock/pkg/logging/logfields"
	"github.com/linux-lock/bpflock/pkg/version"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "config")
)

const (
	// AgentHealthPort is the TCP port for agent health status API
	AgentHealthPort = "agent-health-port"

	// RmBpfOnExit if true deletes bpf programs when bpflock daemon exits
	RmBpfOnExit = "remove-bpf-programs"

	// BPFRoot is the Path to BPF filesystem
	//BPFRoot = "bpf-root"

	// CGroupRoot is the path to Cgroup2 filesystem
	//CGroupRoot = "cgroup-root"

	// ConfigFile is the Configuration file (default "/usr/lib/bpflock/bpflock.yaml")
	ConfigFile = "config"

	// ConfigDir is the directory that contains a file for each option where
	// the filename represents the option name and the content of that file
	// represents the value of that option.
	ConfigDir = "config-dir"

	// BpfConfigDir is the directory that contains bpf programs conifigurations
	BpfConfigDir = "bpf-config-dir"

	// DebugArg is the argument enables debugging mode
	DebugArg = "debug"

	// DebugVerbose is the argument enables verbose log message for particular subsystems
	DebugVerbose = "debug-verbose"

	// GopsPort is the TCP port for the gops server.
	GopsPort = "gops-port"

	// VarLibDir enables the directory path to store variable runtime environment
	VarLibDir = "lib-dir"

	// LogDriver sets logging endpoints to use for example syslog, fluentd
	LogDriver = "log-driver"

	// LogOpt sets log driver options for bpflock
	LogOpt = "log-opt"

	// Logstash enables logstash integration
	// Logstash = "logstash"

	// SocketPath sets daemon's socket path to listen for connections
	SocketPath = "socket-path"

	// StateDir is the directory path to store runtime state
	StateDir = "state-dir"

	// Version prints the version information
	Version = "version"

	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	// PrometheusServeAddr = "prometheus-serve-addr"

	// EnableIPv4Name is the name of the option to enable IPv4 support
	EnableIPv4Name = "enable-ipv4"

	// EnableIPv6Name is the name of the option to enable IPv6 support
	EnableIPv6Name = "enable-ipv6"

	// CMDRef is the path to cmdref output directory
	CMDRef = "cmdref"

	// bpfrestrict
	BpfRestrictProfile = "bpfrestrict-profile"
	BpfRestrictBlock   = "bpfrestrict-block"

	// kmodlock
	KmodLockProfile = "kmodlock-profile"
	KmodLockBlock   = "kmodlock-block"

	// kimglock
	KimgLockProfile = "kimglock-profile"
	KimgLockBlock   = "kimglock-block"

	// filelesslock
	FilelessLockProfile = "filelesslock-profile"

	// execsnoop
	ExecSnoopTarget = "exec-snoop"

	bpflockEnvPrefix = "BPFLOCK_"
)

// getEnvName returns the environment variable to be used for the given option name.
func getEnvName(option string) string {
	under := strings.Replace(option, "-", "_", -1)
	upper := strings.ToUpper(under)
	return bpflockEnvPrefix + upper
}

// RegisteredOptions maps all options that are bind to viper.
var RegisteredOptions = map[string]struct{}{}

// BindEnv binds the option name with an deterministic generated environment
// variable which s based on the given optName. If the same optName is bind
// more than 1 time, this function panics.
func BindEnv(optName string) {
	registerOpt(optName)
	viper.BindEnv(optName, getEnvName(optName))
}

// BindEnvWithLegacyEnvFallback binds the given option name with either the same
// environment variable as BindEnv, if it's set, or with the given legacyEnvName.
//
// The function is used to work around the viper.BindEnv limitation that only
// one environment variable can be bound for an option, and we need multiple
// environment variables due to backward compatibility reasons.
func BindEnvWithLegacyEnvFallback(optName, legacyEnvName string) {
	registerOpt(optName)

	envName := getEnvName(optName)
	if os.Getenv(envName) == "" {
		envName = legacyEnvName
	}

	viper.BindEnv(optName, envName)
}

func registerOpt(optName string) {
	_, ok := RegisteredOptions[optName]
	if ok || optName == "" {
		panic(fmt.Errorf("option already registered: %s", optName))
	}
	RegisteredOptions[optName] = struct{}{}
}

// LogRegisteredOptions logs all options that where bind to viper.
func LogRegisteredOptions(entry *logrus.Entry) {
	keys := make([]string, 0, len(RegisteredOptions))
	for k := range RegisteredOptions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := viper.GetStringSlice(k)
		if len(v) > 0 {
			entry.Infof("  --%s='%s'", k, strings.Join(v, ","))
		} else {
			entry.Infof("  --%s='%s'", k, viper.GetString(k))
		}
	}
}

// DaemonConfig is the configuration used by Daemon.
type DaemonConfig struct {
	CreationTime  time.Time
	VarLibDir     string // bpflock variable library and files directory
	RunDir        string // bpflock runtime directory
	ProgramLibDir string // bpflock programs and libraries
	BpfDir        string // BPF program files directory

	// RestoreState enables restoring the state from previous running daemons.
	RestoreState bool

	// Remove Bpf programs on exit
	RmBpfOnExit bool

	// StateDir is the directory where runtime state of endpoints is stored
	StateDir string

	// Options changeable at runtime
	Opts *IntOptions

	// Mutex for serializing configuration updates to the daemon.
	ConfigPatchMutex lock.RWMutex

	// AgentHealthPort is the TCP port for agent health status API
	AgentHealthPort int

	// EnableMonitor enables the monitor unix domain socket server
	//EnableMonitor bool

	// HTTPRetryTimeout is the time in seconds before an uncompleted request is retried.
	HTTPRetryTimeout int

	// EnableIPv4 is true when IPv4 is enabled
	EnableIPv4 bool

	// EnableIPv6 is true when IPv6 is enabled
	EnableIPv6 bool

	// CLI options

	BPFRoot string
	//CGroupRoot      string

	ConfigFile   string
	ConfigDir    string
	BpfConfigDir string
	Debug        bool
	DebugVerbose []string
	LogDriver    []string
	LogOpt       map[string]string
	// Logstash     bool
	SocketPath string

	Version string
	// PrometheusServeAddr string

	ExecSnoopTarget string
	BpfMeta         *models.BpfMeta
}

var (
	BpfM = models.BpfMeta{
		Bpfmetaver: "v1",
		Kind:       "bpf",
		Bpfmetadata: &models.BpfMetadata{
			Name: components.BpflockAgentName,
		},
		Bpfspec: &models.BpfSpec{
			Programs: make([]*models.BpfProgram, 0),
		},
	}

	BpflockBpfProgs = map[string]models.BpfProgram{
		// For now lets keep bpf programs sorted here
		components.FilelessLock: {
			Name:        "filelesslock",
			Priority:    1,
			Description: "Restrict fileless binary execution",
		},
		// kernel features restrictions priority starts from 50
		components.KimgLock: {
			Name:        "kimglock",
			Priority:    50,
			Description: "Restrict both direct and indirect modification to a running kernel image",
		},
		components.KmodLock: {
			Name:        "kmodlock",
			Priority:    60,
			Description: "Restrict kernel module operations on modular kernels",
		},
		components.BpfRestrict: {
			Name:        "bpfrestrict",
			Priority:    90,
			Description: "Restrict access to the bpf() system call",
		},
	}

	// Config represents the daemon configuration
	Config = &DaemonConfig{
		CreationTime:  time.Now(),
		BPFRoot:       defaults.DefaultMapRoot,
		ProgramLibDir: defaults.ProgramLibPath,
		EnableIPv4:    defaults.EnableIPv4,
		EnableIPv6:    defaults.EnableIPv6,
		LogOpt:        make(map[string]string),
	}
)

type BpfByPriority []*models.BpfProgram

func (progs BpfByPriority) Len() int {
	return len(progs)
}

func (progs BpfByPriority) Less(i, j int) bool {
	return progs[i].Priority < progs[j].Priority
}

func (progs BpfByPriority) Swap(i, j int) {
	progs[i], progs[j] = progs[j], progs[i]
}

// GetGlobalsDir returns the path for the globals directory.
func (c *DaemonConfig) GetGlobalsDir() string {
	return filepath.Join(c.StateDir, "globals")
}

// IPv4Enabled returns true if IPv4 is enabled
func (c *DaemonConfig) IPv4Enabled() bool {
	return c.EnableIPv4
}

// IPv6Enabled returns true if IPv6 is enabled
func (c *DaemonConfig) IPv6Enabled() bool {
	return c.EnableIPv6
}

func isBpfProfileValid(profile string) error {
	if profile == "" {
		return fmt.Errorf("profile not set")
	}
	switch profile {
	case "allow", "none", "privileged", "baseline", "restricted":
		return nil
	}
	return fmt.Errorf("profile '%s' not supported", profile)
}

func (c *DaemonConfig) areBpfProgramsOk() error {
	bpfMeta := c.BpfMeta
	if bpfMeta.Bpfspec == nil || len(bpfMeta.Bpfspec.Programs) == 0 {
		return fmt.Errorf("unable to find spec and bpf programs configuration")
	}

	spec := bpfMeta.Bpfspec
	for _, p := range spec.Programs {
		profile := ""
		for _, n := range p.Args {
			if strings.HasPrefix(n, "--profile") {
				arg := strings.Split(n, "=")
				profile = arg[1]
				break
			}
		}

		err := isBpfProfileValid(profile)
		if err != nil {
			return fmt.Errorf("BpfMeta invalid program '%s': %v", p.Name, err)
		}
	}

	return nil
}

func (c *DaemonConfig) isBpfMetaOk() error {
	bpfMeta := c.BpfMeta
	if bpfMeta.Bpfmetaver != "v1" {
		return fmt.Errorf("bpfmetaver '%s' not supported", bpfMeta.Bpfmetaver)
	}

	if bpfMeta.Kind != "bpf" {
		return fmt.Errorf("kind '%s' not supported", bpfMeta.Kind)
	}

	if bpfMeta.Bpfmetadata.Name != components.BpflockAgentName {
		return fmt.Errorf("metadata name launcher not valid")
	}

	return c.areBpfProgramsOk()
}

func (c *DaemonConfig) isExecSnoopConfOk() error {
	switch c.ExecSnoopTarget {
	case defaults.ExecSnoopAll, defaults.ExecSnoopByFilter, "none", "":
		return nil
	}

	return fmt.Errorf("invalid '%q' value", ExecSnoopTarget)
}

// Validate validates the daemon configuration
func (c *DaemonConfig) Validate() error {
	err := c.isExecSnoopConfOk()
	if err != nil {
		return fmt.Errorf("validate configuration: %v", err)
	}

	err = c.isBpfMetaOk()
	if err != nil {
		return fmt.Errorf("validate configuration: failed BpfMeta: %v", err)
	}

	return nil
}

// validateBpfConfig checks whether the configuration of bpf programs is valid
// and stores passed programs into storeProgs
func validateBpfMeta(bpfMeta *models.BpfMeta, storeProgs *[]*models.BpfProgram) error {
	if bpfMeta == nil || storeProgs == nil {
		return fmt.Errorf("nil values passed")
	}

	if bpfMeta.Bpfmetaver != "v1" {
		return fmt.Errorf("bpfmetaver '%s' not supported", bpfMeta.Bpfmetaver)
	}

	if bpfMeta.Kind != "bpf" {
		return fmt.Errorf("kind '%s' not supported", bpfMeta.Kind)
	}

	// Check nil first
	if bpfMeta.Bpfmetadata == nil || bpfMeta.Bpfmetadata.Name != components.BpflockAgentName {
		return fmt.Errorf("bpfmetadata name launcher not valid")
	}

	spec := *bpfMeta.Bpfspec
	if len(spec.Programs) == 0 {
		return fmt.Errorf("bpfspec.programs is empty")
	}

	for _, prog := range spec.Programs {
		_, ok := BpflockBpfProgs[prog.Name]
		if !ok {
			return fmt.Errorf("bpf program '%s' not supported", prog.Name)
		}
		for _, p := range *storeProgs {
			if prog.Name == p.Name {
				log.Warnf("program '%s' was already provided, duplicate entry", prog.Name)
			}
		}
		*storeProgs = append(*storeProgs, prog)
	}

	return nil
}

// validateConfigmap checks whether the flag exists and validate the value of flag
func validateConfigmap(cmd *cobra.Command, m map[string]interface{}) (error, string) {
	// validate the config-map
	for key, value := range m {
		if val := fmt.Sprintf("%v", value); val != "" {
			flags := cmd.Flags()
			// check whether the flag exists
			if flag := flags.Lookup(key); flag != nil {
				// validate the value of flag
				if err := flag.Value.Set(val); err != nil {
					return err, key
				}
			}
		}
	}

	return nil, ""
}

func populateBpfMetaProgs(dst *models.BpfMeta, passedprogs []*models.BpfProgram) error {
	pushed := make(map[string]*models.BpfProgram, len(passedprogs))
	spec := dst.Bpfspec
	for _, p := range passedprogs {
		pbpf, ok := BpflockBpfProgs[p.Name]
		if !ok {
			return fmt.Errorf("unable to validate program '%s' not supported", p.Name)
		}

		prog := &models.BpfProgram{
			Name:        p.Name,
			Command:     p.Command,
			Description: pbpf.Description,
			Priority:    pbpf.Priority,
			Args:        p.Args,
		}

		if _, ok = pushed[p.Name]; ok {
			// Already pushed lets overwrite previous entry
			log.Warnf("program '%s' was already provided, overwriting previous duplicate entry.", prog.Name)
		}

		pushed[p.Name] = prog
	}

	for _, v := range pushed {
		spec.Programs = append(spec.Programs, v)
	}

	return nil
}

func ReadBpfDirConfig(dirName string, BpfMeta *models.BpfMeta) error {
	files, err := readDirConfig(dirName)
	if err != nil {
		return fmt.Errorf("unable to read configuration directory %s", dirName)
	}

	progs := make([]*models.BpfProgram, 0)
	for _, f := range files {
		fileName := filepath.Join(dirName, f.Name())

		viper.SetConfigType("yaml")
		viper.SetConfigFile(fileName)
		err = viper.ReadInConfig()
		if err != nil {
			return fmt.Errorf("config '%s' unable to read with viper: %v", fileName, err)
		} else {
			log.WithField(logfields.Path, viper.ConfigFileUsed()).
				Info("Using bpflock config from file")
		}

		bpfConf := models.BpfMeta{}
		err = viper.Unmarshal(&bpfConf)
		if err != nil {
			return fmt.Errorf("config '%s' unable to decode BpfMeta struct: %v", fileName, err)
		}

		err = validateBpfMeta(&bpfConf, &progs)
		if err != nil {
			return fmt.Errorf("config '%s' unable to validate BpfMeta : %v", fileName, err)
		}

		log.WithField(logfields.Path, fileName).Info("Using bpflock bpf security configuration from file")
	}

	populateBpfMetaProgs(BpfMeta, progs)

	sort.Sort(BpfByPriority(BpfMeta.Bpfspec.Programs))

	return nil
}

func readDirConfig(dirName string) ([]os.DirEntry, error) {
	files, err := os.ReadDir(dirName)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read configuration directory: %s", err)
	}

	retf := make([]os.DirEntry, 0)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		fName := filepath.Join(dirName, f.Name())

		// the file can still be a symlink to a directory
		if f.Type()&os.ModeSymlink == 0 {
			absFileName, err := filepath.EvalSymlinks(fName)
			if err != nil {
				log.WithError(err).Warnf("Unable to read configuration file %q", absFileName)
				continue
			}
			fName = absFileName
		}

		fi, err := os.Stat(fName)
		if err != nil {
			log.WithError(err).Warnf("Unable to read configuration file %q", fName)
			continue
		}
		if fi.Mode().IsDir() {
			continue
		}

		retf = append(retf, f)
	}

	return retf, nil
}

// ReadDirConfig reads the given directory and returns a map that maps the
// filename to the contents of that file.
func ReadDirConfig(dirName string) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	files, err := readDirConfig(dirName)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read configuration directory: %s", err)
	}
	for _, f := range files {
		fName := filepath.Join(dirName, f.Name())
		b, err := os.ReadFile(fName)
		if err != nil {
			log.WithError(err).Warnf("Unable to read configuration file %q", fName)
			continue
		}
		m[f.Name()] = string(bytes.TrimSpace(b))
	}
	return m, nil
}

// MergeBpfMetaConfig merges the given configuration with viper's configuration.
func mergeBpfMetaConfig(BpfMeta *models.BpfMeta) error {
	data, err := BpfMeta.MarshalBinary()
	if err != nil {
		return err
	}

	err = viper.MergeConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("unable to merge bpf programs configuration: %s", err)
	}
	return nil
}

// MergeConfig merges the given configuration map with viper's configuration.
func MergeConfig(m map[string]interface{}) error {
	err := viper.MergeConfigMap(m)
	if err != nil {
		return fmt.Errorf("unable to read merge directory configuration: %s", err)
	}
	return nil
}

// Populate sets all options with the values from viper
func (c *DaemonConfig) Populate() {
	c.AgentHealthPort = viper.GetInt(AgentHealthPort)
	//c.CGroupRoot = viper.GetString(CGroupRoot)
	c.Debug = viper.GetBool(DebugArg)
	c.DebugVerbose = viper.GetStringSlice(DebugVerbose)
	c.VarLibDir = viper.GetString(VarLibDir)
	c.LogDriver = viper.GetStringSlice(LogDriver)
	//c.Logstash = viper.GetBool(Logstash)
	//c.PrometheusServeAddr = viper.GetString(PrometheusServeAddr)
	c.RunDir = viper.GetString(StateDir)
	c.Version = viper.GetString(Version)
	c.SocketPath = defaults.SockPath
	c.EnableIPv4 = viper.GetBool(EnableIPv4Name)
	c.EnableIPv6 = viper.GetBool(EnableIPv6Name)
	c.RmBpfOnExit = viper.GetBool(RmBpfOnExit)
	c.ExecSnoopTarget = viper.GetString(ExecSnoopTarget)

	bpfrargs := ""
	value := viper.GetString(BpfRestrictProfile)
	if value != "" {
		bpfrargs = fmt.Sprintf("--profile=%s", value)
		value = viper.GetString(BpfRestrictBlock)
		if value != "" {
			bpfrargs = fmt.Sprintf("%s --block=%s", bpfrargs, value)
		}
	}

	kimgrargs := ""
	value = viper.GetString(KimgLockProfile)
	if value != "" {
		kimgrargs = fmt.Sprintf("--profile=%s", value)
		value = viper.GetString(KimgLockBlock)
		if value != "" {
			kimgrargs = fmt.Sprintf("%s --block=%s", kimgrargs, value)
		}
	}

	kmodrargs := ""
	value = viper.GetString(KmodLockProfile)
	if value != "" {
		kmodrargs = fmt.Sprintf("--profile=%s", value)
		value = viper.GetString(KmodLockBlock)
		if value != "" {
			kmodrargs = fmt.Sprintf("%s --block=%s", kmodrargs, value)
		}
	}

	filelessargs := ""
	value = viper.GetString(FilelessLockProfile)
	if value != "" {
		filelessargs = fmt.Sprintf("--profile=%s", value)
	}

	for _, p := range BpfM.Bpfspec.Programs {
		switch p.Name {
		case components.KimgLock:
			if kimgrargs != "" {
				p.Args = strings.Fields(kimgrargs)
			}
		case components.KmodLock:
			if kmodrargs != "" {
				p.Args = strings.Fields(kmodrargs)
			}
		case components.BpfRestrict:
			if bpfrargs != "" {
				p.Args = strings.Fields(bpfrargs)
			}
		case components.FilelessLock:
			if filelessargs != "" {
				p.Args = strings.Fields(filelessargs)
			}
		}
	}

	c.BpfMeta = &BpfM

	if m := viper.GetStringMapString(LogOpt); len(m) != 0 {
		c.LogOpt = m
	}
}

// name 'daemon-config.json'. If this file already exists, it is renamed to
// 'daemon-config-1.json', if 'daemon-config-1.json' also exists,
// 'daemon-config-1.json' is renamed to 'daemon-config-2.json'
func (c *DaemonConfig) StoreInFile(dir string) error {
	backupFileNames := []string{
		"agent-runtime-config.json",
		"agent-runtime-config-1.json",
		"agent-runtime-config-2.json",
	}
	backupFiles(dir, backupFileNames)
	f, err := os.Create(backupFileNames[0])
	if err != nil {
		return err
	}
	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", " ")
	return e.Encode(c)
}

// StoreViperInFile stores viper's configuration in a the given directory under
// the file name 'viper-config.yaml'. If this file already exists, it is renamed
// to 'viper-config-1.yaml', if 'viper-config-1.yaml' also exists,
// 'viper-config-1.yaml' is renamed to 'viper-config-2.yaml'
func StoreViperInFile(dir string) error {
	backupFileNames := []string{
		"viper-agent-config.yaml",
		"viper-agent-config-1.yaml",
		"viper-agent-config-2.yaml",
	}
	backupFiles(dir, backupFileNames)
	return viper.WriteConfigAs(backupFileNames[0])
}

func backupFiles(dir string, backupFilenames []string) {
	for i := len(backupFilenames) - 1; i > 0; i-- {
		newFileName := filepath.Join(dir, backupFilenames[i-1])
		oldestFilename := filepath.Join(dir, backupFilenames[i])
		if _, err := os.Stat(newFileName); os.IsNotExist(err) {
			continue
		}
		err := os.Rename(newFileName, oldestFilename)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"old-name": oldestFilename,
				"new-name": newFileName,
			}).Error("Unable to rename configuration files")
		}
	}
}

func sanitizeIntParam(paramName string, paramDefault int) int {
	intParam := viper.GetInt(paramName)
	if intParam <= 0 {
		if viper.IsSet(paramName) {
			log.WithFields(
				logrus.Fields{
					"parameter":    paramName,
					"defaultValue": paramDefault,
				}).Warning("user-provided parameter had value <= 0 , which is invalid ; setting to default")
		}
		return paramDefault
	}
	return intParam
}

// InitConfig reads in config file and ENV variables if set.
func InitConfig(cmd *cobra.Command, programName, configName string) func() {
	return func() {
		if viper.GetBool("version") {
			fmt.Printf("%s %s\n", programName, version.Version)
			os.Exit(0)
		}

		if viper.GetString(CMDRef) != "" {
			return
		}

		Config.ConfigFile = viper.GetString(ConfigFile) // enable ability to specify config file via flag
		Config.ConfigDir = viper.GetString(ConfigDir)
		Config.BpfConfigDir = viper.GetString(BpfConfigDir)
		viper.SetEnvPrefix("bpflock")

		if Config.BpfConfigDir == "" {
			log.Fatalf("flag option '%s' is not set", Config.BpfConfigDir)
		}
		if _, err := os.Stat(Config.BpfConfigDir); os.IsNotExist(err) {
			log.Fatalf("Non-existent configuration directory %s", Config.BpfConfigDir)
		}

		if err := ReadBpfDirConfig(Config.BpfConfigDir, &BpfM); err != nil {
			log.WithError(err).Fatalf("unable to process bpf configurations: %s", Config.BpfConfigDir)
		}

		if Config.ConfigDir != "" {
			if _, err := os.Stat(Config.ConfigDir); os.IsNotExist(err) {
				log.Fatalf("Non-existent configuration directory %s", Config.ConfigDir)
			}

			if m, err := ReadDirConfig(Config.ConfigDir); err != nil {
				log.WithError(err).Fatalf("Unable to read configuration directory %s", Config.ConfigDir)
			} else {
				// validate the config-map
				if err, flag := validateConfigmap(cmd, m); err != nil {
					log.WithError(err).Fatal("Incorrect config-map flag " + flag)
				}

				if err := MergeConfig(m); err != nil {
					log.WithError(err).Fatal("Unable to merge configuration")
				}
			}
		}

		if Config.ConfigFile != "" {
			viper.SetConfigFile(Config.ConfigFile)
		} else {
			viper.SetConfigType("yaml")
			viper.SetConfigName(configName)          // name of config file (without extension)
			viper.AddConfigPath("$HOME")             // adding home directory as first search path
			viper.AddConfigPath("/etc/bpflock/")     // adding home directory as first search path
			viper.AddConfigPath("/usr/lib/bpflock/") // adding home directory as first search path
		}

		// If a config file is found, read it in.
		if err := viper.ReadInConfig(); err == nil {
			log.WithField(logfields.Path, viper.ConfigFileUsed()).
				Info("Using bpflock config from file")
		} else if Config.ConfigFile != "" {
			log.WithField(logfields.Path, Config.ConfigFile).
				Fatal("Error reading config file")
		} else {
			log.WithError(err).Debug("Skipped reading configuration file")
		}

		if err := mergeBpfMetaConfig(&BpfM); err != nil {
			log.WithError(err).Fatal("Unable to merge bpf security configuration")
		}
	}
}
