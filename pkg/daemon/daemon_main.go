// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2016-2021 Authors of Cilium

package daemon

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"time"

	"github.com/go-openapi/loads"
	gops "github.com/google/gops/agent"
	flags "github.com/jessevdk/go-flags"

	"github.com/linux-lock/bpflock/api/v1/restapi"
	"github.com/linux-lock/bpflock/api/v1/restapi/operations"
	"github.com/linux-lock/bpflock/pkg/bpf"
	"github.com/linux-lock/bpflock/pkg/common"
	"github.com/linux-lock/bpflock/pkg/components"
	"github.com/linux-lock/bpflock/pkg/defaults"
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/linux-lock/bpflock/pkg/logging/logfields"
	"github.com/linux-lock/bpflock/pkg/option"
	"github.com/linux-lock/bpflock/pkg/pidfile"
	linuxrequirements "github.com/linux-lock/bpflock/pkg/requirements/linux"
	"github.com/linux-lock/bpflock/pkg/version"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	apiTimeout   = 60 * time.Second
	daemonSubsys = components.BpflockAgentName

	// fatalSleep is the duration bpflock should sleep before existing in case
	// of a log.Fatal is issued or a CLI flag is specified but does not exist.
	fatalSleep = 2 * time.Second
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, daemonSubsys)

	bootstrapTimestamp = time.Now()

	// RootCmd represents the base command when called without any subcommands
	RootCmd = &cobra.Command{
		Use:   components.BpflockAgentName,
		Short: "Run the bpflock agent",
		Run: func(cmd *cobra.Command, args []string) {
			cmdRefDir := viper.GetString(option.CMDRef)
			if cmdRefDir != "" {
				genMarkdown(cmd, cmdRefDir)
				os.Exit(0)
			}

			// Open socket for using gops to get stacktraces of the agent.
			addr := fmt.Sprintf("127.0.0.1:%d", viper.GetInt(option.GopsPort))
			addrField := logrus.Fields{"address": addr}
			if err := gops.Listen(gops.Options{
				Addr:                   addr,
				ReuseSocketAddrAndPort: true,
			}); err != nil {
				log.WithError(err).WithFields(addrField).Fatal("Cannot start gops server")
			}
			log.WithFields(addrField).Info("Started gops server")

			initEnv(cmd)
			runDaemon()
		},
	}
)

// Installs the cleanup signal handler and invokes
// the root command. This function only returns when an interrupt
// signal has been received. This is intended to be called by main.main().
func Execute() {
	interruptCh := cleaner.registerSigHandler()
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	<-interruptCh
}

func init() {
	setupSleepBeforeFatal()
	initializeFlags()
}

func setupSleepBeforeFatal() {
	RootCmd.SetFlagErrorFunc(func(_ *cobra.Command, e error) error {
		time.Sleep(fatalSleep)
		return e
	})
	logrus.RegisterExitHandler(func() {
		time.Sleep(fatalSleep)
	},
	)
}

func initializeFlags() {
	cobra.OnInitialize(option.InitConfig(RootCmd, "bpflock", "bpflock"))

	// Reset the help function to also exit, as we block elsewhere in interrupts
	// and would not exit when called with -h.
	oldHelpFunc := RootCmd.HelpFunc()
	RootCmd.SetHelpFunc(func(c *cobra.Command, a []string) {
		oldHelpFunc(c, a)
		os.Exit(0)
	})

	flags := RootCmd.Flags()

	// Env bindings
	flags.Int(option.AgentHealthPort, defaults.AgentHealthPort, "TCP port for agent health status API")
	option.BindEnv(option.AgentHealthPort)

	flags.Bool(option.RmBpfOnExit, defaults.RmBpfOnExit, "Remove bpf programs and all installed security features on exit")
	option.BindEnv(option.RmBpfOnExit)

	//flags.String(option.BPFRoot, defaults.DefaultMapRoot , "Path to BPF filesystem")
	//option.BindEnv(option.BPFRoot)

	flags.String(option.ConfigFile, filepath.Join(defaults.ConfigurationPath, "bpflock.yaml"), `Configuration file`)
	option.BindEnv(option.ConfigFile)

	flags.String(option.ConfigDir, filepath.Join(defaults.ConfigurationPath, "bpflock.d"), `Configuration directory that contains a file for each configuration`)
	option.BindEnv(option.ConfigDir)

	flags.String(option.BpfConfigDir, filepath.Join(defaults.ConfigurationPath, "bpf.d"), `Configuration directory that contains bpf programs configurations`)
	option.BindEnv(option.BpfConfigDir)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(option.DebugArg)

	flags.Bool(option.EnableIPv4Name, defaults.EnableIPv4, "Enable IPv4 support")
	option.BindEnv(option.EnableIPv4Name)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	option.BindEnv(option.EnableIPv6Name)

	flags.String(option.VarLibDir, defaults.VariablePath, "Directory path to store runtime environment")
	option.BindEnv(option.VarLibDir)

	//flags.StringSlice(option.LogDriver, []string{}, "Logging endpoints to use for example syslog")
	//option.BindEnv(option.LogDriver)

	//flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil),
	//	option.LogOpt, `Log driver options for bpflock, `+
	//		`configmap example for syslog driver: {"syslog.level":"info","syslog.facility":"local5","syslog.tag":"bpflock"}`)
	//option.BindEnv(option.LogOpt)

	flags.String(option.StateDir, defaults.RuntimePath, "Directory path to store runtime state")
	option.BindEnv(option.StateDir)

	flags.Bool(option.Version, false, "Print version information")
	option.BindEnv(option.Version)

	//flags.String(option.PrometheusServeAddr, "", "IP:Port on which to serve prometheus metrics (pass \":Port\" to bind on all interfaces, \"\" is off)")
	//option.BindEnvWithLegacyEnvFallback(option.PrometheusServeAddr, "PROMETHEUS_SERVE_ADDR")

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(option.CMDRef)

	flags.Int(option.GopsPort, defaults.GopsPortAgent, "Port for gops server to listen on")
	option.BindEnv(option.GopsPort)

	flags.String(option.BpfRestrictProfile, "", "bpfrestrict security profile to restrict bpf() system call")
	option.BindEnv(option.BpfRestrictProfile)

	flags.String(option.BpfRestrictBlock, "", "bpfrestrict block operations")
	option.BindEnv(option.BpfRestrictBlock)

	flags.String(option.KmodLockProfile, "", "kmodlock bpf security profile to restrict kernel module operations")
	option.BindEnv(option.KmodLockProfile)

	flags.String(option.KmodLockBlock, "", "kmodlock block operations")
	option.BindEnv(option.KmodLockBlock)

	flags.String(option.KimgLockProfile, "", "kimglock bpf security profile to restrict direct and indirect kernel image modification")
	option.BindEnv(option.KimgLockProfile)

	flags.String(option.KimgLockAllow, "", "kimglock allow operations")
	option.BindEnv(option.KimgLockAllow)

	flags.String(option.FilelessLockProfile, "", "filelesslock bpf security profile to restrict fileless binary execution")
	option.BindEnv(option.FilelessLockProfile)

	flags.String(option.ExecSnoopTarget, "none", "Run execsnoop to trace process execution")
	option.BindEnv(option.ExecSnoopTarget)

	viper.BindPFlags(flags)
}

// restoreExecPermissions restores file permissions to 0740 of all files inside
// `searchDir` with the given regex `patterns`.
func restoreExecPermissions(searchDir string, patterns ...string) error {
	fileList := []string{}
	err := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		for _, pattern := range patterns {
			if regexp.MustCompile(pattern).MatchString(f.Name()) {
				fileList = append(fileList, path)
				break
			}
		}
		return nil
	})

	for _, fileToChange := range fileList {
		// Changing files permissions to -rwx:r--:---, we are only
		// adding executable permission to the owner and keeping the
		// same permissions stored by go-bindata.
		if err := os.Chmod(fileToChange, os.FileMode(0740)); err != nil {
			return err
		}
	}

	return err
}

func initEnv(cmd *cobra.Command) {
	// Prepopulate option.Config with options from CLI.
	option.Config.Populate()

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logging.SetupLogging(option.Config.LogDriver, logging.LogOptions(option.Config.LogOpt),
		components.BpflockAgentName, option.Config.Debug); err != nil {
		log.Fatal(err)
	}

	option.LogRegisteredOptions(log)

	common.RequireRootPrivilege(components.BpflockAgentName)

	log.Infof("%s %s", components.BpflockAgentName, version.Version)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.Path + ".RunDir":    option.Config.RunDir,
		logfields.Path + ".VarLibDir": option.Config.VarLibDir,
	})

	option.Config.BpfDir = filepath.Join(option.Config.ProgramLibDir, defaults.BpfDir)
	scopedLog = scopedLog.WithField(logfields.Path+".BPFDir", defaults.BpfDir)
	if err := os.MkdirAll(option.Config.RunDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create runtime directory")
	}

	if option.Config.RunDir != defaults.RuntimePath {
		if err := os.MkdirAll(defaults.RuntimePath, defaults.RuntimePathRights); err != nil {
			scopedLog.WithError(err).Fatal("Could not create default runtime directory")
		}
	}

	option.Config.StateDir = filepath.Join(option.Config.RunDir, defaults.StateDir)
	scopedLog = scopedLog.WithField(logfields.Path+".StateDir", option.Config.StateDir)
	if err := os.MkdirAll(option.Config.StateDir, defaults.StateDirRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create state directory")
	}

	if err := os.MkdirAll(option.Config.VarLibDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create library directory")
	}
	// Restore permissions of executable files
	if err := restoreExecPermissions(option.Config.VarLibDir, `.*\.sh`); err != nil {
		scopedLog.WithError(err).Fatal("Unable to restore agent asset permissions")
	}

	linuxrequirements.CheckMinRequirements()

	if err := pidfile.Write(defaults.PidFilePath); err != nil {
		log.WithField(logfields.Path, defaults.PidFilePath).WithError(err).Fatal("Failed to create Pidfile")
	}

	scopedLog = log.WithField(logfields.Path, option.Config.SocketPath)
	socketDir := path.Dir(option.Config.SocketPath)
	if err := os.MkdirAll(socketDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Cannot mkdir directory for cilium socket")
	}

	if err := os.Remove(option.Config.SocketPath); !os.IsNotExist(err) && err != nil {
		scopedLog.WithError(err).Fatal("Cannot remove existing bpflock sock")
	}

	// The standard operation is to mount the BPF filesystem to the
	// standard location (/sys/fs/bpf).
	bpf.CheckOrMountFS()
}

func runDaemon() {
	log.Info("Initializing daemon")

	ctx, cancel := context.WithCancel(restapi.ServerCtx)
	d, err := NewDaemon(ctx, cancel)
	if err != nil {
		select {
		case <-restapi.ServerCtx.Done():
			log.WithError(err).Debug("Error while creating daemon")
		default:
			log.WithError(err).Fatal("Error while creating daemon")
		}
		return
	}

	d.startStatusCollector()

	d.startAgentHealthHTTPService()

	d.startBpfReadEvents()

	srv := restapi.NewServer(d.instantiateAPI())
	srv.EnabledListeners = []string{"unix"}
	srv.SocketPath = flags.Filename(option.Config.SocketPath)
	srv.ReadTimeout = apiTimeout
	srv.WriteTimeout = apiTimeout
	defer srv.Shutdown()

	srv.ConfigureAPI()

	log.WithField("bootstrapTime", time.Since(bootstrapTimestamp)).
		Info("Daemon initialization completed")

	errs := make(chan error, 1)

	go func() {
		errs <- srv.Serve()
	}()

	err = option.Config.StoreInFile(option.Config.StateDir)
	if err != nil {
		log.WithError(err).Error("Unable to store bpflock's configuration")
	}

	err = option.StoreViperInFile(option.Config.StateDir)
	if err != nil {
		log.WithError(err).Error("Unable to store Viper's configuration")
	}

	select {
	case err := <-errs:
		if err != nil {
			log.WithError(err).Fatal("Error returned from non-returning Serve() call")
		}
	}
}

func (d *Daemon) instantiateAPI() *operations.BpflockAPI {
	swaggerSpec, err := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
	if err != nil {
		log.WithError(err).Fatal("Cannot load swagger spec")
	}

	apilog := logging.DefaultLogger.WithField(logfields.LogSubsys, "api")

	apilog.Info("Initializing bpflock API")
	api := operations.NewBpflockAPI(swaggerSpec)

	api.Logger = apilog.Infof

	// /healthz/
	api.DaemonGetHealthzHandler = NewGetHealthzHandler(d)

	// /config/
	//api.DaemonGetConfigHandler = NewGetConfigHandler(d)
	//api.DaemonPatchConfigHandler = NewPatchConfigHandler(d)

	return api
}
