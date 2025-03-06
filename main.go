package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	cRand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"cymetricx/controls"
	"cymetricx/ini"
	"cymetricx/ldb"
	"database/sql"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	mRand "math/rand"
	"mime/multipart"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/capnspacehook/taskmaster"
	_ "github.com/mattn/go-sqlite3"
	"github.com/natefinch/lumberjack"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/process"
	"github.com/shirou/gopsutil/v3/mem"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	complience   bool
	isDeletedIIS bool

	keepAlive int
)

var loginPassword = ""
var recheckInIIS = false

var id = ""
var authenticationTokenV2 = ""
var authenticationTokenV1 = ""
var tokenExpirationData time.Time

var cmdPath = ""
var powerShellPath = ""
var activeDirectoryDomainController bool

var rescanStatus = false
var exitCommandCheck = true

type FeatureToggleConfig struct {
	VulnerabilityScan     bool // Old: vuls
	IdentityUsersCheck    bool // Old: identityusers
	InstalledPatchesCheck bool // Old: installedpatchesKb

	//! This one is never used anywwhere in the code
	PatchManagementSystemCheck bool // Old: patchmgmt

	SystemHardeningCheck            bool // Old: SystemHardeningCheck
	NetworkConfigurationCheck       bool // Old: networksettings
	LocalDNSMonitoring              bool // Old: LocalDNSMonitoring
	RemoteToolsLogCollection        bool // Old: remotetoolslogs
	ApplicationSoftwareInventory    bool // Old: applicationsandsoftwares
	WindowsStartupItemsCheck        bool // Old: windowsstartup
	WindowsServicesCheck            bool // Old: windowsservices
	SystemProcessesAndServicesCheck bool // Old: systemprocessesandservices
	ScheduledTasksCheck             bool // Old: scheduledtasks
	NetworkSharesCheck              bool // Old: networkshares
	BitLockerStatusCheck            bool // Old: bitlocker
	AntivirusStatusCheck            bool // Old: av
	SecureBootStatusCheck           bool // Old: bootsecure
	ComputerConfigurationAudit      bool // Old: computerconfigrations
	ChromeExtensionsCheck           bool // Old: Chromeextions
	DisplayVersionCheck             bool // Old: DisplayVersion
	TPMStatusCheck                  bool // Old: tpmwin
	GPOReportCollection             bool // Old: getGPOReport
	RDPStatusCheck                  bool // Old: rdpstatus
	AssetDiscoveryAD                bool // Old: assetDiscoveryUsingADComputer
	SystemUptimeCheck               bool // Old: getuptimewin
	ProxySettingsCheck              bool // Old: winproxysettings
	CertificateStatusCheck          bool // Old: certs
	ActivePatchesCheck              bool // Old: patchesactive
}

var SystemHardeningCheck = true          //->controls complines **
var networksettings = true               //->get_network()**
var remotetoolslogs = true               //->get_connectionanydesk()**
var applicationsandsoftwares = true      //->getApplications()**
var windowsstartup = true                //->get_startup()**
var windowsservices = true               //->get_GetService()**
var scheduledtasks = true                //->get_winScheduledTask()**
var networkshares = true                 //->get_netshare()**
var bitlocker = true                     //->get_bitlocker()**
var av = true                            //->getAV()**
var bootsecure = true                    //->get_autofim()**
var computerconfigrations = true         //->get_computerinfo()**
var Chromeextions = true                 //->get_Chromeextions()**
var DisplayVersion = true                //->get_DisplayVersion()**
var tpmwin = true                        //->get_tpm_win()
var getGPOReport = true                  //->gpos()
var rdpstatus = true                     //get_rdp()
var assetDiscoveryUsingADComputer = true //compcs()
var getuptimewin = true                  //get_uptime()
var winproxysettings = true              //==> get_proxy()
var certs = true                         //certswin()()

var featureToggleConfig = FeatureToggleConfig{
	LocalDNSMonitoring:              true,
	SystemHardeningCheck:            true,
	VulnerabilityScan:               true,
	IdentityUsersCheck:              true,
	InstalledPatchesCheck:           true,
	PatchManagementSystemCheck:      true,
	NetworkConfigurationCheck:       true,
	RemoteToolsLogCollection:        true,
	ApplicationSoftwareInventory:    true,
	WindowsStartupItemsCheck:        true,
	WindowsServicesCheck:            true,
	SystemProcessesAndServicesCheck: true,
	ScheduledTasksCheck:             true,
	NetworkSharesCheck:              true,
	BitLockerStatusCheck:            true,
	AntivirusStatusCheck:            true,
	SecureBootStatusCheck:           true,
	ComputerConfigurationAudit:      true,
	ChromeExtensionsCheck:           true,
	DisplayVersionCheck:             true,
	TPMStatusCheck:                  true,
	GPOReportCollection:             true,
	RDPStatusCheck:                  true,
	AssetDiscoveryAD:                true,
	SystemUptimeCheck:               true,
	ProxySettingsCheck:              true,
	ActivePatchesCheck:              true,
	CertificateStatusCheck:          true,
}

// var apiURLFlask = "https://192.168.199.133/cymetricxapi/" // Python (Flask)
// var apiURLLaravel = "https://192.168.199.133/cymetricx_api/" // Laravel
// var apiURLLaravel = "https://15.185.175.135/cymetricx_api/" // Laravel (Cloud one)

var apiURLFlask = ""

// var apiURLLaravel = "https://192.168.199.133/cymetricx_api/"
// var apiURLLaravel = "https://test2.cymetricx.com/cymetricx_api/" // Cloud one
var apiURLLaravel = "" //"https://157.175.205.169/cymetricx_api/" // Cloud one

// This is initialized as a global veriable because http.Client must be
// initialized once and reused. It's also thread safe so it can be used
// by multiple goroutines.
var client = createInsecureHttpClient()

const AgentVersion = "4.9.26"

const CymetricxPath = "C:\\Program Files\\CYMETRICX"

// For how long to wait before uploading to the server. A random time between
// min and max values repectively in seconds.

var minimalRescanInterval = 780    // In minutes (13 hourrs)
var maximalRescanInterval = 1380   // In minutes (23 hours)
var minimalMonitoringInterval = 10 // In minutes (10 minutes)
var maximalMonitoringInterval = 15 // In minutes (20 minutes)
var timeUSN = 60                   // In minutes (60 minutes)

func main() {

	// Catch any panic and logs it with its stack trace.
	defer catchAndRestartPanicForFunction(main)

	cmdFlags := parseAllCommandFlags()
	setupLoggerSettings()

	log.Info().Msgf("Starting the agent at version %s...", AgentVersion)

	//! Let's talk about the flow of steps in the agent and if it neeeds to be modified.

	startProfiling(cmdFlags)

	// Check if cmd and powershell exist on the system and get their paths.
	cmdPath, powerShellPath = getCMDandPowerShellPaths()

	//! Why does this function used in windows and not also in linux?
	// Uninstall any old agent that might exist on the system with all of its packages and services.
	uninstallOldAgentWithItsPackagesAndServices()
	deletePreviousAgentEntries()

	stopAndRemoveRunUpgradeService()
	stopAndRemoveRunRecoveryService()
	initializeCreateNewAgentEntries()

	setServiceRegistryKeyForImagePath("CYMETRICX", "cymetricxm.exe")

	// Process the cymetricx.ini file by decrypting it and updating it if needed.
	// Also Update it if any CMD flags were to be passed to the agent.
	iniData := processCymetricxIniOnStartup()
	iniData = updateConfigWithCMDAndExitIfRequired(iniData, cmdFlags)

	terminateCymetricxm()

	serialNumber := initializeAndAuthenticate(iniData)

	checkIfAgentStoppedOrDeleted()
	uploadLogsIfAgentWasJustUpdated()

	startSystemDetailesUploadProcess()
	startGoRoutines(iniData, serialNumber, cmdFlags)
	holdingAgentForever()
}

// uploadLogsIfAgentWasJustUpdated uploads the logs to the server if the agent
// was just updated. This is done by checking if the file "update-occured.txt"
// exists in the agent's directory. If it does, it means that the agent was just
// updated and the logs should be uploaded to the server. The file is then removed.
func uploadLogsIfAgentWasJustUpdated() {
	// If the agent was just updated, this file would exist.
	updateFilePath := filepath.Join(CymetricxPath, "update-occured.txt")

	// If the file does not exist, it means that the agent was not just updated.
	if !fileExists(updateFilePath) {
		return
	}

	// Upload the logs to the server.
	if err := compressAndUploadLogs(`after_update_` + AgentVersion); err != nil {
		log.Error().Err(err).Msg("Failed to upload logs after agent update.")
	}

	// Remove the file that indicates that the agent was just updated.
	if err := os.Remove(updateFilePath); err != nil {
		log.Error().Err(err).Msg("Failed to remove the file that indicates that the agent was just updated.")
	}
}

// checkIfAgentStoppedOrDeleted checks if the agent has been stopped or deleted
// by a trigger from the web interface when the agent was not running
// (the device was off) and then stops the agent for 5 minutes untill
// the agent is started again.
func checkIfAgentStoppedOrDeleted() {
	type AgentStatus struct {
		StopValue   bool `json:"StopAgent"`
		DeleteValue bool `json:"DeleteAgent"`
	}

	for {
		responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("GET", "check_agent_status/"+id, nil, 10)
		if err != nil {
			log.Error().Err(err).Msg("Failed to check agent status.")
			return
		}

		// If this is the first time the agent is launched, the server will
		// return "Client not found" as the response body.
		if strings.Contains(responseBody.String(), "Client not found") {
			log.Info().Msg("Agent not found on the server. This is the agent's initial launch.")

			// Remove these in case the system details upload failed before but the
			// file itself was already created. (edge case)
			os.Remove("Hash Files/system-details-hash.txt")
			os.Remove("Time Files/system-details-timer.txt")
			return
		}

		var agentStatus AgentStatus

		if err := json.Unmarshal(responseBody.Bytes(), &agentStatus); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal agent status response.")
			return
		}

		if agentStatus.StopValue {
			log.Info().Msg("Agent has been stopped from the web interface. Stopping the agent for 5 minutes")
			time.Sleep(5 * time.Minute)
			continue
		}

		if agentStatus.DeleteValue {
			log.Info().Msg("Agent has been deleted from the web interface. Stopping the agent for 5 minutes")
			time.Sleep(5 * time.Minute)
			continue
		}

		// Contiue the agent's normal operation.
		break
	}
}

func checkingUSNPeriodecly() {
	// Channel to signal when there's a change in USN.
	usnChangedChan := make(chan bool)

	go monitorUSNChanges(usnChangedChan)

	// Use a for-range loop to range over the channel.
	for range usnChangedChan {
		go uploadWindowsUsersInformationV2()
	}
}

func monitorUSNChanges(usnChangedChan chan bool) {
	usnFilePath := filepath.Join(CymetricxPath, "Agent Files", "usn.txt")

	for {
		currentUSN, previousUSN, err := processUSN(usnFilePath)
		if err != nil {
			log.Error().Err(err).Msg("Error checking USN")
			time.Sleep(30 * time.Second)
			continue
		}

		if currentUSN != previousUSN && previousUSN != "" {
			log.Info().Msg("USN has changed. Signaling to upload users information.")
			usnChangedChan <- true
		}

		if timeUSN < 60 {
			// Default time to check USN is 60 minutes.
			timeUSN = 60
		}
		time.Sleep(time.Duration(timeUSN) * time.Minute)
	}
}

// catchPanic is a function that catches any panic that occurs in the agent
// with its stack trace and logs it.
func catchPanic() {

	// Recover from panic
	if r := recover(); r != nil {
		// Create a buffer with a size of 1024 bytes to hold the stack trace
		stackTrace := make([]byte, 1024)
		for {

			// Retrieve the stack trace only for this goroutine and fill it
			// into the buffer. False means that we only want the stack trace
			// for this goroutine and not all of them.
			n := runtime.Stack(stackTrace, false)

			// If the buffer was large enough to fit the stack trace, break
			if n < len(stackTrace) {
				stackTrace = stackTrace[:n]
				break
			}

			// If the buffer was too small to fit the stack trace, double its size
			stackTrace = make([]byte, len(stackTrace)*2)
		}

		// Convert the stack trace to a string and concatenate it with the panic message
		err := fmt.Errorf("%v\nStack Trace:\n%s", r, stackTrace)

		// Use Msgf to log the error formatter as opposed in one line when
		// using Err()
		log.Error().Msgf("Panic recovered and logged with stack trace: %v", err)
	}

}

// logError logs the error at the end of the function execution if it exists.
func logError(err *error, message string) {
	if *err != nil {
		log.Error().Err(*err).Msg(message)
	}
}

// CMDFlags is a struct that holds the command line flags passed to the agent.
type CMDFlags struct {
	APIURL        string
	CID           string
	PortRedis     string
	Profiling     bool
	PortProfiling string
}

// parseAllCommandFlags parses the command line flags passed to the agent.
// It returns a CMDFlags struct that holds the parsed flags.
func parseAllCommandFlags() CMDFlags {
	flag.Usage = printUsageCMD

	versionFlag, shortVersionFlag, apiURLFlag, shortURLFlag, CID, shortCID, portRedis, shortPortRedis, profilingFlag, shortProfilingFlag, portProfiling, shortPortProfiling := parseFlags()

	if *versionFlag || *shortVersionFlag {
		fmt.Println("Agent Version:", AgentVersion)
		os.Exit(0)
	}

	checkURL(apiURLFlag, shortURLFlag)

	// if !*runFlag && !*shortRunFlag {
	// 	flag.Usage()
	// 	os.Exit(0)
	// }

	var cmdFlags CMDFlags = CMDFlags{
		APIURL:        firstNonEmpty(*apiURLFlag, *shortURLFlag),
		CID:           firstNonEmpty(*CID, *shortCID),
		PortRedis:     firstNonEmpty(*portRedis, *shortPortRedis),
		Profiling:     firstTrueBoolean(*profilingFlag, *shortProfilingFlag),
		PortProfiling: firstNonEmpty(*portProfiling, *shortPortProfiling),
	}

	return cmdFlags
}

func printUsageCMD() {
	fmt.Printf("NAME:\n")
	fmt.Printf("   %s - This application is the core cyemtricx agent that runs on this machine.\n\n", os.Args[0])
	fmt.Printf("USAGE:\n")
	fmt.Printf("   %s [options] [arguments...]\n\n", os.Args[0])
	fmt.Printf("OPTIONS:\n")
	fmt.Printf("   --help, -h                 		 Show help\n")
	fmt.Printf("   --url value, -u value      		 Modifies the URL of the API server\n")
	fmt.Printf("   --cid value, -c value      		 Modiefies the Client ID\n")
	fmt.Printf("   --version, -v              		 Shows the version of the agent\n")
	fmt.Printf("   --port-redis value, -pr value  	 Modifies the port of Redis\n")
	fmt.Printf("   --profiling, -p            		 Starts the profiling of the agent on port 8080 by default\n")
	fmt.Printf("   --port-profiling value, -pp value     Modifies the port of the profiling\n")
	fmt.Println()
	fmt.Printf("EXAMPLES:\n")
	fmt.Printf("   %s --url http://api.example.com --cid 12345\n", os.Args[0])
}

func parseFlags() (*bool, *bool, *string, *string, *string, *string, *string, *string, *bool, *bool, *string, *string) {
	versionFlag := flag.Bool("version", false, "Shows the version of the agent")
	shortVersionFlag := flag.Bool("v", false, "Shows the version of the agent (short form)")

	apiURLFlag := flag.String("url", "", "Specifies the URL of the API server that the agent will talk to")
	shortURLFlag := flag.String("u", "", "Specifies the URL of the API server that the agent will talk to (short form)")

	CID := flag.String("cid", "", "Specifies the Client ID (CID) of the agent correlating to the server")
	shortCID := flag.String("c", "", "Specifies the Client ID (CID) of the agent correlating to the server (short form)")

	portRedis := flag.String("port-redis", "", "Specifies the port of Redis")
	shortPortRedis := flag.String("pr", "", "Specifies the port of Redis (short form)")

	profilingFlag := flag.Bool("profiling", false, "Starts the profiling of the agent on port 8080")
	shortProfilingFlag := flag.Bool("p", false, "Starts the profiling of the agent on port 8080 (short form)")

	portProfiling := flag.String("port-profiling", "", "Specifies the port of the profiling")
	shortPortProfiling := flag.String("pp", "", "Specifies the port of the profiling (short form)")

	flag.Parse()

	return versionFlag, shortVersionFlag, apiURLFlag, shortURLFlag, CID, shortCID, portRedis, shortPortRedis, profilingFlag, shortProfilingFlag, portProfiling, shortPortProfiling
}

func checkURL(apiURLFlag, shortURLFlag *string) {
	if firstNonEmpty(*apiURLFlag, *shortURLFlag) != "" {
		if !strings.HasPrefix(firstNonEmpty(*apiURLFlag, *shortURLFlag), "http://") && !strings.HasPrefix(firstNonEmpty(*apiURLFlag, *shortURLFlag), "https://") {
			fmt.Println("The URL must start with either http:// or https://")
			os.Exit(0)
		}
	}
}

// Helper function to get the first non-empty string from a list of strings.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// Helper function to get the first true boolean from a list of booleans.
func firstTrueBoolean(values ...bool) bool {
	for _, value := range values {
		if value {
			return true
		}
	}
	return false
}

// setupLoggerSettings sets up the logger to log to a file in a specific format.
func setupLoggerSettings() {
	// allow stack trace to be logged when using pkg/errors
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	// Human-readable time format that looks like this: Fri, 20 Oct 2023 00:00:37 IDT
	zerolog.TimeFieldFormat = time.RFC1123

	ljhook := logRotaterConfigs()
	// Output to console and log file
	//output := zerolog.MultiLevelWriter(ljhook, zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC1123})

	// Output to log file only
	// output := zerolog.MultiLevelWriter(ljhook)

	// Output to console only
	_ = ljhook
	output := zerolog.MultiLevelWriter(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC1123})

	// Create a logger instance that includes the timestamp and caller.
	// Note: The caller was modified inside of the globals.go file to only include the file name and line number.
	log.Logger = zerolog.New(output).With().Timestamp().Caller().Logger()

	log.Info().Msg("Logger settings have been set up.")

	// Set the chmod for "logs" directory to 0600 to allow only the root to read and write.
	// Note: This would cauae an error if the logger was set to only log to the console.
	// Also, would cause an error if there was no log before it to initiate the creating of the logs directory.
	if err := os.Chmod(filepath.Join(CymetricxPath, "logs"), 0600); err != nil {
		log.Error().Err(err).Msg("Failed to change permissions of logs directory.")
	}

	// Set the global log level
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
}

// logRotaterConfigs returns a pointer to a lumberjack.Logger object that is used to rotate the log files.
func logRotaterConfigs() *lumberjack.Logger {

	// It rotates the logs every 25 MB for a maximum of 4 backup and 28 days of retention.
	// It would remove the oldest log file when rotating if the 100 MB limit is reached and replace it with a new one.
	// Meaning that the logger would only keep the last 4 log files, named as follows:
	// agent.log, agent.log.1, agent.log.2, agent.log.3
	return &lumberjack.Logger{
		Filename:   filepath.Join(CymetricxPath, "logs/agent.log"), // path to the log file, if it does not exist it will be created
		MaxSize:    25,                                             // maximum size before it gets rotated
		MaxBackups: 4,                                              // maximum number of backups
		MaxAge:     28,                                             // maximum number of days to retain the log files
		Compress:   true,                                           // whether to compress the rotated log files
	}
}

// startProfiling starts the profiling of the agent on port 8080 so we could check the memory and cpu usage of the agent
func startProfiling(cmdFlags CMDFlags) {
	if cmdFlags.Profiling {
		portProfiling := cmdFlags.PortProfiling
		go func() {
			fmt.Printf("Listening on link: http://localhost:%s/debug/pprof/\n", portProfiling)
			log.Fatal().Err(http.ListenAndServe(":"+portProfiling, nil))
			println("stopped listining")
		}()
	}
}

// getCMDandPowerShellPaths calls getCMDPath and getPowerShellPath to obtain the paths for cmd and powershell.
//
// Returns:
//   - string: The path to cmd.
//   - string: The path to powershell.
func getCMDandPowerShellPaths() (string, string) {
	cmdPath := getCMDPath()
	powerShellPath := getPowerShellPath()

	log.Info().Msg("Successfully found cmd and powershell paths.")

	return cmdPath, powerShellPath
}

// getCMDPath finds the path to cmd on the system.
//
// Returns:
//   - string: The path to cmd.
func getCMDPath() string {
	log.Info().Msg("Attempting to find cmd path...")

	// Check if cmd.exe exists in the System32 directory. If it does, use that path. Otherwise, use "cmd"
	// which will use the cmd.exe in the PATH environment variable.
	cmdFilePath, err := exec.LookPath("cmd")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to find cmd path. Using default path.")
		// Return the default location of cmd.exe
		return "C:\\Windows\\System32\\cmd.exe"
	}

	log.Info().Msgf("Found cmd path: %s", cmdFilePath)
	return cmdFilePath
}

// getPowerShellPath finds the path to powershell on the system.
//
// Returns:
//   - string: The path to powershell.
func getPowerShellPath() string {
	log.Info().Msg("Attempting to find powershell path...")

	// Check if powershell.exe exists in the System32 directory. If it does, use that path. Otherwise, use "powershell"
	// which will use the powershell.exe in the PATH environment variable.
	powerShellFilePath, err := exec.LookPath("powershell")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to find powershell path. Using default path.")
		// Return the default location of powershell.exe
		return "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
	}

	log.Info().Msgf("Found powershell path: %s", powerShellFilePath)
	return powerShellFilePath
}

// uninstallOldAgentWithItsPackagesAndServices uninstalls any old agent that
// might exist on the system with all of its packages and services.
func uninstallOldAgentWithItsPackagesAndServices() {
	if err := uninstallOldAgentServicesAndPackages(); err != nil {
		log.Error().Err(err).Msg("Failed to uninstall old agent.")
		//! Should we exit here if there was an old version and we couldn't uninstall it?
	}

	//! Do we get any error output from the previous function telling that it did not work so i'd know that i need to skip these two functions below?
	// The previous function didn't work on some systems to uninstall the old agent's services and packages.
	// So we need to run these functions to uninstall the old agent's services and packages  as a backup in those cases.
	uninstallOldCymetricxPackagesBackup()
	uninstallOldCymetricxServicesBackup()
}

// uninstallOldAgentServicesAndPackages is responsible for uninstalling older versions of the cymetricx agent if they exist.
// It removes the old agent directory inside of the CYMETRICX director,
// stops and deletes the old agent service, and uninstalls the old agent package.
func uninstallOldAgentServicesAndPackages() error {
	log.Info().Msg("Starting to uninstall the old cymetricx agent...")

	versionFilePath := filepath.Join(CymetricxPath, "VersionFile.txt")

	// If the VersionFile.txt does not exist, it means that this is a fresh install and there is no need to uninstall anything.
	// Ex: CYMETRICX  1.4.119
	if !fileExists(versionFilePath) {
		log.Info().Msg("VersionFile.txt not found. No old agent to uninstall.")
		return nil
	}

	// Read the version from the VersionFile.txt.
	versionRaw, err := os.ReadFile(versionFilePath)
	if err != nil {
		return fmt.Errorf("failed to read VersionFile.txt: %w", err)
	}

	// E.g CYMETRICX  1.4.119
	version := strings.TrimSpace(string(versionRaw))

	// Mind the double space between the version and the version number.
	if version == "CYMETRICX  "+AgentVersion {
		log.Info().Msg("Current agent version matches the version in VersionFile.txt. Skipping uninstallation.")
		return nil
	}

	log.Info().Str("OldVersion", version).Msg("Detected old agent version. Preparing to uninstall.")

	// Create the uninstall script.
	uninstallScript := createScriptToDeleteServicesAndUninstallOldAgent(version)

	// Write the PowerShell command to the file because issues occurred when using the "exec.Command" function directly
	if err := createAndRunPS1FileWithoutOutput("UninstallOldAgentScript.ps1", uninstallScript); err != nil {
		return fmt.Errorf("error creating or running UninstallOldAgentScript.ps1 file because of: %w", err)
	}

	// Remove the old agent directory e.g. C:\Program Files\CYMETRICX\CYMETRICX 1.4.119
	if err = os.RemoveAll(version); err != nil {
		return fmt.Errorf("error removing old agent directory %s because of: %w", version, err)
	}

	log.Info().Msg("Successfully uninstalled the old cymetricx agent.")
	return nil
}

func createScriptToDeleteServicesAndUninstallOldAgent(packageName string) string {

	// sc.exe is the service controller for windows responsible to Create, Start, Stop, Query or Delete any Windows SERVICE
	scFilePath := getSCPath()

	// Construct a PowerShell command to uninstall the old version of the package and delete its files
	uninstallScript := strings.Join([]string{
		fmt.Sprintf(`%s stop '%s'`, scFilePath, packageName),      // Stop the service for the old version
		fmt.Sprintf(`%s delete '%s'`, scFilePath, packageName),    // Delete the service for the old version
		fmt.Sprintf(`%s stop 'Cymetricx Recovery'`, scFilePath),   // Stop the service for the recovery
		fmt.Sprintf(`%s delete 'Cymetricx Recovery'`, scFilePath), // Delete the service for the recovery

		// Uninstall old cymeetricx package from the system and delete its files.
		// Confirm:$false is used to bypass the confirmation prompt that appears when uninstalling a package.
		// Force is used to force the uninstallation even if there are dependencies that rely on the package being uninstalled.
		fmt.Sprintf(`Uninstall-Package '%s' -Confirm:$false -Force`, packageName),

		// Confirm triggers a confirmation prompt asking the user to verify that they want to proceed with the uninstallation.
		// This is used because in some systems the above command failed to work so we needed to opt for this command instead.
		fmt.Sprintf(`Uninstall-Package '%s' -Confirm -Force`, packageName),
	}, "\n")

	return uninstallScript
}

func findCommandPath(commandName string) string {
	log.Info().Msgf("Attempting to find %s path...", commandName)

	// Define the possible paths to check (in case SystemRoot isn't set, we also hardcode "C:\WINDOWS").
	possiblePaths := []string{
		filepath.Join("C:\\", "WINDOWS", "system32", commandName),
		filepath.Join(os.Getenv("SystemRoot"), "system32", commandName),
	}

	// Check each possible path; if the file exists, return immediately.
	for _, path := range possiblePaths {
		if fileExists(path) {
			log.Info().Msgf("Found %s path: %s", commandName, path)
			return path
		}
	}

	// Fallback to PATH environment variable search.
	foundPath, err := exec.LookPath(commandName)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to find %s path. Using default path.", commandName)
		return ""
	}

	log.Info().Msgf("Found %s path: %s", commandName, foundPath)
	return foundPath
}

// getSCPath finds the path to sc.exe on the system which is the service controller
// for windows responsible to Create, Start, Stop, Query or Delete any Windows SERVICE.
func getSCPath() string {
	return findCommandPath("sc.exe")
}

// getNetCommandPath finds the path to net.exe on the system which is used to
// manage network resources.
func getNetCommandPath() string {
	return findCommandPath("net.exe")
}

// uninstallOldCymetricxPackagesBackup uninstalls any cymetricx packages that are not the current version.
// This function is run as a backup in case the uninstallOldAgentServicesAndPackages function failed to uninstall the old agent's packages.
func uninstallOldCymetricxPackagesBackup() {
	log.Info().Msg("Starting to uninstall outdated cymetricx packages as backup...")

	// This command returns a list of all the cymetricx packages installed on the system. e.g. CYMETRICX  1.4.119
	fetchCymetricxPackagesCommand := "Get-Package '*CYMETRICX  *' | Select-Object -ExpandProperty Name "

	//! Ask Abdel-Wahab about this if he could test it without the use of "Cmd /c" and just use the powershell path directly
	//! Also, when i run this command it gives me an error, but when i run the fetchCymetricxPackagesCommand directly in powershell, it works.
	//! But it works here in the code normally as it is now.
	packagesListOutput, err := exec.Command(cmdPath, "/c ", powerShellPath, "-Command", fetchCymetricxPackagesCommand).CombinedOutput()
	if err != nil {
		log.Error().Err(err).Str("Output:", string(packagesListOutput)).Msg("Failed to fetch cymetricx packages list")
	}

	parsedPackagesList := bytes.Split(packagesListOutput, []byte("\n"))

	//! Why do we return them as a list? isn't only one package called "CYMETRICX  1.4.119"?
	for _, rawPackageData := range parsedPackagesList {
		packageName := string(bytes.Trim(bytes.Trim(bytes.TrimSpace(rawPackageData), "��"), "\\0"))
		if (packageName == "CYMETRICX  "+AgentVersion) || (packageName == "") || !strings.Contains(packageName, "CYMETRICX  ") {
			continue
		}

		log.Info().Str("packageName", packageName).Msg("Attempting to uninstall outdated cymetricx package...")

		uninstallOldCymetricxPackageScript := strings.Join([]string{

			// Uninstall old package from the system and delete its files.
			// Confirm:$false is used to bypass the confirmation prompt that appears when uninstalling a package.
			// Force is used to force the uninstallation even if there are dependencies that rely on the package being uninstalled.
			fmt.Sprintf("Uninstall-Package '%s' -Confirm:$false -Force;", packageName),

			//! Is this needed after the previous command?
			// Confirm triggers a confirmation prompt asking the user to verify that they want to proceed with the uninstallation.
			fmt.Sprintf("Uninstall-Package '%s' -Confirm -Force; ", packageName),
		}, "\n")

		// Write the PowerShell command to the file because issues occurred when using the "exec.Command" function directly
		if err := createAndRunPS1FileWithoutOutput("DeleteOldCymetricxPackage.ps1", uninstallOldCymetricxPackageScript); err != nil {
			log.Error().Err(err).Str("packageName", packageName).Msg("Failed to uninstall outdated cymetricx package")
			continue
		}

		log.Info().Str("packageName", packageName).Msg("Successfully uninstalled outdated cymetricx package.")

	}

	log.Info().Msg("Finished uninstalling outdated cymetricx packages.")
}

// uninstallOldCymetricxServicesBackup uninstalls any cymetricx Service that are not the current version.
// This function is run as a backup in case the uninstallOldAgentServicesAndPackages function failed to uninstall the old agent's services.
func uninstallOldCymetricxServicesBackup() {
	log.Info().Msg("Starting to uninstall outdated cymetricx services...")

	// This command returns a list of all the cymetricx services installed on the system. e.g. CYMETRICX  1.4.119
	//! What about returning the "Cymetricx Recovery" service? cuz this looks like it only returns the cymetricx agent service
	fetchCymetricxServicesCommand := "Get-Service '*CYMETRICX  *' | Select-Object -ExpandProperty Name"

	//! Ask Abdel-Wahab about this if he could test it without the use of "Cmd /c" and just use the powershell path directly
	//! Also, when i run this command it gives me an error, but when i run the fetchCymetricxPackagesCommand directly in powershell, it works.
	//! But it works here in the code normally as it is now.
	servicesListOutput, err := exec.Command(cmdPath, "/c ", powerShellPath, "-Command", fetchCymetricxServicesCommand).Output()
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch cymetricx services list.")
		return
	}

	parsedServicesList := bytes.Split(servicesListOutput, []byte("\n"))

	//! Why do we return them as a list? isn't only one package called "CYMETRICX  1.4.119"?
	for _, rawServiceData := range parsedServicesList {

		//! What is this? why do we need to trim it like this?
		serviceName := string(bytes.Trim(bytes.Trim(bytes.TrimSpace(rawServiceData), "��"), "\\0"))

		//! Why do we not stop and delte Cymetricx Recovery service?
		if (serviceName == "CYMETRICX  "+AgentVersion) || (serviceName == "Cymetricx Recovery") || (serviceName == "") || !strings.Contains(serviceName, "CYMETRICX  ") {
			continue
		}

		log.Info().Str("serviceName", serviceName).Msg("Attempting to uninstall outdated cymetricx service...")

		// sc.exe is the service controller for windows responsible to Create, Start, Stop, Query or Delete any Windows SERVICE
		//! Can we get this using exec.LookPath() for more dynamic approach?
		scFilePath := getSCPath()

		uninstallOldCymetricxServiceScript := strings.Join([]string{
			fmt.Sprintf(`%s stop '%s'`, scFilePath, serviceName),
			fmt.Sprintf(`%s delete '%s'`, scFilePath, serviceName),
		}, "\n")

		if err := createAndRunPS1FileWithoutOutput("DeleteOldCymetricxservice.ps1", uninstallOldCymetricxServiceScript); err != nil {
			log.Error().Err(err).Str("serviceName", serviceName).Msg("Failed to uninstall old cymetricx service.")
			continue
		}

		log.Info().Str("serviceName", serviceName).Msg("Successfully uninstalled outdated cymetricx service.")

	}

	log.Info().Msg("Finished uninstalling outdated cymetricx services.")
}

// deletePreviousAgentEntries deletes old files from the cymeetricx directory that
// existed in the old agents. Meaning they are not needed anymore.
func deletePreviousAgentEntries() {
	log.Info().Msg("Starting to delete previous agent files and folders...")

	// Read the files in the cymetricx directory. If there is an error, log it and don't return
	// because os.ReadDir returns a slice of files it was able to read in addition to the error.
	cymetricxEntries, err := os.ReadDir(CymetricxPath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read configuration directory.")
	}

	// If there are no files in the directory, or it wasn't able to read any, log an Error and return.
	if len(cymetricxEntries) == 0 {
		log.Error().Msg("No files found in configuration directory.")
		return
	}

	// Files with these extensions will be deleted.
	extensionsToDelete := []string{".gz", ".zip", ".bat", ".ps1"}

	// Call the function to delete files with specific extentions from the
	// cymetricx directory.
	delteCymetricxFilesWithExtentions(cymetricxEntries, extensionsToDelete)

	// Call the function to delete specific entries that existed in
	// the old agents or must be removed before the agent starts.
	removeListOfSpecificEntries()

	log.Info().Msg("Successfully deleted previous agent files and folders.")
}

// deleteCymetricxFilesWithExtensions removes files from the cymetricx directory
// that either have specific extensions or include "time.txt" in their names.
// The function accepts a slice of directory entries to inspect and a list of
// target extensions.
func delteCymetricxFilesWithExtentions(cymetricxEntries []fs.DirEntry, extensionsToDelete []string) {

	// Create a set of file extensions to delete for efficient lookup.
	// Since Go doesn't have a built-in set data structure, we use a map with empty
	// struct values. Empty structs are used because they don't consume any memory,
	// unlike strings which include pointers and length.
	extensionsMap := make(map[string]struct{})
	for _, ext := range extensionsToDelete {
		extensionsMap[ext] = struct{}{}
	}

	// Iterate over the files in the directory. Delete any file that either has
	// an extension listed above or contains the phrase "time.txt" in its name,
	// such as "system-details-timer.txt".
	for _, cymetricxEntry := range cymetricxEntries {
		excuteDeleteCymetricxFilesWithExtensions(cymetricxEntry, extensionsMap)
	}
}

// executeDeleteCymetricxFilesWithExtensions removes the specified entry if its
// file extension matches any in the extensionsMap.
func excuteDeleteCymetricxFilesWithExtensions(cymetricxEntry fs.DirEntry, extensionsMap map[string]struct{}) {
	cymetricxEntryName := cymetricxEntry.Name()

	// Get the file extention of the current file.
	fileExtension := filepath.Ext(cymetricxEntryName)

	// Check if the file has one of the extensions in the extensionsMap.
	_, ok := extensionsMap[fileExtension]

	// Delete the file if it has one of the extensions in the extensionsMap or
	// has the word "time.txt" in it.
	if strings.Contains(cymetricxEntryName, "time.txt") || ok {
		err := os.Remove(filepath.Join(CymetricxPath, cymetricxEntryName))
		if err != nil {
			log.Warn().Err(err).Str("file", cymetricxEntryName).Msg("Failed to delete file.")
		}
	}
}

// removeListOfSpecificEntries removes specific files and folders that existed in
// the old agents or must be removed before the agent starts.
func removeListOfSpecificEntries() {
	// Define a list of files and directories to remove.
	specificEntriesToRemove := []string{
		"exist_sql.txt",
		"sql_3.txt",
		"Compressed_files",
		"times_files",
		"hash_files",
		"versionfile.txt",
		"restart_failer.bat",
		filepath.Join("Hash Files", "upload_get_uptime.txt"),
		filepath.Join("Time Files", "API_Starttime.txt"),
		filepath.Join("Time Files", "API_Start.txt"),
		"gettasklist.ps1",
		"realservice.csv",
		"Applications.ps1",
		"process_service_w.db",
	}

	// Loop through the list of files and directories to remove them using os.RemoveAll since some of them are directories.
	for _, entry := range specificEntriesToRemove {
		err := os.RemoveAll(filepath.Join(CymetricxPath, entry))
		if err != nil {
			log.Warn().Err(err).Str("file", entry).Msg("Failed to remove file or directory.")
		}
	}
}

// initializeCreateNewAgentEntries initiates the calls to create the new agent
// entries that will be needed for the agent to run.
func initializeCreateNewAgentEntries() {
	createAgentDirectories()
	createNewAgentFilesAndCopyOldDataToThem()

	createVersionFile()
	createAndRunRestartFailure()
}

// createAgentDirectories initializes essential directories for the agent within the CymetricxPath.
// e.g. Hash Files, Compressed Files, and Time Files.
// createAgentDirectories initializes essential directories for the agent within
// the CymetricxPath. e.g. Hash Files, Compressed Files, and Time Files.
func createAgentDirectories() {
	log.Info().Msg("Starting the creation of agent directories...")

	// List of directories to check for their existence and create them if they don't exist.
	dirs := []string{"Hash Files", "Compressed Files", "Time Files", "Agent Files", "Controls"}

	for _, dir := range dirs {
		dir = filepath.Join(CymetricxPath, dir)
		createDirectoryWithPermissions(dir, 0755)
	}

	log.Info().Msg("Finished the creation of agent directories.")
}

// createDirectoryWithPermissions creates the provided directory if it does not
// exist and gives it the provided permissions.
func createDirectoryWithPermissions(dir string, permissions os.FileMode) {

	// Only create the directory if it does not exist.
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {

		// Create the directory.
		if err := os.Mkdir(dir, permissions); err != nil {

			// Exit if any directory fails to be created since directories are
			// essential for the agent to run.
			log.Fatal().Err(err).Msgf("Failed to create directory: %s", dir)
		}

		// The following code only applies on Unix systems.
		// Adjust the directory permissions to 0755 to grant the owner read, write,
		// and execute rights. This step is essential because the Mkdir() function
		// adheres to the system's umask. Unlike Mkdir(), the os.Chmod() function
		// doesn't respect the umask. This adjustment prevents the application from
		// assigning potentially insecure default permissions when creating the directory.
		if err := os.Chmod(dir, permissions); err != nil {
			log.Error().Err(err).Msgf("Failed to change permissions of directory: %s", dir)
			return
		}

		log.Info().Msgf("Successfully created directory: %s", dir)
	}
}

func createNewAgentFilesAndCopyOldDataToThem() {
	if err := createNewCymetricxINIFileAndCopyDataToIt(); err != nil {
		//! Shouldn't this be a fatal error? because there is no ini file created to deal with?
		log.Warn().Err(err).Msg("Failed to create new cymetricx.ini file.")
	}

	if err := renameCymetricxmAgent(); err != nil {
		//! Shouldn't this be a fatal error? because there is no cymetricxm.exe file created to deal with?
		log.Warn().Err(err).Msg("Failed to rename cymetricxm.exe file.")
	}

	type Operation struct {
		src string // source file path
		dst string // destination file path
	}

	operations := []Operation{
		{
			src: fmt.Sprintf("cymetricxService%s.exe", AgentVersion),
			dst: "cymetricxService.exe",
		},
		{
			src: fmt.Sprintf("LGPO%s.exe", AgentVersion),
			dst: "LGPO.exe",
		},
		{
			src: fmt.Sprintf("recovery%s.exe", AgentVersion),
			dst: "recovery.exe",
		},
		{
			src: fmt.Sprintf("cyscan%s.exe", AgentVersion),
			dst: "cyscan.exe",
		},
	}

	for _, op := range operations {
		err := createNewOperationAndCopyDataToIt(op.src, op.dst)
		if err != nil {
			//! Shouldn't this be a fatal error? because there is no files to deal with later? or should we continue and just log the error?
			//! or there could be no cycsan.exe file for example since they have not bought it or something meaning it would always fail?
			log.Warn().Err(err).Msgf("Failed to create new %s file.", op.dst)
		}
	}
}

// copy the contents of the cymetricxAgent.ini file to the new cymetricx.ini file
func createNewCymetricxINIFileAndCopyDataToIt() error {
	cymetrixIniName := fmt.Sprintf("cymetricx%s.ini", AgentVersion)

	filePath := filepath.Join(CymetricxPath, cymetrixIniName)

	if err := copyFile(filePath, "cymetricx.ini"); err != nil {
		return fmt.Errorf("error while copying data to cymetricx.ini file because of: %w", err)
	}

	//! Shouldn't we delete the file now?
	defer os.Remove(filePath)

	return nil
}

// ! Maybe we can replace this with a rename as opposed to copying and deleting?
func createNewOperationAndCopyDataToIt(src, dst string) error {
	log.Info().Msgf("Starting operations for %s...", src)

	if dst != "" {
		output, err := killProcess(dst)
		if err != nil {
			if !strings.Contains(output, "not found") {
				return fmt.Errorf("error killing %s: %w", dst, err)
			}
			log.Warn().Err(err).Msgf("%s was not found, so it was not killed.", dst)
		}
	}

	//! Can we just rename them??

	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("error while copying data to %s file because of: %w", dst, err)
	}

	if err := os.Remove(src); err != nil {
		log.Warn().Err(err).Msgf("Error in removing %s.", src)
	}

	log.Info().Msgf("Successfully handled operations for %s.", src)

	return nil
}

// copyFile copies the contents of the source file to the destination file.
// It creates the destination file if it doesn't exist, and overwrites it if it does.
// It also sets the permissions of the destination file based on the file extension.
//
// Parameters:
//   - src: The path to the source file.
//   - dst: The path to the destination file.
func copyFile(src, dst string) error {
	log.Info().Msgf("Starting to copy data from %s to %s...", src, dst)

	if !fileExists(src) {
		return fmt.Errorf("file %s does not exist", src)
	}

	// Open the source file
	source, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error while opening %s: %w", src, err)
	}
	defer source.Close()

	// Create the destination file
	destination, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("error while creating %s: %w", dst, err)
	}
	defer destination.Close()

	// Copy the contents of the source file to the destination file as a stream of bytes.
	_, err = io.Copy(destination, source)
	if err != nil {
		return fmt.Errorf("error while copying from %s to %s: %w", src, dst, err)
	}

	// Set the permissions of the destination file based on the file extension.
	err = setFilePermissions(dst)
	if err != nil {
		return err
	}

	log.Info().Msgf("Successfully copied data from %s to %s.", src, dst)
	return nil
}

// setFilePermissions sets the file permissions based on the file extension.
// If an exe file, then permissions are set to 0744. Otherwise they are set to 0644.
func setFilePermissions(path string) error {
	// Set permissions based on file extension
	ext := filepath.Ext(path)

	// if the file is executable, then it needs to be written with 0744 permissions
	if ext == ".exe" {
		err := os.Chmod(path, 0744)
		if err != nil {
			return fmt.Errorf("error while setting permissions for %s: %w", path, err)
		}

		log.Info().Msgf("Gave file %s executable permissions.", path)

		return nil
	}

	// if the file is not executable, then it needs to be written with 0644 permissions
	err := os.Chmod(path, 0644)
	if err != nil {
		return fmt.Errorf("error while setting permissions for %s: %w", path, err)
	}

	log.Info().Msgf("Gave file %s read permissions.", path)
	return nil
}

// rename the cymetricx<Agent>.exe file to cymetricxm.exe
func renameCymetricxmAgent() error {
	srcPath := filepath.Join(CymetricxPath, "cymetricxm"+AgentVersion+".exe")
	if !fileExists(srcPath) {
		//! Sholdn't this turn into an error saying that it does not exist, so we could exit outside of the function when any error occurs?
		return fmt.Errorf("file %s does not exist", srcPath)
	}

	dstPath := filepath.Join(CymetricxPath, "cymetricxm.exe")
	err := os.Rename(srcPath, dstPath)
	if err != nil {
		return fmt.Errorf("error renaming cymetricxm.exe file because of: %w", err)
	}

	return nil
}

// kill the process with the given name
func killProcess(name string) (string, error) {
	// kill the process with the given name
	cmd := exec.Command(cmdPath, "/c", `C:\Windows\System32\taskkill.exe`, "/F", "/IM", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("error while killing process %s: %w", name, err)
	}

	return string(output), nil
}

// create a file that holds the version of the cymetricx agent
func createVersionFile() {
	version := fmt.Sprintf("CYMETRICX  %s", AgentVersion)
	versionFilePath := filepath.Join(CymetricxPath, "VersionFile.txt")
	if err := os.WriteFile(versionFilePath, []byte(version), 0644); err != nil {
		log.Error().Err(err).Msg("Failed to write to VersionFile.txt.")
		return
	}
}

// create a file that will restart the service if it fails
// ! Does this really need a bat file to do this? can't we just do it directly?
func createAndRunRestartFailure() {
	log.Info().Msg("Starting to create restart failer batch file...")

	// get the path to sc.exe
	scFilePath := getSCPath()

	// Build the restart command string that instructs the service control manager to restart the CYMETRICX service upon failure.
	// It will restart the service if it fails 3 times in 24 hours, with a 3 minute delay between each restart,
	// where after 24 hours the failure count is reset and the process starts again if it were to have stopped before due to failing 3 times in 24 hours.
	restartCommand := strings.Join([]string{
		scFilePath, // Path to sc.exe.
		`failure`,  // Subcommand to configure service failure actions.

		//! I see no service called "CYMETRICX" in the services list, so how would this work?
		`"CYMETRICX"`, // Name of the service to be configured.

		//! How about we increase the time for this for the system to maybe stabilize?
		// Specifies the failure actions and delay times. Where the delay time
		// is in milliseconds. (3 minutes).
		`"actions=restart/180000/restart/180000/restart/180000"`,

		//! How about we decrease the time for this so it would restart faster?
		// Specifies the time after which the failure count should be reset,
		// which is 24 hours in this case.
		`"reset=86400"`,
	}, " ")

	if err := createAndRunBatScriptWithoutOutput("RestartFailure.bat", restartCommand); err != nil {
		log.Error().Err(err).Msg("Failed to create and run the restart failer batch command.")
		return
	}

	log.Info().Msg("Successfully created and executed restart failer batch file.")
}

// processCymetricxIniOnStartup manages the decryption and updating of the
// cymetricx.ini file on startup. It returns the decrypted and updated ini
// strucured data. It also encrypts the data and writes it to the cymetricx.ini
// file in the CymetricxPath.
func processCymetricxIniOnStartup() ini.IniConfig {
	log.Info().Msg("Starting to update and decrypt ini file...")

	const key = "1zxYAtvQ2H37wUmP3TueDsCigy54rets"

	// decrypt the ini file using the key.
	iniData, err := decryptAndParseCymetricxIni(key)
	if err != nil {
		log.Fatal().Err(err).Msg("Error decrypting ini file")
	}

	iniData = updateAndEncryptIniFile(iniData)

	log.Info().Msg("Successfully updated and encrypted ini file.")

	return iniData
}

// updateAndEncryptIniFile updates the provided iniData with new CID and password
// values if needed. It then encrypts the data and writes it to the cymetricx.ini
func updateAndEncryptIniFile(iniData ini.IniConfig) ini.IniConfig {
	var updated bool

	cidValue := getIniValue(&iniData, "Identification", "CID")
	if cidValue == "" {
		value := getCymetricxRegistryKeyValues("CID")
		setIniData(&iniData, "Identification", "CID", value)
		updated = true
	}

	APIURL := getIniValue(&iniData, "API", "APIURL")
	if APIURL == "" {
		value := getCymetricxRegistryKeyValues("APIURL")
		setIniData(&iniData, "API", "APIURL", value)
		updated = true
	}

	keyPath := `SOFTWARE\CYMETRICX\CYMETRICX`
	_, err := iniData.Value("API", "PortRedis")
	if err != nil {
		// Set the registry value to the default value of "8449".
		if err := setRegistryKeyValue(keyPath, "PortRedis", "8449"); err != nil {
			log.Error().Err(err).Msg("Failed to set the port value in the registry.")
		}
		// Add the "Port" key to the "API" section in the INI file.
		setIniData(&iniData, "API", "PortRedis", "8449")
		updated = true
	}

	if updated {
		// This operation ensures that the updated structure is saved to the cymetricx.ini file.
		if err := encryptDataAndWriteToCymetricxIni(iniData); err != nil {
			log.Fatal().Err(err).Msg("Error encrypting ini file")
		}
	}

	return iniData
}

// decryptAndParseCymetricxIni attempts to decrypts the cymetricx.ini file using
// the provided key. It then parses the decrypted content and returns it as a
// structured INI file as needed by the agent.
func decryptAndParseCymetricxIni(key string) (ini.IniConfig, error) {

	// the path for the cymetricx.ini file
	cymetricxINIPath := filepath.Join(CymetricxPath, "cymetricx.ini")

	// decrypt the ini file using the key and get back the raw ini data
	iniDataRaw, err := decryptFile(cymetricxINIPath, key)
	if err != nil {
		return nil, fmt.Errorf("error decrypting ini file: %w", err)
	}

	// parse the ini data and return it as a map of either as structured ini data
	// or as raw data under "Settings" section
	paredIniData, err := ini.ParseIniData(iniDataRaw)
	if err != nil {
		return nil, fmt.Errorf("error parsing ini data: %w", err)
	}

	return paredIniData, nil
}

// updateConfigWithCMDAndExitIfRequired updates the cymetricx.ini file based on
// command-line flags. It also updates the service if it's disabled in the INI file.
// If anything updated, it exits the agent. Otherwise, it reutnr the updated ini data.
func updateConfigWithCMDAndExitIfRequired(iniData ini.IniConfig, cmdFlags CMDFlags) ini.IniConfig {
	var ifExit bool
	iniData, ifExit = updateConfig(iniData, cmdFlags)
	if ifExit {

		// Save all of the updated data to the INI file and encrypt it using the first key.
		if err := encryptDataAndWriteToCymetricxIni(iniData); err != nil {
			log.Fatal().Err(err).Msg("Error encrypting ini file")
		}

		// Restart the service to apply the new changes.
		if err := createAndRunRestartServiceBat(); err != nil {
			log.Fatal().Err(err).Msg("Failed to create and run restart service batch command.")
		}

		// Exit this process.
		os.Exit(0)
	}

	return iniData
}

// updateConfigAndService updates the cymetricx.ini file based on command-line flags.
// if given. It also updates the service if it's disabled in the INI file.
// if anything updated, it returns true, meaning that the agent should exit.
func updateConfig(iniData ini.IniConfig, cmdFlags CMDFlags) (ini.IniConfig, bool) {
	var updated bool
	iniData, updated = updateAPIAndCIDByCMDAndPortRedisFlags(iniData, cmdFlags)

	return iniData, updated
}

func updateAPIAndCIDByCMDAndPortRedisFlags(iniData ini.IniConfig, cmdFlags CMDFlags) (ini.IniConfig, bool) {
	updated := false

	if cmdFlags.APIURL != "" {
		setIniData(&iniData, "API", "APIURL", cmdFlags.APIURL)
		setCymetricxRegistryKeyValues("APIURL", cmdFlags.APIURL)
		log.Debug().Msgf("Updated API URL to %s", cmdFlags.APIURL)
		fmt.Println("Updated API URL successfully.")
		updated = true
	}

	if cmdFlags.CID != "" {
		setIniData(&iniData, "Identification", "CID", cmdFlags.CID)
		setCymetricxRegistryKeyValues("CID", cmdFlags.CID)
		log.Debug().Msgf("Updated CID to %s", cmdFlags.CID)
		fmt.Println("Updated CID successfully.")
		updated = true
	}

	if cmdFlags.PortRedis != "" {
		setIniData(&iniData, "API", "PortRedis", cmdFlags.PortRedis)
		setCymetricxRegistryKeyValues("PortRedis", cmdFlags.PortRedis)
		log.Debug().Msgf("Updated Port to %s", cmdFlags.PortRedis)
		fmt.Println("Updated Port successfully.")
		updated = true
	}

	return iniData, updated
}

// setRegistryKeyValue sets a specified value in the Windows registry.
// It sets the valueName to the valueData in the keyPath.
func setRegistryKeyValue(keyPath, valueName, valueData string) error {
	log.Info().Msgf("Setting registry key value: Path=%s, Name=%s, Data=%s", keyPath, valueName, valueData)

	// Create new registry key inside of the registry key path inside of the HKEY_LOCAL_MACHINE
	// with the permissions to be able to set a value to that key.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("error opening registry key at path %s: %w", keyPath, err)
	}

	// Close the registry key after we are done with it.
	defer func() {
		if err := key.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close the registry key.")
		}
	}()

	// Set the value for the specified key.
	if err := key.SetStringValue(valueName, valueData); err != nil {
		return fmt.Errorf("error setting registry value for %s: %w", valueName, err)
	}

	log.Info().Msgf("Successfully set registry value: Path=%s, Name=%s, Data=%s", keyPath, valueName, valueData)
	return nil
}

func getRegistryKeyValue(keyPath, valueName string) (string, error) {
	log.Info().Msgf("Getting registry key value: Path=%s, Name=%s", keyPath, valueName)

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("error opening registry key at path %s: %w", keyPath, err)
	}

	defer func() {
		if err := key.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close the registry key.")
		}
	}()

	value, _, err := key.GetStringValue(valueName)
	if err != nil {
		return "", fmt.Errorf("error getting registry value for %s: %w", valueName, err)
	}

	log.Info().Msgf("Successfully got registry value: Path=%s, Name=%s, Data=%s", keyPath, valueName, value)
	return value, nil
}

// setServiceRegistryKeyForImagePath sets the "ImagePath" value in the registry for a service.
func setServiceRegistryKeyForImagePath(registryKey, executablePath string) {

	// Set the ImagePath value to the executable path of cymetrixcm.exe.
	// This is necessary for the service manager to locate the executable when starting or restarting the service.
	// Without this, the service start or restart operations will fail.
	cymetricxmPath := filepath.Join(CymetricxPath, executablePath)
	cymetricxmPath = `"` + cymetricxmPath + `"`
	registryKeyPath := fmt.Sprintf(`System\CurrentControlSet\Services\%s`, registryKey)
	// return setRegistryKeyValue(registryKeyPath, "ImagePath", executablePath)
	if err := setRegistryKeyValue(registryKeyPath, "ImagePath", cymetricxmPath); err != nil {

		log.Error().Err(err).Msg("Error updating registry")
	}

}

// setAPIandCID sets the APIURL and CID in the registry.
func setCymetricxRegistryKeyValues(valueName, valueData string) {

	keyPath := `SOFTWARE\CYMETRICX\CYMETRICX`
	if err := setRegistryKeyValue(keyPath, valueName, valueData); err != nil {

		//! This should be fatal, correct?
		log.Fatal().Err(err).Msg("Error updating registry")
	}

}

// setCymetricxRegistryKeyValuesAPIandCID I used it here to make sure that the values inside Registry  are 100% correct and there are no errors
// sets the APIURL and CID in the registry.
func setCymetricxRegistryKeyValuesAPIandCID(APIURL string, serial string) {
	// Define the path to the key

	keyPath := `SOFTWARE\CYMETRICX\CYMETRICX`
	if err := setRegistryKeyValue(keyPath, "APIURL", APIURL); err != nil {
		log.Error().Err(err).Msg("Error updating registry APIURL ")
	}
	if err := setRegistryKeyValue(keyPath, "CID", serial); err != nil {
		log.Error().Err(err).Msg("Error updating registry CID ")
	}

}

func getCymetricxRegistryKeyValues(valueName string) string {

	keyPath := `SOFTWARE\CYMETRICX\CYMETRICX`
	value, err := getRegistryKeyValue(keyPath, valueName)
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting registry")
	}

	return value
}

func getIniValue(iniData *ini.IniConfig, section, key string) string {
	value, err := iniData.Value(section, key)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error getting %s value from ini file \nAborting ...", key)
	}
	return value
}

func setIniData(iniData *ini.IniConfig, section, key, value string) {
	if err := iniData.Set(section, key, value); err != nil {
		log.Fatal().Err(err).Msgf("Error setting %s value in ini file \nAborting ...", key)
	}
}

// encryptDataAndWriteToCymetricxIni encrypts the provided iniData using a
// certain key and writes it to the cymetricx.ini file in the CymetricxPath.
func encryptDataAndWriteToCymetricxIni(iniData ini.IniConfig) error {

	filePath := filepath.Join(CymetricxPath, "cymetricx.ini")

	// Key used to encrypt and decrypt the ini file in the new agents going forward.
	const key = "1zxYAtvQ2H37wUmP3TueDsCigy54rets"

	// Convert the map of sections and keys into a sequence of strings.
	// This transformation prepares the data for writing to the INI file.
	iniDataAsLines := iniData.DataAsLines()

	err := encryptDataAndWriteToFile([]byte(iniDataAsLines), key, filePath)
	if err != nil {
		return err
	}

	return nil
}

// encryptDataAndWriteToFile encrypts the provided data using the key and writes it to the provided file path.
func encryptDataAndWriteToFile(data []byte, key string, filePath string) error {

	// Encrypt the data using the key
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return fmt.Errorf("error encrypting ini configs: %w", err)
	}

	// Write the encrypted data to a file
	err = createFileWithPermissionsAndWriteToIt(filePath, string(encryptedData), 0744)
	if err != nil {
		return fmt.Errorf("error writing encrypted cymetricx.ini file: %w", err)
	}

	return nil
}

// createFileWithPermissions creates a new file with the specified permissions
// not adhering to the system's umask. It takes the full path of the file to be
// created and the permissions to set for the new file. The permissions should
// be specified in octal format e.g. 0644.
//
// Example Usage:
//
//	createFileWithPermissions("test.txt", 0644)
func createFileWithPermissions(filePath string, permissions os.FileMode) (*os.File, error) {
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("error creating file %s: %w", filePath, err)
	}

	// Set the file permissions using the os.Chmod function in case of umask
	// exiting and messing up the permissions
	if err := os.Chmod(filePath, permissions); err != nil {
		return nil, fmt.Errorf("error setting file permissions for file %s: %w", filePath, err)
	}

	return file, nil
}

func createAndRunRestartServiceBat() error {
	// creeateRestartServiceBat creates a batch file that will restart the service
	cymetricxmAgentPath := strconv.Quote(filepath.Join(CymetricxPath, "cymetricxm.exe"))
	restartData := cymetricxmAgentPath + " restart " + "CYMETRICX"

	if err := createFileWithPermissionsAndWriteToIt("restartservice.bat", restartData, 0744); err != nil {
		return err
	}

	defer os.Remove("restartservice.bat")
	filePath := filepath.Join(CymetricxPath, "restartservice.bat")
	cmd := exec.Command(filePath)
	_, err := cmd.Output()
	if err != nil {
		return err
	}

	return nil
}

// decryptFile decrypts the passed file using the provided key.
// It returns the decrypted content of the file as a byte array.
func decryptFile(filePath string, key string) ([]byte, error) {

	// Read the encrypted INI file.
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read file %s: %w", filePath, err)
	}

	// Initialize an AES cipher algorithm with the provided key to be used to decrypt the INI file.
	cipherBlock, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("could not create new cipher: %w", err)
	}

	// Implement Galois/Counter Mode (GCM) for added authentication layer, ensuring
	// the data integrity during the encryption/decryption process. This prevents
	// any unauthorized modifications to the data.
	cipherAEAD, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, fmt.Errorf("could not create new gcm: %w", err)
	}

	// Extract the nonce from the beginning of the encrypted data.
	nonceSize := cipherAEAD.NonceSize()

	// Check if the encrypted data is long enough to contain the nonce.
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encryptedINIData is too short to contain the nonce: %w", err)
	}

	// Extract the nonce and encrypted message from the encrypted data.
	nonce, encryptedMessage := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Decrypt the content by opening the encrypted message using the nonce.
	unencryptedData, err := cipherAEAD.Open(nil, nonce, encryptedMessage, nil)
	if err != nil {
		return nil, fmt.Errorf("could not open encrypted message: %w", err)
	}
	return unencryptedData, nil
}

// encryptData encrypts the provided data using the key and returns the encrypted data.
func encryptData(unEncryptedData []byte, key string) ([]byte, error) {

	// Initialize an AES cipher algorithm with the provided key to be used to decrypt the INI file.
	keyCipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("error creating key cipher: %w", err)
	}

	// Use the Galois/Counter Mode (GCM) to add another layer of authentication
	// to the encryption/decryption process to make sure the data has not been tampered with.
	keyGCM, err := cipher.NewGCM(keyCipher)
	if err != nil {
		return nil, fmt.Errorf("error creating key GCM: %w", err)
	}

	// Generate a random one time used series of bytes to be used as a nonce.
	// This added layer of security is used to make sure the same data encrypted
	//  with the same key does not produce the same encrypted data.
	keyNonce := make([]byte, keyGCM.NonceSize())

	// Read random bytes from the crypto/rand reader into the nonce.
	// Meaning that the nonce will be a random series of bytes extracted from
	// the crypto/rand reader.
	if _, err = io.ReadFull(cRand.Reader, keyNonce); err != nil {
		return nil, fmt.Errorf("error reading key random bytes: %w", err)
	}

	// Combine the nonce and encrypted data and seal them together.
	// It appends the encrypted data to the nonce and returns the result.
	newEncryptedData := keyGCM.Seal(keyNonce, keyNonce, unEncryptedData, nil)

	return newEncryptedData, nil
}

// initializeAndAuthenticate initializes the necessary variables and performs authentication
// before returning the serial number.
// If any errors occur during initialization or authentication, the function will log a fatal error.
// The serial number is returned as a string.
func initializeAndAuthenticate(iniData ini.IniConfig) string {
	serial := getIniValue(&iniData, "Identification", "CID")
	apiURLFlask = getIniValue(&iniData, "API", "APIURL")

	// Same as the Flask API URL but with the cymetricxapi replaced with cymetricx_api
	apiURLLaravel = strings.Replace(apiURLFlask, "cymetricxapi", "cymetricx_api", 1)

	loginPassword = getIniValue(&iniData, "Security", "PasswordLogin")

	isValid, err := checkIfSerialValidV2(serial)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to check if CID is valid.")
	}

	if !isValid {
		log.Fatal().Msg("Serial is not valid.")
	}

	// id, err = generateIDAndWriteItToIDTxtFile()
	id, err = generateIDAndWriteItToIDTxtFile2("id")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate UUID and write it to id.txt file.")
	}

	authenticationTokenV1 = loginAndReturnTokenV1(loginPassword)
	if authenticationTokenV1 == "" {
		log.Fatal().Msg("Falied to login to Flask server")
	}

	authenticationTokenV2, tokenExpirationData, err = loginAndReturnTokenV2(loginPassword)
	// if err != nil  and error does not contain the string "Duplicate UUID"
	if err != nil && !strings.Contains(err.Error(), "Duplicate UUID") {
		log.Fatal().Err(err).Msg("Failed to login to laravel server and return token.")
	}

	// If the error contains the string "Duplicate UUID", then the login should be retried
	// And the id.txt and the start up folders should be emptied.
	if err != nil && strings.Contains(err.Error(), "Duplicate UUID") {
		if err := handleDuplicatedUUID(); err != nil {
			time.Sleep(30 * time.Second)
			log.Fatal().Err(err).Msg("Failed to handle duplicated UUID.")
		}
	}

	return serial
}

func handleDuplicatedUUID() error {
	log.Info().Msg("Handling duplicated UUID ...")

	// Remove the id.txt file
	idPath := filepath.Join(CymetricxPath, "id.txt")
	if err := os.Remove(idPath); err != nil {
		return fmt.Errorf("failed to remove id.txt file: %w", err)
	}

	// Empty the startup folders
	foldersToEmpty := []string{"Hash Files", "Compressed Files", "Time Files"}
	for _, folder := range foldersToEmpty {
		err := emptyDirectory(folder)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to empty %s folder.", folder)
		}
	}

	// Regenerate the ID and write it to the id.txt file
	var err error
	// id, err = generateIDAndWriteItToIDTxtFile()
	id, err = generateIDAndWriteItToIDTxtFile2("id")
	if err != nil {
		return fmt.Errorf("failed to generate UUID and write it to id.txt file: %w", err)
	}

	// Retry the login and return the token
	authenticationTokenV2, tokenExpirationData, err = loginAndReturnTokenV2(loginPassword)
	if err != nil {
		return fmt.Errorf("failed to login to laravel server and return token after duplicate UUID retry: %w", err)
	}

	return nil

}

type ApiSerialResponse struct {
	IsValid bool   `json:"isValid"`
	Message string `json:"message,omitempty"`
}

// checkIfSerialValid checks if the serial number is valid or not by sending a request to the server
func checkIfSerialValidV2(serial string) (bool, error) {
	log.Info().Msg("Starting to check if serial is valid ...")

	responseBody, err := prepareAndExecuteSerialHTTPRequest("POST", "checkSerial", serial, 10)
	if err != nil {
		return false, err
	}

	// Unmarshal the JSON response into the ApiResponse struct
	var response ApiSerialResponse
	err = json.Unmarshal(responseBody.Bytes(), &response)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshed response body: %w", err)
	}

	// Check the success field in the response
	if !response.IsValid {
		log.Debug().Msgf("Serial is not valid. Error: %s", response.Message)
		return false, nil
	}

	log.Info().Msg("Successfully checked if Serial is valid. It is valid.")
	return true, nil
}

//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------
//% --------------------------------------------------------------------------------------------------------------------------------------------------------------------

// loginAndReturnTokenV1 function to loginAndReturnTokenV1 to the server by sending the id and password and returning a token to be used in the next requests
func loginAndReturnTokenV1(passwordlogin string) string {
	log.Info().Msg("Starting the login process.")

	loginData := generateLoginDataV1(passwordlogin)
	jsonPayload, err := createJsonPayloadV1(loginData)
	if err != nil {
		log.Error().Err(err).Stack().Msg("Failed to marshal login payload to JSON.")
		return ""
	} else {
		log.Debug().Msg("Successfully marshaled login payload to JSON.")
	}

	req, cancel, err := createHTTPRequestWithTimeout("POST", "login", jsonPayload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create HTTP request with timeout for login.")
		return ""
	}
	// The cancel function must be called to free resources of the context whether the operation is successful or not
	// before needing to wait for the timeout to finish and free the resources itself saving time and no memory leaks
	defer cancel()

	token, err := executeLoginRequestV1(req)
	if err != nil {
		log.Error().Err(err).Stack().Msg("Failed to execute login request.")
		return ""
	}

	log.Info().Msg("Successfully retrieved token through login.")
	return token
}

// executeLoginRequestV1 retries the login request 10 times before returning an error.
// It sends the request using custom Insecure HTTP Client and reads the response body and return the token.
func executeLoginRequestV1(req *http.Request) (string, error) {
	log.Info().Msg("Starting the login request execution.")

	for retries := 0; retries < 10; retries++ {
		// Only retry if the request fails since other errors are all deterministic so no need to retry
		resp, err := sendCustomHTTPClientRequest(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			log.Error().Err(err).Stack().Msgf("Error sending POST request to api/login on attempt %d.", retries+1)
			// Calculate backoff time exponentially, where each time the backoff is doubled before retrying
			backoff := time.Duration(math.Pow(2, float64(retries))) * time.Second
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}
			log.Info().Msgf("Retrying after %s.", backoff)
			time.Sleep(backoff)
			continue
		}
		defer resp.Body.Close()

		var responseBody bytes.Buffer
		_, err = io.Copy(&responseBody, resp.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read response body from api/login.")
			return "", err
		}

		log.Debug().Msg("Successfully retrieved response body from api/login.")
		return responseBody.String(), nil
	}

	log.Error().Msg("Failed to send request to api/login after reaching max tries.")
	return "", fmt.Errorf("error sending request to api/login after reaching max tries")
}

// generateLoginDataV1 generates the login data including ID and Password to be sent to the server as one string
func generateLoginDataV1(passwordlogin string) string {
	newPassword := passwordlogin + id
	passwordHash := sha256.Sum256([]byte(newPassword))
	generatedPassword := fmt.Sprintf("%x", passwordHash)
	loginData := strings.Join([]string{
		"id:" + id,
		"passwordlogin:" + generatedPassword,
	}, "\n")
	return loginData
}

// holdingAgentForever is used so it be the last for loop that keeps the agent running. It checks every 5 minutes if the value of stop has changed,
// If so, it would break, leading to the agnet stopping and exiting
// Only then, the service would run it again by itself, cuz this is what services do
func holdingAgentForever() {

	log.Info().Msg("Starting the holding agent forever loop.")
	for {
		time.Sleep(5 * time.Minute)
	}
}

// startGoRoutines starts all the go routines that are responsible for the agent's functionality
func startGoRoutines(iniData ini.IniConfig, serialNumber string, cmdFlags CMDFlags) {
	log.Info().Msg("Starting the go routines...")

	// This is responsible for running and dealing with the "Cymetricx Recovery" service that runs next to "Cyemtricx agent"
	// if err := handleCymetricxRecoveryServiceStatus(cmdFlags); err != nil {
	// 	// We don't to break out of the for loop if the cymetricx recovery failed to run because we care more about the
	// 	// cymetricx agent itself to be running But we would still want to log it in the logs to check why that happened
	// 	log.Warn().Err(err).Msg("Failed to handle cymetricx recovery service status.")
	// }

	if err := callRealTimeAndProcessFeatureSettings(serialNumber); err != nil {
		log.Error().Err(err).Msg("Failed to call real time and process feature settings before starting go routines.")
	}

	// Call this first because it pulls configuration values for other functions.
	go realTimeWebsiteInteractionThreadV2(serialNumber)

	go sendOnlineStatusToServerV2()
	go realTimeRedisWebsiteInteractionThreadV2(iniData, serialNumber)
	go addRunningProcessesAndServicesToDB()
	go startCollectAndUploadMonitoringDataAndComputerUpTime()
	go scanActiveDirectoryAndLGPOAndUploadThem()
	go startInitialFullSystemDataAndDetailsScan()
	go startPeriodicUploadLogs()
	go checkingUSNPeriodecly()

	go watchDNSFile()
	go monitorAndDetectChangesForLocalUsers()
	go monitorInstalledUninstalledApplications()
	go monitorNetworkInterfaces()
	go monitorServiceChanges()

	log.Info().Msg("Successfully started the go routines.")
}

type serviceInfo struct {
	name string
}

// Query all services currently available in the Service Control Manager
func queryServices() ([]serviceInfo, error) {

	var services []serviceInfo

	// Open the Service Control Manager
	scmHandle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("failed to open service manager: %w", err)
	}
	defer windows.CloseServiceHandle(scmHandle)

	// Query all services
	var bytesNeeded, servicesReturned, resumeHandle uint32
	for {
		var buffer [1 << 14]byte // 16KB buffer
		err := windows.EnumServicesStatusEx(
			scmHandle,
			windows.SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32,
			windows.SERVICE_STATE_ALL,
			&buffer[0],
			uint32(len(buffer)),
			&bytesNeeded,
			&servicesReturned,
			&resumeHandle,
			nil,
		)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return nil, fmt.Errorf("failed to enumerate services: %w", err)
		}

		serviceArray := (*[1 << 20]windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buffer[0]))[:servicesReturned:servicesReturned]
		for _, service := range serviceArray {
			serviceName := windows.UTF16ToString((*[256]uint16)(unsafe.Pointer(service.ServiceName))[:])
			services = append(services, serviceInfo{name: serviceName})
		}

		if err != windows.ERROR_MORE_DATA {
			break
		}
	}

	return services, nil
}

// Monitor services for additions or removals
func monitorServiceChanges() {
	// trigger := func(event, name string) {
	// 	log.Info().Str("Event", event).Str("Service", name).Msg("Service event detected")
	// }

	lastServiceSet := make(map[string]struct{})

	// Initial service query
	services, err := queryServices()
	if err != nil {
		log.Fatal().Err(err).Msg("Error querying services")
	}

	for _, service := range services {
		lastServiceSet[service.name] = struct{}{}
	}

	log.Info().Msg("Monitoring for added or removed services...")

	for {
		currentServiceSet := make(map[string]struct{})

		// Query the services again
		services, err := queryServices()
		if err != nil {
			log.Error().Err(err).Msg("Error querying services")
			time.Sleep(1 * time.Second)
			continue
		}

		for _, service := range services {
			currentServiceSet[service.name] = struct{}{}
		}

		// Detect added services
		for name := range currentServiceSet {
			if _, exists := lastServiceSet[name]; !exists {
				log.Info().Str("Service", name).Msg("Service added")
				if err := getAndCompressAndUploadAllWindowsServices(); err != nil {
					log.Error().Err(err).Msg("Failed to compress and upload windows services.")
				}
			}
		}

		// Detect removed services
		for name := range lastServiceSet {
			if _, exists := currentServiceSet[name]; !exists {
				log.Info().Str("Service", name).Msg("Service removed")
				if err := getAndCompressAndUploadAllWindowsServices(); err != nil {
					log.Error().Err(err).Msg("Failed to compress and upload windows services.")
				}
			}
		}

		// Update the last known state
		lastServiceSet = currentServiceSet

		time.Sleep(1 * time.Second)
	}
}

func getAndSendNetworkInterfaces() error {
	log.Info().Msg("Starting the process of uploading Network Interfaces...")

	// Get the local DNS mappings.
	networkInterfaces, err := getNetworkInterfaceInfo()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %w", err)
	}

	networkInterfacesMap := map[string]interface{}{
		"network": networkInterfaces,
	}

	jsonPayload, err := json.Marshal(networkInterfacesMap)
	if err != nil {
		return fmt.Errorf("failed to marshal network interfaces: %w", err)
	}

	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityForWindowsV2("POST", "upload-network-data/"+id, jsonPayload, 10)
	if err != nil {
		log.Error().Err(err).Msg("Error while uploading Network Interfaces.")
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload network interfaces: %w", err)
	}

	// Check if the response body contains the string "success".
	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload network interfaces: %w", err)
	}

	log.Info().Msg("Successfully uploaded Network Interfaces.")

	return nil
}

func monitorNetworkInterfaces() {
	log.Info().Msg("Starting the process of monitoring network interfaces...")

	previousState, err := getInterfacesState()
	if err != nil {
		log.Error().Err(err).Msg("Error getting initial state")
		return
	}

	for {
		currentState, err := getInterfacesState()
		if err != nil {
			log.Error().Err(err).Msg("Error getting current state")
			continue
		}

		changes := compareStates(previousState, currentState)
		if len(changes) > 0 {
			if err := getAndSendNetworkInterfaces(); err != nil {
				log.Error().Err(err).Msg("Failed to upload network interfaces.")
			}
		}

		previousState = currentState
		time.Sleep(20 * time.Second) // Poll every 2 seconds
	}
}

func getInterfacesState() (map[string]InterfaceState, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	state := make(map[string]InterfaceState)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		var ips []string
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil {
				ips = append(ips, ip.String())
			}
		}

		state[iface.Name] = InterfaceState{IPs: ips}
	}

	return state, nil
}

func compareStates(oldState, newState map[string]InterfaceState) []string {
	var changes []string

	for name, newIface := range newState {
		oldIface, exists := oldState[name]
		if !exists {
			changes = append(changes, fmt.Sprintf("Interface added: %s", name))
			continue
		}

		oldIPs := make(map[string]bool)
		for _, ip := range oldIface.IPs {
			oldIPs[ip] = true
		}

		for _, ip := range newIface.IPs {
			if !oldIPs[ip] {
				changes = append(changes, fmt.Sprintf("IP change on interface %s: %v -> %v", name, oldIface.IPs, newIface.IPs))
				break
			}
		}
	}

	for name := range oldState {
		if _, exists := newState[name]; !exists {
			changes = append(changes, fmt.Sprintf("Interface removed: %s", name))
		}
	}

	return changes
}

type InterfaceState struct {
	IPs []string
}

// func monitorInstalledUninstalledApplications() {
// 	log.Info().Msg("Starting the process of monitoring installed and uninstalled applications...")

// 	var (
// 		advapi32                    = syscall.NewLazyDLL("advapi32.dll")
// 		procRegNotifyChangeKeyValue = advapi32.NewProc("RegNotifyChangeKeyValue")
// 	)

// 	const (
// 		KEY_NOTIFY                 = 0x0010
// 		REG_NOTIFY_CHANGE_NAME     = 0x0001
// 		REG_NOTIFY_CHANGE_LAST_SET = 0x0004
// 	)

// 	// // Placeholder for the upload function
// 	// upload := func(appKey string, action string) {
// 	// 	log.Info().Str("Application", appKey).Str("Action", action).Msg("Trigger detected. Uploading changes...")
// 	// }

// 	// Helper function to get installed applications
// 	getStoreApplications := func(key registry.Key) (map[string]struct{}, error) {
// 		apps := make(map[string]struct{})
// 		subKeys, err := key.ReadSubKeyNames(-1)
// 		if err != nil {
// 			return nil, err
// 		}
// 		for _, subKeyName := range subKeys {
// 			apps[subKeyName] = struct{}{}
// 		}
// 		return apps, nil
// 	}

// 	// Helper function to monitor a registry key
// 	monitorRegistryKey := func(hKey windows.Handle) {
// 		key := registry.Key(hKey)
// 		defer key.Close()

// 		oldSnapshot, err := getStoreApplications(key)
// 		if err != nil {
// 			log.Error().Err(err).Msg("Error taking initial snapshot")
// 			return
// 		}

// 		for {
// 			// Wait for registry changes
// 			status, _, err := procRegNotifyChangeKeyValue.Call(
// 				uintptr(hKey),
// 				1, // bWatchSubtree
// 				REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET,
// 				0,
// 				0,
// 			)
// 			if status != 0 {
// 				log.Error().Err(err).Msg("Error waiting for registry change")
// 				return
// 			}

// 			newSnapshot, err := getStoreApplications(key)
// 			if err != nil {
// 				log.Error().Err(err).Msg("Error taking new snapshot")
// 				return
// 			}

// 			// Compare snapshots to detect changes
// 			for appKey := range newSnapshot {
// 				if _, found := oldSnapshot[appKey]; !found {
// 					log.Info().Msgf("Application Installed: %s", appKey)
// 					if err := getAndCompressAndUploadAllInstalledApplications(); err != nil {
// 						log.Error().Err(err).Msg("Failed to compress and upload all installed applications.")
// 					}

// 				}
// 			}

// 			for appKey := range oldSnapshot {
// 				if _, found := newSnapshot[appKey]; !found {
// 					log.Info().Msgf("Application Uninstalled: %s", appKey)
// 					if err := getAndCompressAndUploadAllInstalledApplications(); err != nil {
// 						log.Error().Err(err).Msg("Failed to compress and upload all installed applications.")
// 					}
// 				}
// 			}

// 			oldSnapshot = newSnapshot
// 		}
// 	}

// 	// Get the user ID for current user
// 	userID, err := getWindowsUserIDV2()
// 	if err != nil {
// 		log.Error().Err(err).Msg("Error getting user ID")
// 		return
// 	}

// 	// Add all registry paths from getInstalledApplicationsForAllAndCurrentUserV2 and include user-specific keys
// 	keys := []struct {
// 		baseKey registry.Key
// 		path    string
// 	}{
// 		// Existing keys
// 		{registry.CURRENT_USER, `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`},
// 		{registry.LOCAL_MACHINE, `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`},

// 		// Additional keys based on getInstalledApplicationsForAllAndCurrentUserV2
// 		{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
// 		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
// 		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
// 		{registry.CURRENT_USER, `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},

// 		// User-specific registry paths using userID
// 		{registry.USERS, fmt.Sprintf(`%s\Software\Microsoft\Windows\CurrentVersion\Uninstall`, userID)},
// 		{registry.USERS, fmt.Sprintf(`%s\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, userID)},
// 	}

// 	// Monitor all registry keys
// 	for _, keyInfo := range keys {
// 		key, err := registry.OpenKey(keyInfo.baseKey, keyInfo.path, registry.READ|KEY_NOTIFY)
// 		if err != nil {
// 			log.Error().Err(err).Msg("Error opening registry key")
// 			continue
// 		}
// 		hKey := windows.Handle(key)
// 		go monitorRegistryKey(hKey)
// 	}
// }

var seenApplications = struct {
	sync.Mutex
	data map[string]time.Time
}{
	data: make(map[string]time.Time),
}

func monitorInstalledUninstalledApplications() {
	log.Info().Msg("Starting the process of monitoring installed and uninstalled applications...")

	var (
		advapi32                    = syscall.NewLazyDLL("advapi32.dll")
		procRegNotifyChangeKeyValue = advapi32.NewProc("RegNotifyChangeKeyValue")
	)

	const (
		KEY_NOTIFY                 = 0x0010
		REG_NOTIFY_CHANGE_NAME     = 0x0001
		REG_NOTIFY_CHANGE_LAST_SET = 0x0004
	)

	// Helper function to get installed applications
	getStoreApplications := func(key registry.Key) (map[string]struct{}, error) {
		apps := make(map[string]struct{})
		subKeys, err := key.ReadSubKeyNames(-1)
		if err != nil {
			return nil, err
		}
		for _, subKeyName := range subKeys {
			apps[subKeyName] = struct{}{}
		}
		return apps, nil
	}

	// Helper function to monitor a registry key
	monitorRegistryKey := func(hKey windows.Handle) {
		key := registry.Key(hKey)
		defer key.Close()

		oldSnapshot, err := getStoreApplications(key)
		if err != nil {
			log.Error().Err(err).Msg("Error taking initial snapshot")
			return
		}

		for {
			// Wait for registry changes
			status, _, err := procRegNotifyChangeKeyValue.Call(
				uintptr(hKey),
				1, // bWatchSubtree
				REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET,
				0,
				0,
			)
			if status != 0 {
				log.Error().Err(err).Msg("Error waiting for registry change")
				return
			}

			newSnapshot, err := getStoreApplications(key)
			if err != nil {
				log.Error().Err(err).Msg("Error taking new snapshot")
				return
			}

			// Compare snapshots to detect changes
			for appKey := range newSnapshot {
				if _, found := oldSnapshot[appKey]; !found {
					if isRecentlySeen(appKey) {
						continue // Skip if the app was recently processed
					}

					log.Info().Msgf("Application Installed: %s", appKey)
					markAsSeen(appKey)

					if err := getAndCompressAndUploadAllInstalledApplications(); err != nil {
						log.Error().Err(err).Msg("Failed to compress and upload all installed applications.")
					}
				}
			}

			for appKey := range oldSnapshot {
				if _, found := newSnapshot[appKey]; !found {
					if isRecentlySeen(appKey) {
						continue // Skip if the app was recently processed
					}

					log.Info().Msgf("Application Uninstalled: %s", appKey)
					markAsSeen(appKey)

					if err := getAndCompressAndUploadAllInstalledApplications(); err != nil {
						log.Error().Err(err).Msg("Failed to compress and upload all installed applications.")
					}
				}
			}

			oldSnapshot = newSnapshot
		}
	}

	// Get the user ID for the current user
	userID, err := getWindowsUserIDV2()
	if err != nil {
		log.Error().Err(err).Msg("Error getting user ID")
		return
	}

	// Registry keys to monitor
	keys := []struct {
		baseKey registry.Key
		path    string
	}{
		// For microsft store applications
		// {registry.CURRENT_USER, `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`},
		// {registry.LOCAL_MACHINE, `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`},

		{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.USERS, fmt.Sprintf(`%s\Software\Microsoft\Windows\CurrentVersion\Uninstall`, userID)},
		{registry.USERS, fmt.Sprintf(`%s\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, userID)},
	}

	// Monitor all registry keys
	for _, keyInfo := range keys {
		key, err := registry.OpenKey(keyInfo.baseKey, keyInfo.path, registry.READ|KEY_NOTIFY)
		if err != nil {
			log.Error().Err(err).Msg("Error opening registry key")
			continue
		}
		hKey := windows.Handle(key)
		go monitorRegistryKey(hKey)
	}

	// Start periodic cleanup of the seenApplications map
	go cleanupSeenApplications()
}

func markAsSeen(appKey string) {
	seenApplications.Lock()
	defer seenApplications.Unlock()
	seenApplications.data[appKey] = time.Now()
}

func isRecentlySeen(appKey string) bool {
	seenApplications.Lock()
	defer seenApplications.Unlock()

	if lastSeen, found := seenApplications.data[appKey]; found {
		if time.Since(lastSeen) < 5*time.Second {
			return true // Recently seen
		}
	}
	return false
}

func cleanupSeenApplications() {
	for {
		time.Sleep(1 * time.Minute)
		seenApplications.Lock()
		now := time.Now()
		previousLength := len(seenApplications.data)
		removedCount := 0

		for appKey, timestamp := range seenApplications.data {
			if now.Sub(timestamp) > 1*time.Minute {
				delete(seenApplications.data, appKey)
				removedCount++
			}
		}

		newLength := len(seenApplications.data)
		seenApplications.Unlock()

		if removedCount > 0 {
			log.Info().
				Int("removed_count", removedCount).
				Int("previous_length", previousLength).
				Int("new_length", newLength).
				Msg("Cleanup completed")
		}
	}
}

func monitorAndDetectChangesForLocalUsers() {
	log.Info().Msg("Starting the process of monitoring and detecting changes for local users...")

	if activeDirectoryDomainController {
		log.Info().Msg("Active Directory Domain Controller detected. Skipping user monitoring.")
		return
	}

	var (
		modNetapi32          = windows.NewLazySystemDLL("netapi32.dll")
		procNetUserEnum      = modNetapi32.NewProc("NetUserEnum")
		procNetApiBufferFree = modNetapi32.NewProc("NetApiBufferFree")
	)

	const (
		MAX_PREFERRED_LENGTH  = 0xFFFFFFFF
		FILTER_NORMAL_ACCOUNT = 2
	)

	type USER_INFO_1 struct {
		Name        *uint16
		Password    *uint16
		PasswordAge uint32
		Privilege   uint32
		HomeDir     *uint16
		Comment     *uint16
		Flags       uint32
		ScriptPath  *uint16
	}

	// Helper to fetch users
	fetchLocalUsers := func() (map[string]map[string]string, error) {
		var entriesRead, totalEntries, resumeHandle uint32
		var buf unsafe.Pointer

		ret, _, _ := procNetUserEnum.Call(
			0, // servername (null for local machine)
			1, // level (USER_INFO_1)
			// uintptr(FILTER_NORMAL_ACCOUNT),
			FILTER_NORMAL_ACCOUNT,
			uintptr(unsafe.Pointer(&buf)),
			MAX_PREFERRED_LENGTH,
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)
		if ret != 0 {
			return nil, fmt.Errorf("NetUserEnum call failed with code %d", ret)
		}
		defer procNetApiBufferFree.Call(uintptr(buf))

		users := make(map[string]map[string]string)
		userInfo := (*[1 << 30]USER_INFO_1)(buf)[:entriesRead:entriesRead]

		for _, user := range userInfo {
			username := syscall.UTF16ToString((*[1 << 30]uint16)(unsafe.Pointer(user.Name))[:])
			userData := map[string]string{
				"Name":        username,
				"Flags":       fmt.Sprintf("%d", user.Flags),
				"PasswordAge": fmt.Sprintf("%d", user.PasswordAge), // Include PasswordAge
			}
			users[username] = userData
		}

		return users, nil
	}

	// Helper to detect changes
	detectChanges := func(oldState, newState map[string]map[string]string) {
		changeDetected := false

		// Detect added users
		for username := range newState {
			if _, exists := oldState[username]; !exists {
				log.Info().Str("username", username).Msg("User added")
				changeDetected = true
			}
		}

		// Detect removed users
		for username := range oldState {
			if _, exists := newState[username]; !exists {
				log.Info().Str("username", username).Msg("User removed")
				changeDetected = true
			}
		}

		// Helper to convert string to integer
		atoi := func(s string) int {
			val, err := strconv.Atoi(s)
			if err != nil {
				return 0
			}
			return val
		}

		// Detect modified users and password changes
		for username, newUserData := range newState {
			if oldUserData, exists := oldState[username]; exists {
				for key, newValue := range newUserData {
					if key == "PasswordAge" {
						oldPasswordAge := atoi(oldUserData[key])
						newPasswordAge := atoi(newValue)

						if newPasswordAge < oldPasswordAge {
							log.Info().Str("username", username).Msg("Password changed")
							changeDetected = true
						}
						continue
					}
					if oldValue, exists := oldUserData[key]; exists && oldValue != newValue {
						log.Info().
							Str("username", username).
							Str("field", key).
							Str("old_value", oldValue).
							Str("new_value", newValue).
							Msg("User modified")
						changeDetected = true
					}
				}
			}
		}

		// If changes are detected, trigger the upload function
		if changeDetected {
			if err := getAndUploadLocalUsersAndGroups(); err != nil {
				log.Error().Err(err).Msg("Failed to upload local users and groups.")
			}
		}
	}

	// Initial snapshot
	oldState, err := fetchLocalUsers()
	if err != nil {
		log.Error().Err(err).Msg("Error fetching initial user state")
		return
	}

	log.Info().Msg("Initial user state captured.")

	for {
		time.Sleep(10 * time.Second) // Adjust polling interval as needed

		newState, err := fetchLocalUsers()
		if err != nil {
			log.Error().Err(err).Msg("Error fetching users")
			continue
		}

		// Detect changes
		detectChanges(oldState, newState)

		// Update the old state to the new state
		oldState = newState
	}
}

func watchDNSFile() {
	dnsFilePath := `C:\Windows\System32\drivers\etc\hosts`
	var previousHash string

	for {
		// Wait for 20 seconds before checking again
		time.Sleep(20 * time.Second)

		fileData, err := os.ReadFile(dnsFilePath)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to read file %s", dnsFilePath)
			continue
		}

		currentHash, err := getHexHash(string(fileData))
		if err != nil {
			log.Error().Err(err).Msg("Failed to get hash of DNS file.")
			continue
		}

		if currentHash == previousHash {
			continue
		}

		if currentHash != previousHash {
			log.Info().Msg("DNS file has changed. Uploading DNS data...")
			if err := getAndCompressAndUploadLocalDNS(); err != nil {
				log.Error().Err(err).Msg("Failed to compress and upload local DNS.")
			}
			previousHash = currentHash
		}
	}
}

// startPeriodicUploadLogs initializes the process of uploading logs to the server.
// It uploades the logs every 24 hours and checks if the time has elapsed since the
// last upload every 30 minutes. it truncates the logs after uploading them.
func startPeriodicUploadLogs() {
	log.Info().Msg("Starting the periodic logs upload process...")

	for {
		err := startExcuteCompressAndUploadLogsIfTimeElapsed()
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute compress and upload logs process.")
		}

		log.Debug().Msg("Sleeping for 30 minutes before checking if logs need to be uploaded again.")

		time.Sleep(30 * time.Minute)
	}

}

func startExcuteCompressAndUploadLogsIfTimeElapsed() error {
	filePath := filepath.Join(CymetricxPath, "Time Files", "logs-upload-timer.txt")

	ifElapsed, err := isDurationElapsedSinceLastUpdate(filePath, 24)
	if err != nil {
		return err
	}

	if !ifElapsed {
		return nil
	}

	if err := compressAndUploadLogs("regular"); err != nil {
		return fmt.Errorf("failed to upload logs peridecly: %w", err)
	}

	// Update the timer file with the current time
	createNowFileTimer(filePath)

	return nil
}

// startSystemDetailesUploadProcess initializes the process of uploading system information
// to the server. It creates a timer file to keep track of the time of the last upload,
// and then compresses and uploads the system information to the server.
func startSystemDetailesUploadProcess() {
	filepath := filepath.Join(CymetricxPath, "Time Files", "system-details-timer.txt")

	if !fileExists(filepath) {
		for i := 0; i < 3; i++ {
			if err := collectAndUploadSystemDetails_start_windows(true, "system-details-hash.txt", "start_windows"); err != nil {
				log.Error().Err(err).Msg("Failed to compress and upload system details.")
				if i == 2 {
					log.Fatal().Msg("Failed to compress and upload system details after 3 attempts.")
				}
			} else {
				break
			}
		}
		createNowFileTimer(filepath)
	} else {
		if err := checkAndUpdateSystemDetailesUploadTimer(filepath); err != nil {
			log.Error().Err(err).Msg("Failed to check and update system detailes timer.")
		}
	}
}

// fileExists checks if a file exists at the given path
func expandEnvironmentVariables(path string) string {
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) == 2 {
			path = strings.ReplaceAll(path, "%"+pair[0]+"%", pair[1])
		}
	}
	return path
}

// fileExists checks if a file exists and is not a directory
// and returns a boolean value indicating whether the file exists.
func fileExists(filePath string) bool {
	expandedPath := expandEnvironmentVariables(filePath)

	info, err := os.Stat(expandedPath)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}

	return !info.IsDir()
}

// createNowFileTimer generates a file specific to the calling function.
// This file contains the timestamp (in milliseconds) of the last successful
// upload related to that function's action. Each function maintains its own
// distinct timer file.
func createNowFileTimer(apiStartTimeFilePath string) {
	currentTime := fmt.Sprint(time.Now().UnixNano() / int64(time.Millisecond))
	if err := createFileWithPermissionsAndWriteToIt(apiStartTimeFilePath, currentTime, 0644); err != nil {
		log.Error().Err(err).Str("Path", apiStartTimeFilePath).Msg("Failed to write system details upload file timer.")
	}
}

// checkAndUpdateSystemDetailesUploadTimer checks if the difference between the
// current time and the previous time is greater than 5 hours. If it is, it
// compresses and uploads the system details and updates the file with the
// current time in milliseconds.
func checkAndUpdateSystemDetailesUploadTimer(apiStartTimeFilePath string) error {
	log.Info().Str("Path", apiStartTimeFilePath).Msg("Starting to check and updating system details upload timer..")

	rawPreviousTime, err := os.ReadFile(apiStartTimeFilePath)
	if err != nil {
		return fmt.Errorf("failed to read API start time from file %s: %w", apiStartTimeFilePath, err)
	}

	previousTime, err := strconv.ParseInt(string(rawPreviousTime), 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse previous time %s: %w", string(rawPreviousTime), err)
	}

	// Convert previousTime back to time.Time for comparison
	previousTimeParsed := time.Unix(0, previousTime*int64(time.Millisecond))

	// Check if the current time is after the previous time + 5 hours
	if time.Now().After(previousTimeParsed.Add(5 * time.Hour)) {
		log.Debug().Msg("Difference in system details upload time is greater than threshold. Uploading system details...")

		if err := collectAndUploadSystemDetails_start_windows(false, "system-details-hash.txt", "start_windows"); err != nil {
			return fmt.Errorf("failed to compress and upload system details: %w", err)
		}

		// Updating the file with the current time in milliseconds
		createNowFileTimer(apiStartTimeFilePath)
	} else {
		log.Debug().Msg("Difference in system details upload time is less than threshold. Skipping system details upload.")
	}

	log.Info().Str("Path", apiStartTimeFilePath).Msg("Successfully checked and updated system details upload timer.")

	return nil
}

// terminateCymetricxm terminates the cymetricxm.exe process
func terminateCymetricxm() {
	log.Info().Msg("Attempting to terminate cymetricxm process.")
	commandArgs := []string{"/c ", "WMIC Process Where \"ExecutablePath='C:\\\\Program Files\\\\runservice\\\\cymetricxm.exe'\" Call Terminate"}

	err := execCommandWithoutOutput(powerShellPath, commandArgs...)
	if err != nil {
		log.Error().Err(err).Msg("Failed to terminate cymetricxm process.")
	} else {
		log.Info().Msg("Successfully terminated cymetricxm process.")
	}

	log.Info().Msg("Attempting to remove runservice directory.")

	/* Remove the folder that contains all of the files that were used throughout the "upgrading Process".
	The reason we do this is because we upgrade using the "Advanced Installer" and we do NOT remove
	the folder using it, so it is left in the system because it created some issues.
	So, we opted for just removing this file whenever we run the agent to make sure any of the upgrading files are all removed.*/
	runServiceDirectory := filepath.Join(`C:\`, "Program Files", "runservice")
	err = os.RemoveAll(runServiceDirectory)
	if err != nil {
		log.Error().Err(err).Msg("Failed to remove runservice directory.")
	}

	log.Info().Msg("Successfully removed runservice directory.")
}

// stopAndRemoveRunUpgradeService stops and removes the runupgrade service
func stopAndRemoveRunUpgradeService() {
	log.Info().Msg("Attempting to stop and remove the runupgrade service.")
	scFilePath := getSCPath()
	var batchFileContents []byte
	if scFilePath != "" {
		batchFileContents = []byte(strings.Join([]string{
			fmt.Sprintf(`%s stop "runupgrade" `, scFilePath),
			fmt.Sprintf(`%s  delete "runupgrade" `, scFilePath),
		}, "\n"))
	} else {
		batchFileContents = []byte(
			"cymetricxm.exe stop runupgrade \n" +
				"cymetricxm.exe remove runupgrade confirm",
		)
	}

	filePath := filepath.Join(CymetricxPath, "stop_and_remove_runupgrade.bat")
	if err := createFileWithPermissionsAndWriteToIt(filePath, string(batchFileContents), 0744); err != nil {
		log.Error().Err(err).Msg("Failed to write to stop_and_remove_runupgrade.bat.")
	}
	//defer os.Remove("stop_and_remove_runupgrade.bat")

	err := execCommandWithoutOutput(filePath)
	if err == nil {
		log.Info().Msg("Successfully stopped and removed the runupgrade service.")
		return
	}

	// Check for specific error message that indicates 'runupgrade' does not exist.
	if strings.Contains(err.Error(), "runupgrade does not exist") {
		log.Warn().Err(err).Msg("The runupgrade service does not exist; this is expected behavior in some cases.")
	} else {
		log.Error().Err(err).Msg("Error occurred when running stop_and_remove_runupgrade.bat.")
	}
}

// execCommandWithOutput runs the specified command along with its arguments and
// returns the output as a string. If the command execution fails, it captures
// the standard error output and includes it in the returned error.
func execCommandWithOutput(command string, args ...string) (string, error) {
	// Create a buffer to store the error output of the command.
	var stderr bytes.Buffer

	// Create a new command with the specified command and args.
	cmd := exec.Command(command, args...)

	// Set the stderr of the command to the stderr buffer.
	// So, if there is an error, it will be stored in the stderr buffer.
	cmd.Stderr = &stderr

	// Execute the command and get the output.
	output, err := cmd.Output()
	if err != nil {
		// Using strings.Join for better formatting of args
		// Format and return the error with the command, arguments, and captured stderr.
		return "", fmt.Errorf("could not execute command: %s, args: %s, Stderr: %s, error: %w", command, strings.Join(args, " "), stderr.String(), err)
	}

	return string(output), nil
}

// execCommandWithOutputRaw runs the specified command along with its arguments and
// returns the output as a string. If the command execution fails, it captures
// the standard error output and includes it in the returned error.
func execCommandWithOutputRaw(command string, args ...string) ([]byte, error) {
	// Create a buffer to store the error output of the command.
	var stderr bytes.Buffer

	// Create a new command with the specified command and args.
	cmd := exec.Command(command, args...)

	// Set the stderr of the command to the stderr buffer.
	// So, if there is an error, it will be stored in the stderr buffer.
	cmd.Stderr = &stderr

	// Execute the command and get the output.
	output, err := cmd.Output()
	if err != nil {
		// Using strings.Join for better formatting of args
		// Format and return the error with the command, arguments, and captured stderr.
		return nil, fmt.Errorf("could not execute command: %s, args: %s, Stderr: %s, error: %w", command, strings.Join(args, " "), stderr.String(), err)
	}

	return output, nil
}

// execCommandWithoutOutput runs the specified command along with its arguments.
// If the command execution fails, it captures the standard error output and
// includes it in the returned error.
func execCommandWithoutOutput(command string, args ...string) error {
	// Create a buffer to store the error output of the command.
	var stderr bytes.Buffer

	// Create a new command with the specified command and args.
	cmd := exec.Command(command, args...)

	// Set the stderr of the command to the stderr buffer.
	// So, if there is an error, it will be stored in the stderr buffer.
	cmd.Stderr = &stderr

	// Execute the command using Run().
	// Run() is used here instead of Output() because we do not need to capture
	// the standard output of the command, only its error output if it exists.
	err := cmd.Run()
	if err != nil {
		// Using strings.Join for better formatting of args.
		// Format and return the error with the command, arguments, and captured stderr.
		return fmt.Errorf("could not execute command: %s, args: %s, Stderr: %s, error: %w", command, strings.Join(args, " "), stderr.String(), err)
	}

	return nil
}

// stopAndRemoveRunRecoveryService stops and removes the runrecovery service
func stopAndRemoveRunRecoveryService() {
	log.Info().Msg("Attempting to stop and remove the runrecovery service.")

	batchFileContents := []byte(strings.Join([]string{
		"cymetricxm_2.exe stop runrecovery",
		"cymetricxm_2.exe remove runrecovery confirm",
	}, "\n"))
	if err := os.WriteFile("stop_and_remove_runrecovery.bat", batchFileContents, 0744); err != nil {
		log.Error().Err(err).Msg("Failed to write to stop_and_remove_runrecovery.bat.")
	}
	defer os.Remove("stop_and_remove_runrecovery.bat")

	filePath := filepath.Join(CymetricxPath, "stop_and_remove_runrecovery.bat")
	err := execCommandWithoutOutput(filePath)
	if err == nil {
		log.Info().Msg("Successfully stopped and removed the runrecovery service.")
		return

	}

	// Check for specific error message that indicates 'runrecovery' does not exist.
	if strings.Contains(err.Error(), "runrecovery does not exist") {
		log.Warn().Err(err).Msg("The runrecovery service does not exist; this is expected behavior in some cases.")
	} else {
		log.Error().Err(err).Msg("Error occurred when running stop_and_remove_runrecovery.bat.")
	}

}

type ApiLoginResponse struct {
	IsValid        bool   `json:"isValid"`                  // IsValid will always be present
	Token          string `json:"token,omitempty"`          // Token will be present only on successful login
	ExpirationDate string `json:"expirationDate,omitempty"` // ExpirationData will be present only on successful login
	Message        string `json:"message,omitempty"`        // Message will be present only on failed login
}

// loginAndReturnTokenV2 initiates the login process to obtain a token.
// It generates login credentials from the given password and the id variable.
// It returns the token if successful, otherwise it returns an error.
func loginAndReturnTokenV2(passwordlogin string) (string, time.Time, error) {
	log.Info().Msg("Starting the login process...")

	loginCredentials := generateLoginCredentials(passwordlogin)
	responseBody, err := prepareAndExecuteLoginHTTPRequestV2("POST", "login", loginCredentials, 10)
	if err != nil {
		return "", time.Time{}, err
	}

	// Unmarshal the JSON response into the ApiLoginResponse struct
	var response ApiLoginResponse
	err = json.Unmarshal(responseBody.Bytes(), &response)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to unmarshal response body")
		return "", time.Time{}, err
	}

	// Check if the login was successful by examining if token is present
	if !response.IsValid {
		return "", time.Time{}, fmt.Errorf("login failed: %s", response.Message)
	}

	// Define the layout based on the reference time in the response
	dateLayout := "2006-01-02T15:04:05.000000Z"
	parsedTime, err := time.Parse(dateLayout, response.ExpirationDate)
	if err != nil {
		log.Error().Err(err).Msg("Error parsing the time got from login response")
	}

	return response.Token, parsedTime, nil
}

type LoginCredentials struct {
	ID       string  `json:"id"`
	Password string  `json:"password"`
	UUID     *string `json:"uuid"`
}

type Win32_ComputerSystemProduct struct {
	UUID string
}

func getWindowsUUID() (string, error) {
	var dst []Win32_ComputerSystemProduct
	query := wmi.CreateQuery(&dst, "")
	err := wmi.Query(query, &dst)
	if err != nil {
		return "", err
	}

	if len(dst) > 0 {
		return dst[0].UUID, nil
	}
	return "", fmt.Errorf("no UUID found")
}

// generateLoginCredentials generates login credentials from the given password.
func generateLoginCredentials(passwordlogin string) LoginCredentials {
	password := generatePassword(id)
	uuid, err := getWindowsUUID()
	if err != nil {
		// If the UUID cannot be retrieved, set it to nil
		log.Error().Err(err).Msg("Failed to get UUID from Windows.")
	}

	loginCredintials := LoginCredentials{
		ID:       id,
		Password: password,
		UUID:     strToPtrOrNil(uuid),
	}

	return loginCredintials
}

func generatePassword(userID string) string {
	// Step 1: Scramble the user ID
	scrambledID := scramble(userID)

	// Step 2: Hash the user ID with SHA-256
	hasher := sha256.New()
	hasher.Write([]byte(scrambledID))
	hashBytes := hasher.Sum(nil)

	// Convert the hash to a hexadecimal string (This so it would match the
	// Laravel implementation of the hashing algorithm)
	hexHash := hex.EncodeToString(hashBytes)

	// Step 3: Convert the hexadecimal hash to a base64 encoded string
	b64Encoded := b64.StdEncoding.EncodeToString([]byte(hexHash))

	// Step 4: Truncate the base64 string to 32 characters
	password := b64Encoded[:32]

	return password
}

func scramble(input string) string {
	// Reverse the string
	reversed := ""
	for _, c := range input {
		reversed = string(c) + reversed
	}

	// Take the second block of four characters and put it at the start
	if len(reversed) >= 8 {
		part1 := reversed[4:8]
		part2 := reversed[:4]
		part3 := reversed[8:]
		reversed = part1 + part2 + part3
	}

	// fmt.Println("Reversed: ", reversed)

	return reversed
}

func prepareAndExecuteLoginHTTPRequestV2(httpMethod string, apiEndpoint string, loginCredentials LoginCredentials, retries int) (bytes.Buffer, error) {
	// Create JSON Payload if data is not empty.
	loginJSONPayload, err := json.Marshal(loginCredentials)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error marshaling jsonPayload: %w", err)
	}

	// Create HTTP Request with Timeout
	req, cancel, err := createHTTPRequestWithTimeoutV2(httpMethod, apiEndpoint, loginJSONPayload)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer cancel()

	// Execute HTTP Request
	responseBody, err := executeLoginHTTPRequestV2(req, retries)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error sending %s request to %s: %w", req.Method, req.URL, err)
	}

	return responseBody, nil
}

func executeLoginHTTPRequestV2(req *http.Request, retries int) (bytes.Buffer, error) {
	log.Info().Msgf("Starting executing %s request to %s ...", req.Method, req.URL)

	resp, err := sendLoginRequestWithRetries(req, retries)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer resp.Body.Close()

	// Read the response body
	responseBody, err := readResponseBody(resp)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to read response body of %s request to %s, %w", req.Method, req.URL, err)
	}

	log.Info().Msgf("Successfully executed %s request to %s.", req.Method, req.URL)

	return responseBody, nil
}

func sendLoginRequestWithRetries(req *http.Request, retries int) (*http.Response, error) {
	if retries < 1 {
		retries = math.MaxInt32
	}

	var originalBody []byte

	if req != nil && req.Body != nil {
		var err error
		originalBody, err = copyBody(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to copy request body: %w", err)
		}
		resetBody(req, originalBody)
	}

	for i := 0; i < retries; i++ {
		// Create a new context with a fresh timeout for each attempt
		// This is so when the deadline is exceeded, it would be refreshed as opposed to using the same deadline
		// for all the attempts. This is to avoid the deadline being exceeded for all the attempts even if the
		// deadline is exceeded for the first attempt and the subsequent attempts are made and should be successful.
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		req = req.WithContext(ctx) // Apply the new context to the existing request

		resp, err := sendCustomHTTPClientRequest(req)
		if err != nil {
			handleFailedRequest(req, resp, i, err)
			if req.Body != nil {
				resetBody(req, originalBody)
			}
			cancel()
			continue
		}

		cancel()
		if resp.StatusCode == http.StatusUnauthorized {
			// These status codes indicate a client-side error that is unlikely to be resolved by retrying
			log.Debug().Msg("Received 401 Unauthorized.")
			return resp, nil
		}

		if resp.StatusCode == http.StatusOK {
			return resp, nil // Successful response, no need to retry
		}

		// For other errors, log the issue and retry
		if req.Body != nil {
			resetBody(req, originalBody)
		}
		handleFailedRequest(req, resp, i, err)
	}

	return nil, fmt.Errorf("reached maximum retry attempts for %s request to %s", req.Method, req.URL)
}

// createHTTPRequestWithTimeout generates the HTTP request and adds a context timeout
func createHTTPRequestWithTimeout(httpMethod string, endPoint string, jsonPayload []byte) (*http.Request, context.CancelFunc, error) {

	req, err := createHttpRequestV1(httpMethod, endPoint, jsonPayload, "application/json")
	if err != nil {
		log.Error().Err(err).Str("EndPoint", endPoint).Msg("Failed to create HTTP request.")
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)

	// TODO: This needs more testing to see how it performs and acts when actually combined
	// TODO: with the timeout above.
	req = req.WithContext(ctx)

	return req, cancel, nil
}

// createHTTPRequestWithTimeout creates a new HTTP request method to the specified endpoint
// with a 5 minute timeout but without adding "/api" to the endpoint.
// It returns the created HTTP request object, the context for handling request timeout,
// and the function to cancel the context responsible for handling the request timeout.
func createHTTPRequestWithTimeoutForNoAPIEndpointsV1(httpMethod string, endPoint string, jsonPayload []byte) (*http.Request, context.CancelFunc, error) {
	req, err := createHttpRequestWithNoAPIAddedV1(httpMethod, endPoint, jsonPayload, "application/json")
	if err != nil {
		return nil, nil, fmt.Errorf("error creating POST request of api/login. %w", err)
	}

	// Implement a 5-minute timeout for requests to prevent indefinite hanging.
	// A duration of 5 minutes is chosen as some requests, particularly uploads,
	// can take a substantial amount of time to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	// TODO: This needs more testing to see how it performs and acts when actually combined
	// TODO: with the timeout above.
	req = req.WithContext(ctx)

	return req, cancel, nil
}

// createHTTPRequestWithTimeout creates a new HTTP request method to the specified endpoint
// with a 5 minute timeout but without adding "/api" to the endpoint.
// It returns the created HTTP request object, the context for handling request timeout,
// and the function to cancel the context responsible for handling the request timeout.
func createHTTPRequestWithTimeoutForNoAPIEndpointsV2(httpMethod string, endPoint string, jsonPayload []byte) (*http.Request, context.CancelFunc, error) {
	req, err := createHttpRequestWithNoAPIAddedV2(httpMethod, endPoint, jsonPayload, "application/json")
	if err != nil {
		return nil, nil, fmt.Errorf("error creating POST request of api/login. %w", err)
	}

	// Implement a 5-minute timeout for requests to prevent indefinite hanging.
	// A duration of 5 minutes is chosen as some requests, particularly uploads,
	// can take a substantial amount of time to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	// TODO: This needs more testing to see how it performs and acts when actually combined
	// TODO: with the timeout above.
	req = req.WithContext(ctx)

	return req, cancel, nil
}

// sendCustomHTTPClientRequest sends the HTTP request to the server using Insecure HTTP Client
func sendCustomHTTPClientRequest(req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending POST request. %w", err)
	}

	return resp, nil
}

func prepareAndExecuteSerialHTTPRequest(httpMethod, apiEndpoint, serial string, retries int) (bytes.Buffer, error) {
	// Create Serial JSON Payload
	serialJsonPayload, err := createSerialPayload(serial)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error marshaling serial JSON payload: %w", err)
	}

	// Create HTTP Request with Timeout
	req, cancel, err := createHTTPRequestWithTimeoutV2(httpMethod, apiEndpoint, serialJsonPayload)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer cancel()

	// Execute HTTP Request
	responseBody, err := executeSerialHTTPRequest(req, retries)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error sending %s request to %s: %w", req.Method, req.URL, err)
	}

	return responseBody, nil
}

type SerialPayload struct {
	Serial string `json:"serial"`
}

func createSerialPayload(serial string) ([]byte, error) {
	serialPayload := SerialPayload{
		Serial: serial,
	}

	return json.Marshal(serialPayload)
}

// executeHTTPRequest executes the HTTP request and returns the
// response body as bytes.Buffer. It takes the request, client, and
// number of retries as parameters. If retries is <1, it retries the
// request forever. Otherwise, it retries the request up to the given
// number of retries.
func executeSerialHTTPRequest(req *http.Request, retries int) (bytes.Buffer, error) {
	log.Info().Msgf("Starting excuting %s request to %s ...", req.Method, req.URL)

	resp, err := sendSerialRequestWithRetries(req, retries)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer resp.Body.Close()

	responseBody, err := readResponseBody(resp)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to read response body of %s request to %s, %w", req.Method, req.URL, err)
	}

	log.Info().Msgf("Successfully executed %s request to %s.", req.Method, req.URL)
	return responseBody, nil
}

// sendRequestWithRetries sends the given request using the given client and
// retries up to 10 times if it fails or the response status code is not 200.
// It returns the response of the request.
func sendSerialRequestWithRetries(req *http.Request, retries int) (*http.Response, error) {

	if retries < 1 {
		retries = math.MaxInt32 // set the default number of retries to infinity
	}

	var originalBody []byte

	if req != nil && req.Body != nil {
		var err error
		originalBody, err = copyBody(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to copy request body: %w", err)
		}
		resetBody(req, originalBody)
	}

	for i := 0; i < retries; i++ {
		// Create a new context with a fresh timeout for each attempt
		// This is so when the deadline is exceeded, it would be refreshed as opposed to using the same deadline
		// for all the attempts. This is to avoid the deadline being exceeded for all the attempts even if the
		// deadline is exceeded for the first attempt and the subsequent attempts are made and should be successful.
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		req = req.WithContext(ctx) // Apply the new context to the existing request

		resp, err := sendCustomHTTPClientRequest(req)
		if err != nil {
			handleFailedRequest(req, resp, i, err)
			if req.Body != nil {
				resetBody(req, originalBody)
			}
			cancel()
			continue // Continue to retry
		}

		cancel()
		// Only proceed to check the status code if there was no error
		if resp.StatusCode == http.StatusForbidden {
			log.Debug().Msg("Received 403 Forbidden. Serial does not match.")
			return resp, nil // Do not retry, forbidden means wrong credentials
		}

		if resp.StatusCode == http.StatusOK {
			return resp, nil // Successful response
		}

		handleFailedRequest(req, resp, i, err)
		if req.Body != nil {
			resetBody(req, originalBody)
		}
	}

	return nil, fmt.Errorf("reached maximum retry attempts for %s request to %s", req.Method, req.URL)
}

// ErrorResponse is used to unmarshal the JSON response from the server.
type ErrorResponse struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

// handleFailedRequest handles a failed request by logging the error and
// sleeping for a calculated backoff time before retrying the request.
func handleFailedRequest(req *http.Request, resp *http.Response, retries int, err error) {

	if resp != nil {
		// if there is a response, log the status code
		log.Info().Int("status_code", resp.StatusCode)

		responseBody, err := readResponseBody(resp)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read response body.")
		}

		var errorResponse ErrorResponse

		if jsonErr := json.Unmarshal(responseBody.Bytes(), &errorResponse); jsonErr != nil {
			log.Error().Err(jsonErr).Msg("Failed to unmarshal response body.")
			log.Error().Msgf("Error message from server: %s", responseBody.String())
		} else {
			log.Error().Str("message", errorResponse.Message).Msg("Error message from server.")
			log.Error().Str("error", errorResponse.Error).Msg("Error2 message from server.")
			log.Error().Msgf("Error message from server: %s", responseBody.String())
		}

		// close the body so we don't leak resources
		resp.Body.Close()
	}

	// Log the error and the request details.
	log.Error().
		Err(err).
		Str("Method:", req.Method).
		Any("URL_Path:", req.URL).
		Msgf("Failed attempt #%d", retries+1)

	// Stack trace logging
	log.Debug().Msgf("StackTrace: %s", debug.Stack())

	// Cap the retries to prevent overflow in newExpectedMaxBackoff calculation
	maxRetriesForCalc := 10
	if retries > maxRetriesForCalc {
		retries = maxRetriesForCalc
	}

	// Calculate backoff time exponentially with jitter
	jitterMaxTime := 10 * time.Second

	// maxBackoff is defined in seconds (5 minutes)
	maxBackoff := 300 * time.Second

	// Calculate exponential backoff in seconds, then convert to time.Duration
	newExpectedMaxBackoff := math.Pow(2, float64(retries))
	newExpectedMaxBackoffDuration := time.Duration(newExpectedMaxBackoff) * time.Second

	// Ensure that backoff does not exceed maxBackoff
	backoff := time.Duration(math.Min(float64(newExpectedMaxBackoffDuration), float64(maxBackoff)))

	// Add a random jitter to the backoff time to prevent thundering herd problem
	// Where all the clients retry at the same time and overwhelm the server.
	jitter := time.Duration(mRand.Int63n(int64(jitterMaxTime)))
	totalBackoff := backoff + jitter

	log.Warn().Msgf("Retrying in %s...", totalBackoff)

	// Sleep for the calculated backoff time before retrying the request.
	time.Sleep(totalBackoff)
}

// createInsecureHttpClient creates a custom http client that ignores the certificate verification of the server.
func createInsecureHttpClient() *http.Client {
	// This is used because the servers are not using a valid certificate
	// and we don't want to go through the hassle of creating a valid one for each customer,
	// installing it on their server, and renewing it every year.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &http.Client{
		Transport: tr,
	}
}

// ! The IP is completely unnecessary but it's just how it's implemented in the server side so it does not fail
type Payload struct {
	Data string `json:"data"`
	IP   string `json:"ip"`
}

// createJsonPayloadV1 creates the json payload for the http requests.
func createJsonPayloadV1(data string) ([]byte, error) {
	//! This should be removed in the future after the server is updated to accept the serial as a string not encoded
	encodedData := b64.StdEncoding.EncodeToString([]byte(data))
	payload := Payload{
		Data: encodedData,
	}

	return json.Marshal(payload)
}

// createJsonPayloadWithSingleQuotes creates the json payload for the http requests but puts extra single quotes around the data.
// The addition of single quotations is unnecessary but it's just how it's implemented in the server side
func createJsonPayloadWithSingleQuotes(encodedData string) ([]byte, error) {
	log.Info().Msg("Creating JSON payload with single quotes around data.")

	payload := Payload{
		Data: "'" + encodedData + "'",
		IP:   "'" + "" + "'",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Error().Err(err).Str("EncodedData", encodedData).Msg("Failed to marshal the payload to JSON.")
		return nil, err
	}

	log.Info().Msg("Successfully created JSON payload with single quotes.")
	return jsonPayload, nil
}

// createHttpRequestV1 creates the http request for a specific endpoint and sets the headers.
func createHttpRequestV1(httpMethod string, endPoint string, jsonPayload []byte, MIMEType string) (*http.Request, error) {
	// req, err := http.NewRequest(httpMethod, apiURLFlask+"api/"+endPoint, nil)
	req, err := http.NewRequest(httpMethod, apiURLFlask+"api/"+endPoint, nil)
	if err != nil {
		return nil, err
	}

	if httpMethod != "GET" {
		// The payload is only set for None GET requests and it's given the no operation closer so it does not close the body as it's unnecessary
		req.Body = io.NopCloser(bytes.NewBuffer(jsonPayload))
		req.Header.Set("Content-Type", MIMEType)
	}

	return req, nil
}

// createHttpRequest creates the HTTP request but it does not add "api" end point to the url
func createHttpRequestWithNoAPIAddedV1(httpMethod string, endPoint string, jsonPayload []byte, MIMEType string) (*http.Request, error) {
	req, err := http.NewRequest(httpMethod, apiURLFlask+endPoint, nil)
	if err != nil {
		return nil, err
	}

	if httpMethod != "GET" {
		// The payload is only set for None GET requests and it's given the no operation closer so it does not close the body as it's unnecessary
		req.Body = io.NopCloser(bytes.NewBuffer(jsonPayload))
		req.Header.Set("Content-Type", MIMEType)
	}

	return req, nil
}

// createHttpRequest creates the HTTP request but it does not add "api" end point to the url
func createHttpRequestWithNoAPIAddedV2(httpMethod string, endPoint string, jsonPayload []byte, MIMEType string) (*http.Request, error) {
	req, err := http.NewRequest(httpMethod, apiURLLaravel+endPoint, nil)
	if err != nil {
		return nil, err
	}

	if httpMethod != "GET" {
		// The payload is only set for None GET requests and it's given the no operation closer so it does not close the body as it's unnecessary
		req.Body = io.NopCloser(bytes.NewBuffer(jsonPayload))
		req.Header.Set("Accept", MIMEType)
	}

	return req, nil
}

type SystemDetails struct {
	UniqueID       string
	CurrentUTCTime string
	ComputerInfo   string
	NetworkConfigs []string
	DomainRole     uint32
}

// generateIDAndWriteItToIDTxtFile either generates a new UUID and writes it to
// the id.txt file (if it doesn't already exist), or retrieves the existing UUID
// from the id.txt  file. In both scenarios, the UUID and the Agent Version are
// written to the id.txt file. It returns the ID.
func generateIDAndWriteItToIDTxtFile() (string, error) {
	log.Info().Msg("Attempting to retrieve user ID from id.txt file.")

	uuid, err := getWindowsUUID()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get UUID from Windows.")
	}

	uniqueID, err := getUserIDFromIDTxtFile()
	if err == nil {
		// If the UUID was successfully retrieved from id.txt file, return it.
		return writeDataToIDTxtFile(uniqueID, uuid)
	}

	log.Warn().Err(err).Msg("Failed to retrieve user ID from id.txt, generating a new UUID.")

	uniqueID = generateUUID()

	log.Debug().Msgf("Generated new UUID: %s.", uniqueID)

	return writeDataToIDTxtFile(uniqueID, uuid)
}

func generateIDAndWriteItToIDTxtFile2(baseFileName string) (string, error) {
	log.Info().Msgf("Attempting to retrieve user ID from %s.txt file.", baseFileName)

	uuid := ""
	if baseFileName == "id" {
		var err error
		uuid, err = getWindowsUUID()
		if err != nil {
			log.Error().Err(err).Msg("Failed to get UUID from Windows.")
		}
	} else {
		// Add _id to the baseFileName to differentiate it from the other product ID files.
		baseFileName = baseFileName + "_id"
	}

	uniqueID, err := getUserIDFromIDTxtFile2(baseFileName)
	if err == nil {
		// If the UUID was successfully retrieved from id.txt file, return it.
		idFileContent := createIDFileContent(uniqueID, uuid, baseFileName)
		return writeDataToIDTxtFile2(idFileContent, uniqueID, baseFileName)
	}

	log.Warn().Err(err).Msgf("Failed to retrieve user ID from %s.txt, generating a new UUID.", baseFileName)

	uniqueID = generateUUID()

	log.Debug().Msgf("Generated new UUID: %s.", uniqueID)

	// Deleting other product ID files so they are always unique if the ID was removed before:
	if baseFileName == "id" {
		if err := removeOtherProductIDFiles(); err != nil {
			return "", err
		}
	}

	idFileContent := createIDFileContent(uniqueID, uuid, baseFileName)

	return writeDataToIDTxtFile2(idFileContent, uniqueID, baseFileName)
}

func removeOtherProductIDFiles() error {
	productsArray := []string{
		"google_chrome",
		"microsoft_edge",
		"office_2016",
	}

	for _, product := range productsArray {
		filePath := filepath.Join(CymetricxPath, fmt.Sprintf("%s_id.txt", product))
		if !fileExists(filePath) {
			continue
		}

		log.Debug().Msgf("Removing product ID file: %s", filePath)

		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to remove %s file: %w", filePath, err)
		}
	}

	return nil
}

func createIDFileContent(uniqueID, uuid, baseFileName string) string {
	if baseFileName == "id" {
		return fmt.Sprintf("%s,,,,,,\nAgent Version: %s\nUUID: %s", uniqueID, AgentVersion, uuid)
	}
	return fmt.Sprintf("%s,,,,,,", uniqueID)
}

// generateIDAndWriteItToIDTxtFile either generates a new UUID and writes it to
// the id.txt file (if it doesn't already exist), or retrieves the existing UUID
// from the id.txt  file. In both scenarios, the UUID and the Agent Version are
// written to the id.txt file. It returns the ID.
func generateProductIDAndWriteItToProductTxtFile(baseFileName string) (string, error) {
	log.Info().Msg("Attempting to retrieve user ID from id.txt file.")

	uniqueID, err := getProductIDFromProductIDTxtFile(baseFileName)
	if err == nil {
		// If the UUID was successfully retrieved from id.txt file, return it.
		return writeDataToProductIDTxtFile(uniqueID, baseFileName)
	}

	log.Warn().Err(err).Msg("Failed to retrieve user ID from id.txt, generating a new UUID.")

	uniqueID = generateUUID()

	log.Debug().Msgf("Generated new UUID: %s.", uniqueID)

	return writeDataToProductIDTxtFile(uniqueID, baseFileName)
}

// collectSystemConfigurationDetailsV2 captures the system information and returns it as a SystemData struct
func collectSystemConfigurationDetailsV2() SystemDetails {
	log.Info().Msg("Initiating system information capture.")

	systemDetails := SystemDetails{}

	systemDetails.UniqueID = id

	log.Debug().Msg("Capturing computer information.")
	systemDetails.ComputerInfo = getComputerInfo()

	log.Debug().Msg("Capturing current UTC time.")
	systemDetails.CurrentUTCTime = getCurrentUTCTimeFormatted()

	log.Debug().Msg("Capturing network configurations using ipconfig.")
	var err error
	// commandArgs := []string{"/c", "ipconfig /all"}
	// systemDetails.NetworkConfigs, err = execCommandWithOutput(cmdPath, commandArgs...)
	// if err != nil {
	// 	log.Error().Err(err).Msg("Failed to get network configurations using ipconfig /all.")
	// }

	systemDetails.NetworkConfigs, err = getIPAddresses()

	log.Debug().Msg("Capturing domain role using wmi query for Win32_ComputerSystem.")
	systemDetails.DomainRole, err = getDomainRole()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get DomainRole using wmic get DomainRole.")
	}

	log.Info().Msg("System information capture complete.")
	return systemDetails
}

// getIPAddresses returns a slice of IP addresses of the machine.
func getIPAddresses() ([]string, error) {
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, intf := range interfaces {
		addrs, err := intf.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.IsGlobalUnicast() {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips, nil
}

// Define a struct that matches the properties you want from the WMI query.
// The names must match the WMI class' property names.
type Win32_ComputerSystem struct {
	DomainRole uint32 // Use the appropriate data type.
}

func getDomainRole() (uint32, error) {
	var dst []Win32_ComputerSystem
	query := "SELECT DomainRole FROM Win32_ComputerSystem"

	// Execute the WMI query.
	if err := wmi.Query(query, &dst); err != nil {
		return 0, err // Return 0 as the default value in case of error.
	}

	// Check if we got at least one result.
	if len(dst) == 0 {
		return 0, fmt.Errorf("no results from WMI query")
	}

	// Return the DomainRole of the first result.
	return dst[0].DomainRole, nil
}

// getUserIDFromIDTxtFile retrieves the user ID from /etc/cymetricx/id.txt file.
// The first line is the UUID combined with some commas.
func getUserIDFromIDTxtFile() (string, error) {
	log.Info().Msg("Attempting to open id.txt file for reading...")

	idTxtPath := filepath.Join(CymetricxPath, "id.txt")

	file, err := os.Open(idTxtPath)
	if err != nil {
		return "", fmt.Errorf("error opening id.txt file. %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return "", fmt.Errorf("no content found in id.txt file")
	}

	lineList := strings.SplitN(scanner.Text(), ",", 2)

	// If the file is empty or contains only commas, return an error.
	if len(lineList) < 2 {
		return "", fmt.Errorf("invalid content in id.txt file")
	}

	// The first element in the lineList is the UUID.
	uniqeID := lineList[0]

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error occurred while scanning id.txt file. %w", err)
	}

	log.Info().Str("ID:", uniqeID).Msg("Successfully retrieved ID from id.txt file.")
	return uniqeID, nil
}

func getUserIDFromIDTxtFile2(baseFileName string) (string, error) {
	log.Info().Msg("Attempting to open id.txt file for reading...")

	fileName := fmt.Sprintf("%s.txt", baseFileName)
	idTxtPath := filepath.Join(CymetricxPath, fileName)

	file, err := os.Open(idTxtPath)
	if err != nil {
		return "", fmt.Errorf("error opening %s file. %w", fileName, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return "", fmt.Errorf("no content found in %s file", fileName)
	}

	lineList := strings.SplitN(scanner.Text(), ",", 2)

	// If the file is empty or contains only commas, return an error.
	if len(lineList) < 2 {
		return "", fmt.Errorf("invalid content in %s file", fileName)
	}

	// The first element in the lineList is the UUID.
	uniqeID := lineList[0]

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error occurred while scanning %s file. %w", fileName, err)
	}

	log.Info().Str("ID:", uniqeID).Msgf("Successfully retrieved ID from %s file.", fileName)
	return uniqeID, nil
}

// getUserIDFromIDTxtFile retrieves the user ID from /etc/cymetricx/id.txt file.
// The first line is the UUID combined with some commas.
func getProductIDFromProductIDTxtFile(productName string) (string, error) {
	log.Info().Msg("Attempting to open id.txt file for reading...")

	productFilePath := fmt.Sprintf("%s.txt", productName)
	idTxtPath := filepath.Join(CymetricxPath, productFilePath)

	file, err := os.Open(idTxtPath)
	if err != nil {
		return "", fmt.Errorf("error opening id.txt file. %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return "", fmt.Errorf("no content found in id.txt file")
	}

	lineList := strings.SplitN(scanner.Text(), ",", 2)

	// If the file is empty or contains only commas, return an error.
	if len(lineList) < 2 {
		return "", fmt.Errorf("invalid content in id.txt file")
	}

	// The first element in the lineList is the UUID.
	uniqeID := lineList[0]

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error occurred while scanning id.txt file. %w", err)
	}

	log.Info().Str("ID:", uniqeID).Msg("Successfully retrieved ID from id.txt file.")
	return uniqeID, nil
}

// writeDataToIDTxtFile writes the ID and the Agent Version to the id.txt file
// in a certain format.
func writeDataToIDTxtFile(uniqueID, UUID string) (string, error) {
	// Added these commas for backwards compatibility (should be deleted in the
	// future since they are unnecessary).
	// Added the Agent version to the id.txt file so we could know which version
	// of the agent is running on the machine.
	idFileContent := fmt.Sprintf("%s,,,,,,\nAgent Version: %s\nUUID: %s", uniqueID, AgentVersion, UUID)
	idFilePath := filepath.Join(CymetricxPath, "id.txt")

	if err := createFileWithPermissionsAndWriteToIt(idFilePath, idFileContent, 0644); err != nil {
		return "", fmt.Errorf("error writing the new UUID to id.txt file. %w", err)
	}

	log.Info().Msgf("Successfully wrote data to id.txt file")
	return uniqueID, nil
}
func writeDataToIDTxtFile2(idFileContent, uniqueID, baseFileName string) (string, error) {
	// Added these commas for backwards compatibility (should be deleted in the
	// future since they are unnecessary).
	// Added the Agent version to the id.txt file so we could know which version
	// of the agent is running on the machine.
	fileName := fmt.Sprintf("%s.txt", baseFileName)
	idFilePath := filepath.Join(CymetricxPath, fileName)

	if err := createFileWithPermissionsAndWriteToIt(idFilePath, idFileContent, 0644); err != nil {
		return "", fmt.Errorf("error writing the new UUID to id.txt file. %w", err)
	}

	log.Info().Msgf("Successfully wrote data to %s file", idFilePath)
	return uniqueID, nil
}

func writeDataToProductIDTxtFile(productID, productName string) (string, error) {
	// Added these commas for backwards compatibility (should be deleted in the
	// future since they are unnecessary).
	// Added the Agent version to the id.txt file so we could know which version
	// of the agent is running on the machine.
	productFileContent := fmt.Sprintf("%s,,,,,,", productID)

	productFilePath := fmt.Sprintf("%s.txt", productName)
	productFileFullPath := filepath.Join(CymetricxPath, productFilePath)

	if err := createFileWithPermissionsAndWriteToIt(productFileFullPath, productFileContent, 0644); err != nil {
		return "", fmt.Errorf("error writing the new UUID to id.txt file. %w", err)
	}

	log.Info().Msgf("Successfully wrote data to %s file", productFilePath)
	return productID, nil
}

// getCurrentUTCTimeFormatted returns the current UTC time in the format "2006-01-02 15:04"
func getCurrentUTCTimeFormatted() string {
	utcLocation := time.UTC
	currentUTCTime := time.Now().In(utcLocation)
	currentFormatedUTCTime := currentUTCTime.Format("2006-01-02 15:04")
	return currentFormatedUTCTime
}

// generateUUID creates a unique identifier by generating random bytes.
// It applies an MD5 hash to these bytes and then transforms the hash
// into a 32-character hexadecimal string, which is returned as the unique
// identifier. It uses time seeding as backup for generating random bytes.
func generateUUID() string {
	log.Info().Msg("Generating UUID.")

	// create a byte slice to be filled with random bytes
	randomBytes := make([]byte, 16)

	// fill the byte slice with random bytes using crypto/rand
	_, err := cRand.Read(randomBytes)
	if err != nil {
		log.Error().Err(err).Msg("Error filling randomBytes with random decimals using crypto/rand. Using fallback UUID method.")
		generateFallbackUUID(&randomBytes)
	}

	// hash the random bytes using MD5
	uuid, err := getHexHash(string(randomBytes))
	if err != nil {
		log.Fatal().Err(err).Msg("Error hashing UUID.")
	}

	log.Info().Msg("Succefully generated UUID.")

	return uuid
}

// generateFallbackUUID generates a unique ID for the agent using math/rand if crypto/rand fails
func generateFallbackUUID(randomBytes *[]byte) {
	mathRand := mRand.New(mRand.NewSource(time.Now().UnixNano()))
	for i := range *randomBytes {
		(*randomBytes)[i] = byte(mathRand.Intn(256))
	}
}

// getComputerInfo gets all of the computer information including the OS version, hostname, and OS architecture
func getComputerInfo() string {
	windowsVersionInfo, err := getWindowsVersionInfo()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get windows version info using Get-ItemProperty Registry.")
	}

	hostname, err := getHostName()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get hostname.")
	}

	osArchitecture, err := getOsArchitecture()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get os architecture.")
	}

	// The addition of "Get-ItemProperty::fortress::" is so the server would know how to deal with it according
	// to the type of the way the data was returned since this value would be used in the server side to parse the data
	computerInfo := strings.Join([]string{
		"Get-ItemProperty::fortress::" + string(windowsVersionInfo),
		"hostname:" + hostname,
		"osarchitecture:" + osArchitecture,
	}, "\n")

	// We check for each value because the FallBackComputerINfo returns all of the following information if needed
	if windowsVersionInfo == "" || hostname == "" || osArchitecture == "" {
		computerInfo = getFallbackComputerInfo()
	}

	return computerInfo
}

// getFallbackComputerInfo gets computer info using Get-ComputerInfo or systeminfo if Registry fails to return the info
func getFallbackComputerInfo() string {
	windowsVersionInfo, err := exec.Command(cmdPath, "/c ", powerShellPath, "Get-ComputerInfo").Output()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get computer info using Get-ComputerInfo.")
		windowsVersionInfo, err = exec.Command(cmdPath, "/c", "systeminfo ").Output()
		if err == nil {
			return "systeminfo::fortress::" + string(windowsVersionInfo)
		}

		// If both Get-ComputerInfo and systeminfo failed, we log the error and return an empty string
		log.Error().Err(err).Msg("Failed to get computer info using systeminfo.")
	}
	return "ComputerInfo::fortress::" + string(windowsVersionInfo)
}

// getWindowsVersionInfo gets windows version info using Get-ItemProperty Registry
func getWindowsVersionInfo() (string, error) {
	// windowsVersionInfo, err := execCommandWithOutput(
	// 	powerShellPath,
	// 	`Get-ItemProperty Registry::'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'`,
	// )

	// if err != nil {
	// 	return "", fmt.Errorf("failed to get windows version info using Get-ItemProperty Registry: %w", err)
	// }

	productName, releaseId, err := getWindowsProductNameAndReleaseID()
	if err != nil {
		return "", fmt.Errorf("failed to get windows product name and release ID: %w", err)
	}

	return fmt.Sprintf("\nProductName: %s\nReleaseId: %s\n", productName, releaseId), nil
	// return string(windowsVersionInfo), nil
}

func getWindowsProductNameAndReleaseID() (string, string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "", "", fmt.Errorf("failed to open registry key for Windows NT CurrentVersion: %w", err)
	}
	defer key.Close()

	// Read the ProductName value
	productName, _, err := key.GetStringValue("ProductName")
	if err != nil {
		return "", "", fmt.Errorf("failed to read ProductName from registry: %w", err)
	}

	// Read the ReleaseId value
	releaseId, _, err := key.GetStringValue("ReleaseId")
	if err != nil {
		log.Error().Err(err).Msg("failed to read ReleaseId from registry: %w")
		return productName, "", nil

	}

	return productName, releaseId, nil
}

// getHostName gets device hostname
func getHostName() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}
	return hostname, nil
}

// getOsArchitecture returns the architecture of the running OS using the Go runtime package.\
// which is either 32-bit or 64-bit.
func getOsArchitecture() (string, error) {
	// The GOARCH value for the current system can be obtained directly from runtime.GOARCH.
	// This value represents the architecture: amd64, arm64, etc.
	// Map each architecture to a human-readable description.
	switch runtime.GOARCH {
	case "amd64", "arm64", "arm64be", "loong64", "mips64", "mips64le", "ppc64",
		"ppc64le", "riscv64", "s390x", "sparc64", "wasm":
		return "64-bit", nil
	case "386", "amd64p32", "arm", "armbe", "mips", "mips64p32", "mips64p32le",
		"mipsle", "ppc", "riscv", "s390", "sparc":
		return "32-bit", nil
	default:
		// For architectures not explicitly handled above, handle the error.
		return runtime.GOARCH, fmt.Errorf("unhandled architecture: %s", runtime.GOARCH)
	}
}

// getPublicIP returns the public IP of the host by trying to reach ifconfig.me
func getPublicIP() *string {
	log.Info().Msg("Attempting to retrieve the public IP from ifconfig.me.")

	// Create a custom http.Client with a timeout
	client := http.Client{
		Timeout: 20 * time.Second, // Set timeout to 5 seconds
	}

	// Send the request using the custom client
	response, err := client.Get("http://ifconfig.me/ip")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get IP from ifconfig.me.")
		return nil
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read response body from ifconfig.me.")
		return nil
	}

	if string(body) == "" {
		log.Warn().Msg("Received an empty body from ifconfig.me.")
		return nil
	}

	log.Debug().Msgf("Successfully retrieved public IP: %s", string(body))
	body_str := string(body)
	return &body_str
}

// getInstanceIDFromCloud gets the instance id from the cloud servers by making a request to the instance id endpoint.
func getInstanceIDFromCloud() string {
	log.Info().Msg("Attempting to retrieve the instance ID from cloud metadata.")

	// Create a custom http.Client with a timeout
	client := http.Client{
		Timeout: 20 * time.Second, // Set timeout to 5 seconds
	}

	// Send the request using the custom client
	response, err := client.Get("http://169.254.169.254/latest/meta-data/instance-id")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get instance ID from cloud metadata.")
		return "N/A"
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read response body from cloud metadata.")
		return "N/A"
	}

	if string(body) == "" {
		log.Warn().Msg("Received an empty body from cloud metadata.")
		return "N/A"
	}

	log.Debug().Msgf("Successfully retrieved instance ID: %s", string(body))
	return string(body)
}

// b64Encoding encodes the given string using base64 encoding.
func b64Encoding(data string) string {
	return b64.StdEncoding.EncodeToString([]byte(data))
}

// collectAndUploadSystemDetails_start_windows compresses the system data, stores it into a gzip file and uploads the file to the server
func collectAndUploadSystemDetails_start_windows(ifFirstUpload bool, hashFileName, endPoint string) error {
	log.Info().Msg("Initiating process to compress and upload system data to server.")

	systemDetails := collectSystemConfigurationDetailsV2()
	jsonPayload, err := processSystemDataIntoJson(systemDetails)
	if err != nil {
		return fmt.Errorf("error in processing system data to json in start windows: %w", err)
	}

	if jsonPayload == nil {
		return fmt.Errorf("jsonPayload is nil in start windows")
	}

	//! Do we still need these?
	isSame, err := checkIfHashFileSameOrUpdateIt(hashFileName, string(jsonPayload))
	if err != nil {
		return fmt.Errorf("could not check if hash file is same or update it because of: %w", err)
	}
	if isSame {
		return nil
	}

	// sleepForRandomDelayDuration(10, 60)
	// Buffer the body data so it can be reused across retries.
	// bufferedBody := io.NopCloser(bytes.NewReader(jsonPayload))

	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", endPoint, jsonPayload, 10)
	if err != nil {
		return fmt.Errorf("error in prepareAndExecuteUploadUpTimeHTTPRequest: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in uploading system detailes to the server: %w", err)
	}

	log.Info().Msg("System detailes successfully collected and uploaded to the server.")
	return nil
}

type SystemDataJson struct {
	ID                 string   `json:"id"`
	CurrentUTCTime     string   `json:"currentUtcTime"`
	AgentVersion       string   `json:"agentVersion"`
	RemoteIP           *string  `json:"remoteIp"`
	InstanceID         string   `json:"instanceId"`
	WindowsProductName string   `json:"windowsProductName"`
	OsOriginal         string   `json:"osOriginal"`
	OsName             string   `json:"osName"`
	HostName           string   `json:"hostName"`
	OsTypeArchitecture string   `json:"osTypeArchitecture"`
	IPAddresses        []string `json:"ipAddresses"`
	MultipleIP         string   `json:"multipleIp"`
	MacAddress         string   `json:"macAddress"`
	IpAd               string   `json:"ipAd"`
	DomainRoleNumber   uint32   `json:"domainRoleNumber"`
	CurrentBuild       string   `json:"currentBuild"`
	ProductName        *string  `json:"productName"`
	IsIntune           bool     `json:"isIntune"`
	ReleaseId          string   `json:"releaseId"`
}

func processSystemDataIntoJson(systemData SystemDetails) ([]byte, error) {
	id := systemData.UniqueID
	currentUTCTime := systemData.CurrentUTCTime
	agentVersion := AgentVersion
	publicIP := getPublicIP()
	instanceID := getInstanceIDFromCloud()
	info := systemData.ComputerInfo

	windowsProductName := ""
	osOriginal := ""
	osName := ""             // Microsoft Windows 10 Pro
	hostName := ""           // Waeem-HP-Laptop
	osTypeArchitecture := "" // 64-bit

	if len(instanceID) > 26 {
		instanceID = "N/A"
	}

	if strings.Contains(info, "Get-ItemProperty::fortress::") {
		var WindowsVersion string = "1709"

		for _, line := range strings.Split(info, "\n") {
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if strings.Contains(key, "ProductName") {
				windowsProductName = value
				osName = "Microsoft " + windowsProductName
			} else if strings.Contains(key, "hostname") {
				hostName = value
			} else if strings.Contains(key, "osarchitecture") {
				osTypeArchitecture = value
			} else if strings.Contains(key, "ReleaseId") {
				WindowsVersion = value
			}
		}

		// Handling Windows Product Name based on the version
		switch {
		case strings.Contains(windowsProductName, "Windows 10"):
			if WindowsVersion != "" {
				windowsProductName = "Windows_10_" + WindowsVersion
			} else {
				osOriginal = "Windows 10"
				windowsProductName = "Windows_10_1709"
			}
		case strings.Contains(windowsProductName, "Windows 11"):
			osOriginal = "Windows 11"
			windowsProductName = "Windows_10_2009"
		case strings.Contains(windowsProductName, "Windows Server 2016"):
			windowsProductName = "Windows_Server_2016"
		case strings.Contains(windowsProductName, "Windows Server 2019"):
			windowsProductName = "Windows_Server_2019"
		case strings.Contains(windowsProductName, "Windows 7"):
			windowsProductName = "Windows_7"
		case strings.Contains(windowsProductName, "Windows 8.1"):
			windowsProductName = "Windows_8.1"
		case strings.Contains(windowsProductName, "Windows Server 2012 R2"):
			windowsProductName = "Windows_Server_2012_R2"
		case strings.Contains(windowsProductName, "Windows Server 2012"):
			windowsProductName = "Windows_Server_2012"
		case strings.Contains(windowsProductName, "Windows Server 2008 R2"):
			windowsProductName = "Windows_Server_2008_R2"
		case strings.Contains(windowsProductName, "Windows Server 2008"):
			windowsProductName = "Windows_Server_2008"
		case strings.Contains(windowsProductName, "Windows Server"):
			osOriginal = windowsProductName
			windowsProductName = "Windows_Server_2019"
		}
	} else if strings.Contains(info, "ComputerInfo::fortress::") {
		// Default value for WindowsVersion
		var WindowsVersion = "1709"

		for _, line := range strings.Split(info, "\n") {
			line = strings.TrimSpace(line)
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if strings.Contains(key, "WindowsProductName") {
				windowsProductName = value
			} else if strings.Contains(key, "WindowsVersion") {
				WindowsVersion = value
			} else if strings.Contains(key, "OsName") {
				osName = value
			} else if strings.Contains(key, "CsDNSHostName") {
				hostName = value
			} else if strings.Contains(key, "CsSystemType") {
				osTypeArchitecture = value
			}
		}

		// Handling Windows Product Name based on the version
		switch {
		case strings.Contains(windowsProductName, "Windows 10"):
			if WindowsVersion != "1709" {
				windowsProductName = "Windows_10_" + WindowsVersion
			} else {
				osOriginal = "Windows 10"
				windowsProductName = "Windows_10_1709"
			}
		case strings.Contains(windowsProductName, "Windows 11"):
			osOriginal = "Windows 11"
			windowsProductName = "Windows_10_2009"
		case strings.Contains(windowsProductName, "Windows Server 2016"):
			windowsProductName = "Windows_Server_2016"
		case strings.Contains(windowsProductName, "Windows Server 2019"):
			windowsProductName = "Windows_Server_2019"
		case strings.Contains(windowsProductName, "Windows 7"):
			windowsProductName = "Windows_7"
		case strings.Contains(windowsProductName, "Windows 8.1"):
			windowsProductName = "Windows_8.1"
		case strings.Contains(windowsProductName, "Windows Server 2012 R2"):
			windowsProductName = "Windows_Server_2012_R2"
		case strings.Contains(windowsProductName, "Windows Server 2012"):
			windowsProductName = "Windows_Server_2012"
		case strings.Contains(windowsProductName, "Windows Server 2008 R2"):
			windowsProductName = "Windows_Server_2008_R2"
		case strings.Contains(windowsProductName, "Windows Server 2008"):
			windowsProductName = "Windows_Server_2008"
		case strings.Contains(windowsProductName, "Windows Server"):
			osOriginal = windowsProductName
			windowsProductName = "Windows_Server_2019"
		}
	} else if strings.Contains(info, "systeminfo::fortress::") {
		var WindowsProductName string

		lines := strings.Split(info, "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if strings.Contains(key, "OS Name") {
				WindowsProductName = value
				osName = WindowsProductName
			} else if strings.Contains(key, "Host Name") {
				hostName = value
			} else if strings.Contains(key, "System Type") {
				osTypeArchitecture = value
			}
		}

		// Handling Windows Product Name based on the version
		switch {
		case strings.Contains(WindowsProductName, "Windows 10"):
			osOriginal = "Windows 10"
			WindowsProductName = "Windows_10_1709"
		case strings.Contains(WindowsProductName, "Windows 11"):
			osOriginal = "Windows 11"
			WindowsProductName = "Windows_10_2009"
		case strings.Contains(WindowsProductName, "Windows Server 2016"):
			WindowsProductName = "Windows_Server_2016"
		case strings.Contains(WindowsProductName, "Windows Server 2019"):
			WindowsProductName = "Windows_Server_2019"
		case strings.Contains(WindowsProductName, "Windows 7"):
			WindowsProductName = "Windows_7"
		case strings.Contains(WindowsProductName, "Windows 8.1"):
			WindowsProductName = "Windows_8.1"
		case strings.Contains(WindowsProductName, "Windows Server 2012 R2"):
			WindowsProductName = "Windows_Server_2012_R2"
		case strings.Contains(WindowsProductName, "Windows Server 2012"):
			WindowsProductName = "Windows_Server_2012"
		case strings.Contains(WindowsProductName, "Windows Server 2008 R2"):
			WindowsProductName = "Windows_Server_2008_R2"
		case strings.Contains(WindowsProductName, "Windows Server 2008"):
			WindowsProductName = "Windows_Server_2008"
		case strings.Contains(WindowsProductName, "Windows Server"):
			osOriginal = WindowsProductName
			WindowsProductName = "Windows_Server_2019"
		}
	}

	if osOriginal == "" {
		osOriginal = windowsProductName
	}

	// Delete This Key:
	multipIP := ""

	ipAddresses := systemData.NetworkConfigs

	for _, ipAddress := range ipAddresses {
		//! What is the point of this duplicate removed?
		multipIP = strings.ReplaceAll(multipIP, "(Duplicate)", "") + ipAddress + ","
	}

	if multipIP == "" {
		multipIP = "N/A"
	}

	physAddresses, _ := getMACAddresses()

	macAddress := ""
	for _, physAddress := range physAddresses {
		macAddress = macAddress + physAddress + ","
	}

	if macAddress == "" {
		macAddress = "N/A"
	}

	ipAd := ""
	filteredIPAddresses := []string{}
	for _, ip := range ipAddresses {
		if !strings.Contains(ip, "169.254") {
			filteredIPAddresses = append(filteredIPAddresses, ip)
		}
	}

	if len(filteredIPAddresses) > 0 {
		ipAd = filteredIPAddresses[0]
	} else if len(ipAddresses) > 0 {
		ipAd = ipAddresses[0]
	}

	currentBuild, err := getRegistryKeyValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get CurrentBuild from registry.")
	}

	productName, err := getRegistryKeyValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ProductName from registry.")
	}

	isIntune, err := getRegistryKeyValue("HKLM\\Software\\Microsoft\\Provisioning\\OMADM\\Logger", "Intune")
	if err != nil {
		isIntune = "N/A"
		log.Error().Err(err).Msg("Failed to get Intune from registry.")
	}

	releaseId, err := getRegistryKeyValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ReleaseId from registry.")
	}

	// Create an instance of SystemDataJson and populate it
	systemDataJson := SystemDataJson{
		ID:                 id,
		CurrentUTCTime:     currentUTCTime,
		AgentVersion:       agentVersion,
		RemoteIP:           publicIP,
		InstanceID:         instanceID,
		WindowsProductName: windowsProductName,
		OsOriginal:         osOriginal,
		OsName:             osName,
		HostName:           hostName,
		OsTypeArchitecture: osTypeArchitecture,
		IPAddresses:        filteredIPAddresses,
		MultipleIP:         multipIP,
		MacAddress:         macAddress,
		IpAd:               ipAd,

		DomainRoleNumber: systemData.DomainRole,
		CurrentBuild:     currentBuild,
		ProductName:      strToPtrOrNil(productName),
		IsIntune:         isIntune != "N/A",
		ReleaseId:        releaseId,
	}

	// Convert the struct to a JSON string
	jsonData, err := json.Marshal(systemDataJson)
	if err != nil {
		// handle the error, maybe return it or log it
		return nil, fmt.Errorf("failed to marshal systemData to JSON: %w", err)
	}

	log.Debug().Str("SystemDataJson", string(jsonData)).Msg("Successfully processed system data into JSON.")

	return jsonData, nil

}

// getMACAddresses returns a slice of MAC addresses of the machine.
func getMACAddresses() ([]string, error) {
	var macs []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, intf := range interfaces {
		if intf.HardwareAddr != nil {
			macs = append(macs, strings.Title(intf.HardwareAddr.String()))
		}
	}
	return macs, nil
}

// createAndCompressPayloadIntoGZipFile creates and compresses the JSON
// payload into a GZip file and returns the path of the GZip file created.
func createAndCompressPayloadIntoGZipFile(jsonPayload []byte, fileName string) (string, error) {
	log.Info().Str("FileName", fileName).Msg("Starting creation and compression of payload into GZip file.")

	// TODO: This needs to be changed and include the id in the request itself instead of the filename.
	filePath := filepath.Join(CymetricxPath, "Compressed Files", id+"_"+fileName)

	// create the gzip file.
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("could not create %s file: %w", fileName, err)
	}
	defer file.Close()

	// create a new writer that writes to the gzip file.
	gzipWriter := gzip.NewWriter(file)

	// This is necessary for the writer flush (to write the rest of the data
	// in the buffer to the file)
	defer gzipWriter.Close()

	// write the JSON payload to the gzip file.
	if _, err = gzipWriter.Write(jsonPayload); err != nil {
		return "", fmt.Errorf("could not write to gzip writer: %w", err)
	}

	log.Info().Str("FilePath", filePath).Msg("Successfully created and compressed payload into GZip file.")
	return filePath, nil
}

// createAndExecuteUploadRequestV1 creates a file upload request and executes it using the HTTP client.
func createAndExecuteUploadRequestV1(endPoint string, extraParams map[string]string, filePath string) (bytes.Buffer, error) {
	log.Info().Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("Initiating file upload request.")

	req, err := createFileUploadRequestV1(endPoint, extraParams, "file", filePath)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("could not create file upload request to %s, file: %s : %w", endPoint, filePath, err)
	}

	log.Debug().Msg("File upload request created successfully, preparing to execute.")

	responseBody, err := executeUploadRequestV1(req)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("could not execute file upload request to %s, file: %s : %w", endPoint, filePath, err)
	}

	log.Info().Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("File upload request executed successfully.")
	return responseBody, nil
}

// createAndExecuteUploadRequest creates a file upload request and executes it using the HTTP client.
func createAndExecuteUploadRequestV2(endPoint string, filePath string) (bytes.Buffer, error) {
	log.Info().Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("Starting file upload request...")

	if !fileExists(filePath) {
		return bytes.Buffer{}, fmt.Errorf("file about to be uploaded '%s' does not exit", filePath)
	}

	req, err := createFileUploadRequestV2(endPoint, "file", filePath)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("could not create file upload request to %s, file: %s : %w", endPoint, filePath, err)
	}

	responseBody, err := executeHTTPRequestWithTokenValidtyV2(req, 10)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("could not execute file upload request to %s, file: %s : %w", endPoint, filePath, err)
	}

	log.Info().Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("Successfully executed file upload request.")
	return responseBody, nil
}

// createAndExecuteUploadRequest creates a file upload request and executes it using the HTTP client.
func createAndExecuteFileUploadRequest(endPoint string, filePath string) (bytes.Buffer, error) {
	log.Info().Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("Starting file upload request...")

	if !fileExists(filePath) {
		return bytes.Buffer{}, fmt.Errorf("file about to be uploaded '%s' does not exit", filePath)
	}

	var req *http.Request

	for retries := 0; retries < 10; retries++ {
		var err error
		req, err = createFileUploadRequestV2(endPoint, "file", filePath)
		if err != nil {
			return bytes.Buffer{}, fmt.Errorf("could not create file upload request to %s, file: %s : %w", endPoint, filePath, err)
		}

		if err := checkIfTokenDateExpiredAndUpdateHeader(req); err != nil {
			return bytes.Buffer{}, fmt.Errorf("couldn't check if token expired for %s request to %s ", req.Method, req.URL)
		}

		resp, err := attemptRequest(req, retries)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return bytes.Buffer{}, fmt.Errorf("this %s request to %s was not found 404, %w", req.Method, req.URL, err)
		}

		responseBody, err := readResponseBody(resp)
		if err != nil {
			return bytes.Buffer{}, fmt.Errorf("failed to read response body of %s request to %s, %w", req.Method, req.URL, err)
		}

		isValid, err := checkTokenValidityAndUpdateHeaderV2(responseBody, req)
		if err != nil {
			return bytes.Buffer{}, fmt.Errorf("failed to check token validity in URL Path: %s, because of error: %w", req.URL, err)
		}

		// If the token is valid, then return.
		if !isValid {
			continue
		}

		log.Info().Msgf("Successfully executed uplading file for %s request to %s.", req.Method, req.URL)
		return responseBody, nil
	}

	return bytes.Buffer{}, fmt.Errorf("reached maximum retry in file uploading attempts for %s request to %s", req.Method, req.URL)
}

// executeHTTPRequestWithTokenValidtyV2 excutes the file upload request provided
// in the req parameter using the HTTP client provided in the client parameter.
// It retries the request up to 10 times if it fails or the response status code
// is not 200. It also checks if the token is valid, if not, it updates the token.
// The retries are set to 10 times.
func executeHTTPRequestWithTokenValidtyForFileV2(req *http.Request, retries int) (bytes.Buffer, error) {
	req.Header.Set("Authorization", "Bearer"+authenticationTokenV2)

	responseBody, err := executeHTTPRequestV2(req, retries)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to execute %s request to %s, %w", req.Method, req.URL, err)
	}

	// TODO: Double check if this is actually being checked.
	if err := handleTokenValidityV2(responseBody, req); err != nil {
		return bytes.Buffer{}, err
	}

	log.Info().Msgf("Successfully executed %s request to %s with token validity.", req.Method, req.URL)
	return responseBody, nil
}

// executeUploadRequestV1 executes the upload request and retries if it fails. It reads the response body and checks if the authentication token is invalid.
// It updates the authentication token if it's invalid. It tries to
func executeUploadRequestV1(req *http.Request) (bytes.Buffer, error) {
	log.Info().Str("URL", req.URL.String()).Msg("Starting file upload attempt.")

	for retries := 0; retries < 10; retries++ {
		resp, err := sendCustomHTTPClientRequest(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			log.Error().Err(err).Str("URL", req.URL.String()).Msgf("Upload attempt %d failed. Preparing to retry.", retries+1)

			backoff := time.Duration(math.Pow(2, float64(retries))) * time.Second
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}

			log.Info().Str("URL", req.URL.String()).Msgf("Sleeping for %s before retrying.", backoff.String())
			time.Sleep(backoff)
			continue
		}

		var responseBody bytes.Buffer
		_, err = io.Copy(&responseBody, resp.Body)
		if err != nil {
			log.Error().Err(err).Str("URL", req.URL.String()).Msg("Failed to copy response body after uploading.")
			return bytes.Buffer{}, err
		}
		resp.Body.Close()

		isValid, err := checkTokenValidityAndUpdateHeaderV1(responseBody, req)
		if err != nil {
			log.Error().Err(err).Str("URL", req.URL.String()).Msg("Failed to check token validity.")
			return bytes.Buffer{}, err
		}

		if isValid {
			log.Info().Str("URL", req.URL.String()).Msg("Upload successful and token is valid.")
			return responseBody, nil
		}

		log.Warn().Str("URL", req.URL.String()).Msg("Token found to be invalid. Re-authenticating and retrying upload.")
		req.Header.Set("Authorization", authenticationTokenV1)
		if _, err := executeUploadRequestV1(req); err != nil {
			log.Error().Err(err).Str("URL", req.URL.String()).Msg("Failed to upload after re-authentication.")
			return bytes.Buffer{}, err
		}

		return responseBody, nil
	}

	log.Error().Str("URL", req.URL.String()).Msg("Reached max retries for file upload. Aborting.")
	return bytes.Buffer{}, fmt.Errorf("could not upload files to %s after reaching max retries", req.URL.String())
}

// checkIfPreviousHashFileMatches checks if the previous value inside of the hash file matches the calculated hash value.
func checkIfPreviousHashFileMatches(hashFileName string, hashFilePath string, encodedDataHex string) (bool, error) {
	previousHashedValue, err := os.ReadFile(hashFilePath)
	if err != nil {
		return false, fmt.Errorf("failed to read hash file name: %s, because of error: %w", hashFileName, err)
	}

	if string(previousHashedValue) == encodedDataHex {
		return true, nil
	}

	err = os.WriteFile(hashFilePath, []byte(encodedDataHex), 0644)
	if err != nil {
		return false, fmt.Errorf("failed to create/write to hash file name: %s, because of error: %w", hashFileName, err)
	}

	return false, nil
}

// createFileUploadRequestV1 creates an http request to upload a file to the specified endpoint using the multipart/form-data content type
func createFileUploadRequestV1(endPoint string, params map[string]string, paramName, filePath string) (*http.Request, error) {
	log.Info().Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("Initiating creation of file upload request.")

	body, contentType, err := createMultipartFormDataV1(params, paramName, filePath)
	if err != nil {
		log.Error().Err(err).Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("Failed to create multipart form data.")
		return nil, err
	}

	log.Debug().Msg("Multipart form data created successfully, preparing to create the http request.")

	req, err := createHttpRequestV1("POST", endPoint, body.Bytes(), contentType)
	if err != nil {
		log.Error().Err(err).Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("Failed to create http request.")
		return nil, fmt.Errorf("failed to create http request to upload file, %w", err)
	}

	log.Debug().Str("EndPoint", endPoint).Msg("HTTP request created successfully, setting authorization header.")

	//req.Header.Set("Authorization", authenticationTokenV1)

	log.Info().Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("File upload request creation complete.")
	return req, nil
}

// createFileUploadRequest creates an http request to upload a file to the specified endpoint using the multipart/form-data content type
func createFileUploadRequestV2(endPoint string, paramName, filePath string) (*http.Request, error) {
	body, contentType, err := createMultipartFormDataV2(paramName, filePath)
	if err != nil {
		log.Error().Err(err).Str("EndPoint", endPoint).Str("FilePath", filePath).Msg("Failed to create multipart form data.")
		return nil, err
	}

	req, err := createHttpRequestV2("POST", endPoint, body.Bytes(), "application/json")
	if err != nil {
		return nil, fmt.Errorf("failed to create http request to upload file, %w", err)
	}

	// req.Header.Set("Authorization", authenticationTokenV2)
	req.Header.Set("Authorization", "Bearer "+authenticationTokenV2)
	req.Header.Del("Content-Type")
	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// createMultipartFormDataV1 creates a multipart form data to upload a gzip file and some extra form data parameters to the server.
func createMultipartFormDataV1(params map[string]string, paramName, filePath string) (*bytes.Buffer, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open file %s, %w", filePath, err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	// The use of form-data is because we send a file and some extra form data parameters
	part, err := writer.CreateFormFile(paramName, filepath.Base(filePath))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create form-data file %s, %w", paramName, err)
	}

	if _, err = io.Copy(part, file); err != nil {
		return nil, "", fmt.Errorf("failed to copy file %s to form-data file %s, %w", filePath, paramName, err)
	}

	//! Why do you send these extra form data parameters?
	for key, val := range params {
		if err = writer.WriteField(key, val); err != nil {
			return nil, "", fmt.Errorf("failed to write field %s with value %s, %w", key, val, err)
		}
	}

	if err = writer.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart/form-data writer, %w", err)
	}

	return body, writer.FormDataContentType(), nil
}

// createMultipartFormData creates a multipart form data to upload a gzip file
// and some extra form data parameters to the server. It returns the body of the
// multipart form data and the content type of the body. The paramName parameter
// specifies the name of the file parameter in the request body.
func createMultipartFormDataV2(paramName, filePath string) (*bytes.Buffer, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open file %s, %w", filePath, err)
	}
	defer file.Close()

	body := &bytes.Buffer{}

	// This creates a new multipart writer. Multipart MIME is a way of sending
	// binary or arbitrary data in one message  broken in multiple parts, each
	// having its own set of headers.
	writer := multipart.NewWriter(body)

	// We use form-data because we need to send a file along with additional
	// form data parameters.
	// The following line adds a new form-data part to the multipart writer.
	// The 'paramName' is the form field name which is "file" in our case,
	// and 'filepath.Base(filePath)' is the filename that will be used on the
	// server. This sets the content-disposition to 'form-data', and specifies
	// the name and filename.
	formPart, err := writer.CreateFormFile(paramName, filepath.Base(filePath))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create form-data file %s, %w", paramName, err)
	}

	// Copy the file to the form-data file.
	if _, err = io.Copy(formPart, file); err != nil {
		return nil, "", fmt.Errorf("failed to copy file %s to form-data file %s, %w", filePath, paramName, err)
	}

	// Close the multipart writer.
	if err = writer.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart/form-data writer, %w", err)
	}

	return body, writer.FormDataContentType(), nil
}

// createAndRunBatScriptWithoutOutput creates a bat script, writes the specified content to it and runs it.
func createAndRunBatScriptWithoutOutput(scriptName string, scriptContent string) error {
	// scripFilePath := filepath.Join(CymetricxPath, scriptName)
	filePath := filepath.Join(CymetricxPath, scriptName)
	// if err := os.WriteFile(scriptName, []byte(scriptContent), 0744); err != nil {
	if err := os.WriteFile(filePath, []byte(scriptContent), 0744); err != nil {
		return fmt.Errorf("failed to create/write to %s file, %w", filePath, err)
	}
	defer os.Remove(filePath)

	if err := exec.Command(filePath).Run(); err != nil {
		return fmt.Errorf("failed to run %s file, %w", scriptName, err)
	}

	return nil
}

// createAndRunBatScriptWithOutput creates a bat script, writes the specified content to it and runs it.
func createAndRunBatScriptWithOutput(scriptName string, scriptContent string) ([]byte, error) {
	filePath := filepath.Join(CymetricxPath, scriptName)
	if err := os.WriteFile(filePath, []byte(scriptContent), 0744); err != nil {
		return nil, fmt.Errorf("failed to create/write to %s file, %w", filePath, err)
	}
	defer os.Remove(filePath)

	output, err := execCommandWithOutputRaw(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to run %s file, %w", scriptName, err)
	}

	return output, nil
}

// handleCymetricxRecoveryServiceStatus handles the cymetricx recovery service status, if it is running or not.
// If it is running, it stops it, replaces the executable file, starts it again and sets the registry key image path.
// If it is not running, it replaces the executable file, installs the service, sets the registry key image path and starts the service.
func handleCymetricxRecoveryServiceStatus(cmdFlags CMDFlags) error {
	// If profiling is enabled, then return without doing anything.
	// We don't want to run the recovery service if profiling is enabled.
	// Since it reruns the service of cymetricx and we want it to be off.
	if cmdFlags.Profiling {
		return nil
	}
	// get the information about the cymetricx recovery service, including its status
	// This shouldn't return if the recovery does not exit, cuz that means it is not running, so i need to start it
	// Just output the error as a warning to the errors.log and continue excuting, cuz when an errror occurs, it
	// means that there is no Cymetricx Recovery running, so we need to install it and run it
	cymetricxRecoveryService, err := getServiceStatus("Cymetricx Recovery")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get the status of the cymetricx recovery service.")
	}

	if cymetricxRecoveryService == "Running" {
		return handleRunningRecoveryService()
	}

	return handleNotRunningRecoveryService()
}

func getServiceStatus(serviceName string) (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return "", fmt.Errorf("could not access service: %w", err)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("could not query service: %w", err)
	}

	return serviceStateToString(status.State), nil
}

func serviceStateToString(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "Stopped"
	case svc.StartPending:
		return "Start Pending"
	case svc.StopPending:
		return "Stop Pending"
	case svc.Running:
		return "Running"
	case svc.ContinuePending:
		return "Continue Pending"
	case svc.PausePending:
		return "Pause Pending"
	case svc.Paused:
		return "Paused"
	default:
		return "Unknown"
	}
}

// handleRunningRecoveryService handles the cymetricx recovery service if it is running.
func handleRunningRecoveryService() error {
	cymetricxmFilePath := filepath.Join(CymetricxPath, "cymetricxm.exe")
	stopCymetricxRecoveryCommand := fmt.Sprintf(`"%s" stop "Cymetricx Recovery"`, cymetricxmFilePath)
	if err := createAndRunBatScriptWithoutOutput("recovery_run.bat", stopCymetricxRecoveryCommand); err != nil {
		return fmt.Errorf("failed to stop cymetricx recovery service, %w", err)
	}

	setServiceRegistryKeyForImagePath("Cymetricx Recovery", "cymetricxm_2.exe")

	if err := replaceExecutableFile("recovery.exe", "recovery_cymetricx.exe"); err != nil {
		return fmt.Errorf("failed to create new cymetricx recovery, %w", err)
	}

	startCymetricxRecoveryCommand := fmt.Sprintf(`"%s" start "Cymetricx Recovery"`, cymetricxmFilePath)
	if err := createAndRunBatScriptWithoutOutput("recovery_run.bat", startCymetricxRecoveryCommand); err != nil {
		return fmt.Errorf("failed to start cymetricx recovery service, %w", err)
	}

	scFilePath := getSCPath()
	restartCommand := fmt.Sprintf(`%s failure "Cymetricx Recovery" "actions=restart/180000/restart/180000/restart/180000" "reset=86400"`, scFilePath)
	if err := createAndRunBatScriptWithoutOutput("restart_failer2.bat", restartCommand); err != nil {
		return fmt.Errorf("failed to run restart_failer2.bat file, %w", err)
	}

	return nil
}

// handleNotRunningRecoveryService handles the cymetricx recovery service if it is not running.
func handleNotRunningRecoveryService() error {
	if err := replaceExecutableFile("cymetricxm.exe", "cymetricxm_2.exe"); err != nil {
		return fmt.Errorf("failed to replace cymetricxm_2.exe, %w", err)
	}

	if err := replaceExecutableFile("recovery.exe", "recovery_cymetricx.exe"); err != nil {
		return fmt.Errorf("failed to replace recovery_cymetricx.exe, %w", err)
	}

	if err := replaceExecutableFile("cymetricxService.exe", "cymetricxService_2.exe"); err != nil {
		return fmt.Errorf("failed to replace recovery_cymetricx.exe, %w", err)
	}

	batScriptContent := strings.Join([]string{
		fmt.Sprintf(`"%s\cymetricxm_2.exe" install "Cymetricx Recovery" "%s\recovery_cymetricx.exe"`, CymetricxPath, CymetricxPath),
		fmt.Sprintf(`"%s\cymetricxm_2.exe" set "Cymetricx Recovery" AppThrottle 1`, CymetricxPath),
		fmt.Sprintf(`"%s\cymetricxm_2.exe" set  "Cymetricx Recovery" Description "CYMETRICX Windows Recovery"`, CymetricxPath),
		fmt.Sprintf(`"%s\cymetricxm.exe" start "Cymetricx Recovery"`, CymetricxPath),
	}, " \n")

	if err := createAndRunBatScriptWithoutOutput("recovery_run.bat", batScriptContent); err != nil {
		return fmt.Errorf("failed to run recovery_run.bat file, %w", err)
	}

	setServiceRegistryKeyForImagePath("Cymetricx Recovery", "cymetricxm_2.exe")

	scFilePath := getSCPath()
	restartCommand := fmt.Sprintf(`%s failure "Cymetricx Recovery" "actions=restart/180000/restart/180000/restart/180000" "reset=86400"`, scFilePath)
	if err := createAndRunBatScriptWithoutOutput("restart_failer2.bat", restartCommand); err != nil {
		return fmt.Errorf("failed to run restart_failer2.bat file, %w", err)
	}

	return nil
}

// replaceExecutableFile kills the process of the target file, copies the source file to the newly created target file.
func replaceExecutableFile(sourceFileName, targetFileName string) error {
	sourcePath := filepath.Join(CymetricxPath, sourceFileName)
	targetPath := filepath.Join(CymetricxPath, targetFileName)
	var output string
	if targetPath != "" {
		output, err := killProcess(targetFileName)
		if err != nil && !strings.Contains(string(output), "not found") {
			return fmt.Errorf("failed to kill %s process because of %s: %w", targetPath, output, err)
		}
	}

	if strings.Contains(string(output), "not found") {
		log.Error().Str("Output", string(output)).Str("target File:", targetPath).Msg("Process not found.")
	}

	if err := copyFile(sourcePath, targetPath); err != nil {
		return fmt.Errorf("failed to copy %s file, %w", sourcePath, err)
	}

	return nil
}

// checkTokenValidityAndUpdateHeaderV1 checks if the token is valid, if not, it updates the token again and updates the header of Authorization.
func checkTokenValidityAndUpdateHeaderV1(responseBody bytes.Buffer, req *http.Request) (bool, error) {
	if !strings.Contains(responseBody.String(), "token is invalid") {
		return true, nil
	}

	authenticationTokenV1 = loginAndReturnTokenV1(loginPassword)
	if authenticationTokenV1 == "" {
		return false, fmt.Errorf("could not login and get authentication token while uploading after re-authentication")
	}

	req.Header.Set("Authorization", authenticationTokenV1)
	return false, nil
}

// executeHTTPRequestV11 executes the HTTP request and returns the
// response body as bytes.Buffer. It takes the request, client, and
// number of retries as parameters. If retries is <1, it retries the
// request forever. Otherwise, it retries the request up to the given
// number of retries.
func executeHTTPRequestV11(req *http.Request, retries int) (bytes.Buffer, error) {
	log.Info().Msgf("Starting excuting %s request to %s ...", req.Method, req.URL)

	resp, err := sendRequestWithRetriesV1(req, retries)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer resp.Body.Close()

	responseBody, err := readResponseBody(resp)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to read response body of %s request to %s, %w", req.Method, req.URL, err)
	}

	log.Info().Msgf("Successfully executed %s request to %s.", req.Method, req.URL)
	return responseBody, nil
}

// sendRequestWithRetriesV1 sends the given request using the given client and
// retries up to 10 times if it fails or the response status code is not 200.
// It returns the response of the request.
func sendRequestWithRetriesV1(req *http.Request, retries int) (*http.Response, error) {

	if retries < 1 {
		// set the default number of retries to infinity
		retries = math.MaxInt32
	}

	for i := 0; i < retries; i++ {
		resp, err := sendCustomHTTPClientRequest(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			handleFailedRequest(req, resp, i, err)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("reached maximum retry attempts for %s request to %s", req.Method, req.URL)
}

// stop agent func
func stopAgent() {
	cymetricxServiceName := "CYMETRICX"

	script := strings.Join([]string{
		fmt.Sprintf(`sc stop "%s"`, cymetricxServiceName),
	}, "\n")

	if err := createAndRunBatScriptWithoutOutput("RestartServiceCymetricx.bat", script); err != nil {
		log.Error().Err(err).Msg("failed to run RestartServiceCymetricx.bat: %w")
	}

}

// Delete agent func
func deleteAgent() {
	cymetricxServiceName := "CYMETRICX"

	script := strings.Join([]string{
		fmt.Sprintf(`sc stop "%s"`, cymetricxServiceName),
	}, "\n")

	if err := createAndRunBatScriptWithoutOutput("RestartServiceCymetricx.bat", script); err != nil {
		log.Error().Err(err).Msg("failed to run RestartServiceCymetricx.bat: %w")
	}

}

// extractFeatureSettings extracts the feature settings from the response body.
// These settings are flags that determine which features are enabled or disabled.
func extractFeatureSettings(featuresSettingsFlags string) string {
	if featuresSettingsFlags == "" {
		featureToggleConfig.LocalDNSMonitoring = true              //->get_localdns()**
		featureToggleConfig.VulnerabilityScan = true               //->******
		featureToggleConfig.IdentityUsersCheck = true              //-> getusers()**
		featureToggleConfig.InstalledPatchesCheck = true           //->get_kb()**
		featureToggleConfig.PatchManagementSystemCheck = true      //->*******
		SystemHardeningCheck = true                                //->controls complines **
		networksettings = true                                     //->get_network()**
		remotetoolslogs = true                                     //->get_connectionanydesk()**
		applicationsandsoftwares = true                            //->getApplications()**
		windowsstartup = true                                      //->get_startup()**
		windowsservices = true                                     //->get_GetService()**
		featureToggleConfig.SystemProcessesAndServicesCheck = true //->getprocess() getservices()**
		scheduledtasks = true                                      //->get_winScheduledTask()**
		networkshares = true                                       //->get_netshare()**
		bitlocker = true                                           //->get_bitlocker()**
		av = true                                                  //->getAV()**
		bootsecure = true                                          //->get_autofim()**
		computerconfigrations = true                               //->get_computerinfo()**
		Chromeextions = true                                       //->get_Chromeextions()**
		DisplayVersion = true                                      //->get_DisplayVersion()**
		tpmwin = true                                              //->get_tpm_win()
		getGPOReport = true                                        //->gpos()
		rdpstatus = true                                           //get_rdp()
		assetDiscoveryUsingADComputer = true                       //compcs()
		getuptimewin = true                                        //get_uptime()
		winproxysettings = true                                    //==> get_proxy()
		certs = true                                               //certswin()()
		featureToggleConfig.ActivePatchesCheck = true              //uploadpatchesfiles()

	} else {
		// Convert string occurrences to boolean
		featureToggleConfig.VulnerabilityScan = strings.Contains(featuresSettingsFlags, "vuls='true'")
		featureToggleConfig.IdentityUsersCheck = strings.Contains(featuresSettingsFlags, "identityusers='true'")
		featureToggleConfig.InstalledPatchesCheck = strings.Contains(featuresSettingsFlags, "installedpatchesKb='true'")
		featureToggleConfig.PatchManagementSystemCheck = strings.Contains(featuresSettingsFlags, "patchmgmt='true'")
		SystemHardeningCheck = strings.Contains(featuresSettingsFlags, "hardening='true'")
		networksettings = strings.Contains(featuresSettingsFlags, "networksettings='true'")
		featureToggleConfig.LocalDNSMonitoring = strings.Contains(featuresSettingsFlags, "localdns='true'")
		remotetoolslogs = strings.Contains(featuresSettingsFlags, "remotetoolslogs='true'")
		applicationsandsoftwares = strings.Contains(featuresSettingsFlags, "applicationsandsoftwares='true'")
		windowsstartup = strings.Contains(featuresSettingsFlags, "windowsstartup='true'")
		windowsservices = strings.Contains(featuresSettingsFlags, "windowsservices='true'")
		featureToggleConfig.SystemProcessesAndServicesCheck = strings.Contains(featuresSettingsFlags, "systemprocessesandservices='true'")
		scheduledtasks = strings.Contains(featuresSettingsFlags, "scheduledtasks='true'")
		networkshares = strings.Contains(featuresSettingsFlags, "networkshares='true'")
		bitlocker = strings.Contains(featuresSettingsFlags, "bitlocker='true'")
		av = strings.Contains(featuresSettingsFlags, "av='true'")
		bootsecure = strings.Contains(featuresSettingsFlags, "bootsecure='true'")
		computerconfigrations = strings.Contains(featuresSettingsFlags, "computerconfigrations='true'")
		Chromeextions = strings.Contains(featuresSettingsFlags, "Chromeextions='true'")
		DisplayVersion = strings.Contains(featuresSettingsFlags, "DisplayVersion='true'")
		tpmwin = strings.Contains(featuresSettingsFlags, "tpmwin='true'")
		getGPOReport = strings.Contains(featuresSettingsFlags, "getgporeport='true'")
		rdpstatus = strings.Contains(featuresSettingsFlags, "rdpstatus='true'")
		assetDiscoveryUsingADComputer = strings.Contains(featuresSettingsFlags, "assetdiscoveryusingadcomputer='true'")
		getuptimewin = strings.Contains(featuresSettingsFlags, "getuptimewin='true'")
		winproxysettings = strings.Contains(featuresSettingsFlags, "winproxysettings='true'")
		certs = strings.Contains(featuresSettingsFlags, "certs='true'")
		featureToggleConfig.ActivePatchesCheck = strings.Contains(featuresSettingsFlags, "patchesactive='true'")
	}

	// Create 'datafeatures' string with boolean values converted back to string
	datafeaturs := strings.Join([]string{
		"vuls=" + strconv.FormatBool(featureToggleConfig.VulnerabilityScan),
		"certs=" + strconv.FormatBool(certs),
		"getgporeport=" + strconv.FormatBool(getGPOReport),
		"rdpstatus=" + strconv.FormatBool(rdpstatus),
		"assetdiscoveryusingadcomputer=" + strconv.FormatBool(assetDiscoveryUsingADComputer),
		"getuptimewin=" + strconv.FormatBool(getuptimewin),
		"winproxysettings=" + strconv.FormatBool(winproxysettings),
		"identityusers=" + strconv.FormatBool(featureToggleConfig.IdentityUsersCheck),
		"installedpatchesKb=" + strconv.FormatBool(featureToggleConfig.InstalledPatchesCheck),
		"patchmgmt=" + strconv.FormatBool(featureToggleConfig.PatchManagementSystemCheck),
		"hardening=" + strconv.FormatBool(SystemHardeningCheck),
		"networksettings=" + strconv.FormatBool(networksettings),
		"localdns=" + strconv.FormatBool(featureToggleConfig.LocalDNSMonitoring),
		"remotetoolslogs=" + strconv.FormatBool(remotetoolslogs),
		"applicationsandsoftwares=" + strconv.FormatBool(applicationsandsoftwares),
		"windowsstartup=" + strconv.FormatBool(windowsstartup),
		"windowsservices=" + strconv.FormatBool(windowsservices),
		"systemprocessesandservices=" + strconv.FormatBool(featureToggleConfig.SystemProcessesAndServicesCheck),
		"scheduledtasks=" + strconv.FormatBool(scheduledtasks),
		"networkshares=" + strconv.FormatBool(networkshares),
		"bitlocker=" + strconv.FormatBool(bitlocker),
		"av=" + strconv.FormatBool(av),
		"bootsecure=" + strconv.FormatBool(bootsecure),
		"computerconfigrations=" + strconv.FormatBool(computerconfigrations),
		"Chromeextions=" + strconv.FormatBool(Chromeextions),
		"DisplayVersion=" + strconv.FormatBool(DisplayVersion),
		"tpmwin=" + strconv.FormatBool(tpmwin),
		"patchesactive=" + strconv.FormatBool(featureToggleConfig.ActivePatchesCheck),
	}, "\n")

	return datafeaturs
}

// // sendNewCyscanVersionToServerToUpdateDB sends the new cyscan version that was installed to the server so it would take it and update the database with its value
// func sendNewCyscanVersionToServerToUpdateDB(newCyscanVersionNumber string) error {
// 	client := createInsecureHttpClient()
// 	req, cacnel, err := createHTTPRequestWithTimeout("GET", id+"/update_cyscanagent/"+newCyscanVersionNumber, nil)
// 	if err != nil {
// 		return fmt.Errorf("could not create http request with timeout for /update_cyscanagent: %w", err)
// 	}
// 	defer cacnel()
// 	req.Header.Set("Authorization", authenticationToken)

// 	return excuteSendingNewCyscanVersionRequest(req, client)
// }

type ApiUpdateCyscanAgentResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

// sendNewCyscanVersionToServerToUpdateDBV2 sends the new cyscan version that was
// installed to the server so it would take it and update the database with its
// value
func sendNewCyscanVersionToServerToUpdateDBV2(newCyscanVersionNumber string) error {

	// Send the new version number of Cyscan to the server so it can update the DB.
	endPoint := id + "/update_cyscan_agent/" + newCyscanVersionNumber
	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("GET", endPoint, nil, 10)
	if err != nil {
		return fmt.Errorf("failed to execute /update_cyscan_agent API call: %w", err)
	}

	var apiUpdateCyscanAgentResponse ApiUpdateCyscanAgentResponse

	if err := json.Unmarshal(responseBody.Bytes(), &apiUpdateCyscanAgentResponse); err != nil {
		return fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if apiUpdateCyscanAgentResponse.Status {
		log.Info().Msg("Successfully updated cyscan version on the server.")
		return nil
	}

	return fmt.Errorf("failed to update cyscan version on the server: %s", apiUpdateCyscanAgentResponse.Message)
}

// getTaskListAndCompressItIntoZipFile creates a zip file containing the task manager data
// inside of a csv file. It then compresses it into a zip file.
func getTaskListAndCompressItIntoZipFile() error {
	csvSourcePath, err := getAndStoreTaskListInCSVFile()
	if err != nil {
		return fmt.Errorf("failed to store task list in csv file: %w", err)
	}

	csvDestinationName := fmt.Sprintf("tasklist_%s_uploadtasklist.csv", id)
	zipFileName := fmt.Sprintf("tasklist_%s_uploadtasklist.zip", id)

	srcToDstMap := map[string]string{
		csvSourcePath: csvDestinationName,
	}

	if err := createAndWriteToZipFile(zipFileName, srcToDstMap); err != nil {
		return err
	}

	return nil
}

// getAndStoreTaskListInCSVFile gets the task list and stores it in a CSV file.
// It returns the path of the CSV file.
func getAndStoreTaskListInCSVFile() (string, error) {
	CSVPath := filepath.Join(CymetricxPath, "tasks.csv")

	// tasklist: This command is used to display all the running processes on the system.
	// /v: This parameter displays the verbose task information,  it displays more
	// 	   detailed information about each running task. These include "Status","User Name",
	//	   "CPU Time","Window Title"
	// /FO csv: This parameter displays the output in CSV format.
	// |: This is a pipe. It is used to pass the output of the first command to the next command.
	// Set-Content: This cmdlet is used to write the output of the first command to a file.
	// -Path: This parameter specifies the path of the file where the output of the first command is written.
	// -Encoding UTF8: This parameter specifies the encoding of the file where the output of the first command is written.
	ps1Content := fmt.Sprintf(`tasklist /v /FO csv | Set-Content -Path '%s' -Encoding UTF8`, CSVPath)
	if err := execCommandWithoutOutput(powerShellPath, ps1Content); err != nil {
		return "", fmt.Errorf("failed to execute command for tasklist: %w", err)
	}

	//! Double check that this is okay to not be used
	// if err := writeToAndExcutePS1Script(ps1Content, "tasklist-script.ps1"); err != nil {
	// 	return err
	// }

	return CSVPath, nil
}

func writeToAndExcutePS1Script(ps1Content string, ps1FileName string) error {
	if err := os.WriteFile(ps1FileName, []byte(ps1Content), 0744); err != nil {
		return fmt.Errorf("failed to write to %s: %w", ps1FileName, err)
	}
	defer os.Remove(ps1FileName)

	shellCommand := []string{"-NoProfile", "-NonInteractive", "-NoLogo", powerShellPath, "-ExecutionPolicy", "unrestricted", "-File", ps1FileName}
	if err := exec.Command(powerShellPath, shellCommand...).Run(); err != nil {
		return fmt.Errorf("failed to execute command for %s: %w", ps1FileName, err)
	}

	return nil
}

// getAndCompressWindowsInstallerApplicationsIntoZipFile gets all the installed applications
// using Windows Installer, stores them in a CSV file, and compresses them into a zip file.
func getAndCompressWindowsInstallerApplicationsIntoZipFile() error {
	csvSourcePath, err := getAndStoreWindowsInstallerApplicationsInCSVFile()
	if err != nil {
		return err
	}

	csvDestinationName := fmt.Sprintf("appmanager_%s_uploadappmanager.csv", id)
	zipFileName := fmt.Sprintf("appmanager_%s_uploadappmanager.zip", id)
	srcToDstMap := map[string]string{
		csvSourcePath: csvDestinationName,
	}

	if err := createAndWriteToZipFile(zipFileName, srcToDstMap); err != nil {
		return err
	}

	return nil
}

// getAndStoreWindowsInstallerApplicationsInCSVFile gets the installed
// applications only using Windows Installer and stores them in a CSV file.
// It returns the path of the CSV file.
func getAndStoreWindowsInstallerApplicationsInCSVFile() (string, error) {
	CSVPath := filepath.Join(CymetricxPath, "appmanager.csv")

	// Get-CimInstance: This cmdlet gets the CIM instances of a class from a
	//		CIM server.
	// -Class Win32_Product: This parameter specifies the class from which to
	//		get the CIM instances. This Class represents products (Applications)
	//		 as they are installed by Windows Installer.
	// |: This is a pipe. It is used to pass the output of the first command to
	//	 the next command.
	// Select-Object: This cmdlet selects specified properties of an object or
	//	 set of objects. (Selects specific properties of the installed applications)
	// Name, IdentifyingNumber,InstallDate,Vendor,Version,InstallLocation: These
	//	 are the properties of the installed applications that are selected.
	// Export-Csv: This cmdlet is used to export the output of the first command
	//	 to a CSV file.
	// -Path: This parameter specifies the path of the file where the output of
	//	 the first command is written.
	// -NoTypeInformation: This parameter specifies that the CSV file should not
	//	 include the type information.
	// -Encoding UTF8: This parameter specifies the encoding of the file where the
	//	 output of the first command is written.
	// ps1ContentParts := []string{
	// 	"Get-CimInstance -Class Win32_Product",
	// 	"Select-Object Name, IdentifyingNumber,InstallDate,Vendor,Version,InstallLocation",
	// 	fmt.Sprintf("Export-Csv -Path '%s' -NoTypeInformation -Encoding UTF8", CSVPath),
	// }
	// ps1Content := strings.Join(ps1ContentParts, " | ")

	ps1Content := fmt.Sprintf(`Get-CimInstance -Class Win32_Product | Select-Object Name, IdentifyingNumber,InstallDate,Vendor,Version,InstallLocation | Export-Csv -Path '%s' -NoTypeInformation -Encoding UTF8`, CSVPath)
	log.Debug().Msgf("Executing PowerShell script to export Win32_Product data to CSV: %s", CSVPath)
	if err := writeToAndExcutePS1Script(ps1Content, "getappmanager.ps1"); err != nil {
		log.Error().Err(err).Msg("Failed to execute the PowerShell script for App Manager.")
		return "", nil
	}

	return CSVPath, nil
}

type ApiRealServiceResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

// getAndCompresseAndUploadAllInstalledApplications gets all the installed applications
// including the ones installed via Windows Installer and other methods. It compresses
// them into a gzip file and uploads them to the server.
func getAndCompressAndUploadAllInstalledApplications() error {
	log.Info().Msg("Starting the process of compressing and uploading installed applications..")

	// Get the local DNS mappings.
	installedApplicationsPayloadStr, err := getAllInstalledApplicationsV2()
	if err != nil {
		return err
	}

	type InstalledApplications struct {
		InstalledApplications string `json:"installedApplications"`
	}

	installedApplications := InstalledApplications{
		InstalledApplications: installedApplicationsPayloadStr,
	}

	jsonPayload, err := json.Marshal(installedApplications)
	if err != nil {
		return fmt.Errorf("failed to marshal local DNS payload: %w", err)
	}

	filePath, err := createAndCompressPayloadIntoGZipFile(jsonPayload, "installed_applications.gz")
	if err != nil {
		return err
	}

	responseBody, err := createAndExecuteFileUploadRequest("upload_realtime/"+id+"/windows/application_realtime", filePath)
	if err != nil {
		return err
	}

	// Check if the response body contains the string "success".
	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload installed applications to upload real time: %w", err)
	}

	log.Info().Msg("Successfully compressed and uploaded installed applications.")

	return nil
}

func getAndCompressAndUploadAllWindowsServices() error {
	log.Info().Msg("Starting the process of compressing and uploading all Windows services...")

	// Get the local DNS mappings.
	windowsServicesStatusJson, err := getAllWindowsServicesStatus()
	if err != nil {
		return err
	}

	type windowsServices struct {
		Get_GetService string `json:"get_GetService"`
	}

	windowsServicesStruct := windowsServices{
		Get_GetService: windowsServicesStatusJson,
	}

	jsonPayload, err := json.Marshal(windowsServicesStruct)
	if err != nil {
		return fmt.Errorf("failed to marshal Windows services payload: %w", err)
	}

	filePath, err := createAndCompressPayloadIntoGZipFile(jsonPayload, "windows-services.gz")
	if err != nil {
		return err
	}

	responseBody, err := createAndExecuteFileUploadRequest("upload_realtime/"+id+"/windows/services_realtime", filePath)
	if err != nil {
		return err
	}

	// Check if the response body contains the string "success".
	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload Windows services to upload real time: %w", err)
	}

	log.Info().Msg("Successfully compressed and uploaded Windows services.")

	return nil
}

func getAndCompressAndUploadLocalDNS() error {
	log.Info().Msg("Starting the process of compressing and uploading local DNS mappings...")

	// Get the local DNS mappings.
	localDNSPayloadString, err := getLocalDNSV2()
	if err != nil {
		return err
	}

	type LocalDNS struct {
		LocalDNS string `json:"localDNS"`
	}

	localDNS := LocalDNS{
		LocalDNS: localDNSPayloadString,
	}

	jsonPayload, err := json.Marshal(localDNS)
	if err != nil {
		return fmt.Errorf("failed to marshal local DNS payload: %w", err)
	}

	filePath, err := createAndCompressPayloadIntoGZipFile(jsonPayload, "local_dns.gz")
	if err != nil {
		return err
	}

	responseBody, err := createAndExecuteFileUploadRequest("upload_realtime/"+id+"/windows/local_dns", filePath)
	if err != nil {
		return err
	}

	// Check if the response body contains the string "success".
	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload local DNS mappings to upload real time: %w", err)
	}

	log.Info().Msg("Successfully compressed and uploaded local DNS mappings.")

	return nil
}

// getAllInstalledApplications returns a string of all installed applications on the machine
// and the installed applications for the current user.
func getAllInstalledApplicationsV2() (string, error) {

	installedApplications, err := getSingleOrAllInstalledApplicationsV2(nil)
	if err != nil {
		return "", fmt.Errorf("error getting all installed applications: %w", err)
	}

	jsonOutput, err := json.Marshal(installedApplications)
	if err != nil {
		return "", err
	}

	return string(jsonOutput), nil

}

// getSingleOrAllInstalledApplications returns a slice of installed applications on the machine
// and the installed applications for the current user.
// If applicationName is empty, it returns all installed applications.
// If applicationName is not nil, it returns the installed application that matches the DisplayName.
func getSingleOrAllInstalledApplicationsV2(applicationName *string) ([]ApplicationInfo, error) {
	userID, err := getWindowsUserIDV2()
	if err != nil {
		return nil, fmt.Errorf("error getting Windows user ID: %w", err)
	}

	installedApplicationsForUser, err := getInstalledApplicationsForAllAndCurrentUserV2(userID, applicationName)
	if err != nil {
		return nil, fmt.Errorf("error getting installed applications for the current user: %w", err)
	}

	return installedApplicationsForUser, nil
}

// getWindowsUserID returns the user ID of the current user (not the agent ID)
func getWindowsUserIDV2() (string, error) {
	// Obtain a handle to the current process.
	currentProcess := windows.CurrentProcess()

	// Open the access token associated with the current process.
	var token windows.Token
	if err := windows.OpenProcessToken(currentProcess, windows.TOKEN_QUERY, &token); err != nil {
		return "", fmt.Errorf("error opening process token: %w", err)
	}
	defer token.Close()

	// Get the token user.
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("error getting token user: %w", err)
	}

	// Convert SID to string.
	sidString := user.User.Sid.String()

	log.Info().Msgf("User SID: %s", sidString)

	return sidString, nil
}

type ApplicationInfo struct {
	DisplayName    *string `json:"DisplayName"`
	Publisher      *string `json:"Publisher"`
	InstallDate    *string `json:"InstallDate"`
	DisplayVersion *string `json:"DisplayVersion"`
	EstimatedSize  *uint64 `json:"EstimatedSize"` // Changed to uint64 to match GetIntegerValue return type
	InstallSource  *string `json:"InstallSource"`
	PSPath         string  `json:"PSPath"`
}

// Helper functions to simplify getting values with defaults
func getStringValueOr(k registry.Key, name, defaultValue string) string {
	val, _, err := k.GetStringValue(name)
	if err != nil {
		return defaultValue
	}
	return val
}

func getIntegerValueOr(k registry.Key, name string, defaultValue uint64) uint64 {
	val, _, err := k.GetIntegerValue(name)
	if err != nil {
		return defaultValue
	}
	return val
}

func getInstalledApplicationsForAllAndCurrentUserV2(userID string, applicationName *string) ([]ApplicationInfo, error) {
	// Adjust the keys slice to include user-specific paths using the userID (SID)
	keys := []struct {
		baseKey       registry.Key
		baseKeyString string
		subKey        string
	}{
		{registry.LOCAL_MACHINE, "HKEY_LOCAL_MACHINE", `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, "HKEY_LOCAL_MACHINE", `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, "HKEY_CURRENT_USER", `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, "HKEY_CURRENT_USER", `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},

		// New for microsoft store apps
		// {registry.CURRENT_USER, "HKEY_CURRENT_USER", `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`},
		// {registry.LOCAL_MACHINE, "HKEY_LOCAL_MACHINE", `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`},

		// Add user-specific paths using the provided SID
		{registry.USERS, "HKEY_USERS", fmt.Sprintf(`%s\Software\Microsoft\Windows\CurrentVersion\Uninstall`, userID)},
		{registry.USERS, "HKEY_USERS", fmt.Sprintf(`%s\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, userID)},
	}

	var applications []ApplicationInfo
	seen := make(map[string]struct{}) // Create a map to track seen applications

	for _, key := range keys {
		k, err := registry.OpenKey(key.baseKey, key.subKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue // Skip if the key cannot be opened
		}
		defer k.Close()

		subKeyNames, err := k.ReadSubKeyNames(-1)
		if err != nil {
			return nil, fmt.Errorf("error reading subkey names for %s: %w", key.baseKeyString, err)
		}

		for _, subKeyName := range subKeyNames {
			sk, err := registry.OpenKey(k, subKeyName, registry.QUERY_VALUE)
			if err != nil {
				continue // Skip if the subkey cannot be opened
			}
			defer sk.Close()

			displayName, _, err := sk.GetStringValue("DisplayName")
			if err != nil || displayName == "" {
				continue // Skip if DisplayName is missing
			}

			// Construct a unique key for each application
			uniqueKey := fmt.Sprintf("%s|%s|%s|%s|%d",
				displayName,
				getStringValueOr(sk, "Publisher", ""),
				getStringValueOr(sk, "InstallDate", ""),
				getStringValueOr(sk, "DisplayVersion", ""),
				getIntegerValueOr(sk, "EstimatedSize", 0),
			)

			if _, exists := seen[uniqueKey]; !exists {
				app := ApplicationInfo{
					DisplayName:    stringPtr(displayName),
					Publisher:      stringPtr(getStringValueOr(sk, "Publisher", "")),
					InstallDate:    stringPtr(getStringValueOr(sk, "InstallDate", "")),
					DisplayVersion: stringPtr(getStringValueOr(sk, "DisplayVersion", "")),
					EstimatedSize:  uint64Ptr(getIntegerValueOr(sk, "EstimatedSize", 0)),
					InstallSource:  stringPtr(getStringValueOr(sk, "InstallSource", "")),
					PSPath:         fmt.Sprintf("%s\\%s\\%s", key.baseKeyString, key.subKey, subKeyName),
				}

				// If applicationName is not nil, return the application that matches the DisplayName
				if applicationName != nil && displayName == *applicationName {
					return []ApplicationInfo{app}, nil
				}

				applications = append(applications, app)
				seen[uniqueKey] = struct{}{} // Mark this application as seen
			}
		}
	}

	return applications, nil

}

// Helper function to convert string to pointer
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Helper function to convert uint32 to pointer
func uint64Ptr(u uint64) *uint64 {
	if u == 0 {
		return nil
	}
	return &u
}

// getLocalDNS reads the /etc/hosts file and returns its content as a
// string. The content includes the DNS mappings of hostnames to IP addresses.
// e.g. 127.0.0.1 localhost. Also, it includes the DNS mappings of IPv6 addresses
// to hostnames. e.g. ::1 ip6-localhost ip6-loopback.
func getLocalDNS() (string, error) {
	hostsPath := filepath.Join(`C:\`, "Windows", "System32", "drivers", "etc", "hosts")

	// Read the content of the /etc/hosts file
	output, err := os.ReadFile(hostsPath)
	if err != nil {
		return "", fmt.Errorf("error reading /etc/hosts file: %w", err)
	}

	return string(output), nil

}

// getLocalDNS reads the /etc/hosts file and returns its content as a
// string. The content includes the DNS mappings of hostnames to IP addresses.
// e.g. 127.0.0.1 localhost. Also, it includes the DNS mappings of IPv6 addresses
// to hostnames. e.g. ::1 ip6-localhost ip6-loopback.
func getLocalDNSV2() (string, error) {
	hostsPath := filepath.Join(`C:\`, "Windows", "System32", "drivers", "etc", "hosts")

	// Read the content of the /etc/hosts file
	output, err := os.ReadFile(hostsPath)
	if err != nil {
		return "", fmt.Errorf("error reading /etc/hosts file: %w", err)
	}

	type DNS struct {
		IP     string `json:"ip"`
		Domain string `json:"domain"`
		Extra  string `json:"extra"`
	}

	var localDNS []DNS
	localDNS = make([]DNS, 0)

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		var extra string
		ip := fields[0]
		domain := fields[1]

		if len(fields) > 2 {
			extra = strings.Join(fields[2:], " ")
		}

		dns := DNS{
			IP:     ip,
			Domain: domain,
			Extra:  extra,
		}
		localDNS = append(localDNS, dns)
	}

	// Convert the localDNS to JSON
	localDNSJSON, err := json.Marshal(localDNS)
	if err != nil {
		return "", fmt.Errorf("error while marshalling localDNS to JSON: %w", err)
	}

	return string(localDNSJSON), nil

}

// createExcutableFile creates any excutable file, e.g.  ps1, with the given name and content
func createExcutableFile(excutableFileName string, excutableFileContent string) error {
	appendCommand := `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;`
	data := []byte(appendCommand + "\n" + excutableFileContent)

	if err := os.WriteFile(excutableFileName, data, 0744); err != nil {
		return fmt.Errorf("error writing to %s because of: %w", excutableFileName, err)
	}

	return nil
}

func createNonExcutableFile(nonExcutableFileName string, nonExcutableFileContent string) error {
	data := []byte("")
	if strings.Contains(nonExcutableFileName, ".ps1") {
		appendCommand := `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;`
		data = []byte(appendCommand + "\n" + nonExcutableFileContent)
	} else {
		data = []byte(nonExcutableFileContent)
	}

	if err := os.WriteFile(nonExcutableFileName, data, 0644); err != nil {
		return fmt.Errorf("error writing to %s because of: %w", nonExcutableFileName, err)
	}

	return nil
}

// runPS1FileWithOutput executes the ps1 file and returns the output of the excution
func runPS1FileWithOutput(ps1FileName string) ([]byte, error) {
	defer os.Remove(ps1FileName)

	psScript := []string{"-NoProfile", "-NonInteractive", "-NoLogo", powerShellPath, "-ExecutionPolicy", "unrestricted", "-File", fmt.Sprintf(`"%s"`, ps1FileName)}
	output, err := execCommandWithOutputRaw(powerShellPath, psScript...)
	if err != nil {
		return nil, fmt.Errorf("error executing %s because of: %w", ps1FileName, err)
	}

	return output, nil
}

// runPS1FileWithOutputForexeccommand executes the ps1 file and returns the output of the execution, with stderr included in errors
func runPS1FileWithOutputForexeccommand(ps1FileName string) ([]byte, error) {
	defer os.Remove(ps1FileName)

	psScript := []string{"-NoProfile", "-NonInteractive", "-NoLogo", powerShellPath, "-ExecutionPolicy", "unrestricted", "-File", fmt.Sprintf(`"%s"`, ps1FileName)}
	cmd := exec.Command(powerShellPath, psScript...)

	// Capture the command's standard output and standard error
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error stdout %s because of: %w", ps1FileName, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("error stderr %s because of: %w", ps1FileName, err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error Start %s because of: %w", ps1FileName, err)
	}

	// Read the standard output and standard error
	stdoutBytes, err := io.ReadAll(stdout)
	if err != nil {
		return nil, fmt.Errorf("error reading stdout %s because of: %w", ps1FileName, err)
	}
	stderrBytes, err := io.ReadAll(stderr)
	if err != nil {
		return nil, fmt.Errorf("error reading stderr %s because of: %w", ps1FileName, err)
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("error Wait %s because of: %w\nstderr: %s", ps1FileName, err, string(stderrBytes))
	}

	// If there's any stderr content, include it in the error
	if len(stderrBytes) > 0 {
		return stdoutBytes, fmt.Errorf("stderr: %s", string(stderrBytes))
	}

	return stdoutBytes, nil
}

// runPS1FileWithoutOutput executes the ps1 file and returns only error if any
func runPS1FileWithoutOutput(ps1FileName string) error {
	defer os.Remove(ps1FileName)

	psScript := []string{"-NoProfile", "-NonInteractive", "-NoLogo", powerShellPath, "-ExecutionPolicy", "unrestricted", "-File", fmt.Sprintf(`"%s"`, ps1FileName)}

	if err := execCommandWithoutOutput(powerShellPath, psScript...); err != nil {
		return err
	}

	return nil
}

// createAndRunPS1FileWithoutOutput creates the ps1 file with the given content and name and executes it and returns only error if any
func createAndRunPS1FileWithoutOutput(ps1FileName string, ps1Content string) error {
	filePath := filepath.Join(CymetricxPath, ps1FileName)

	if err := createExcutableFile(filePath, ps1Content); err != nil {
		return fmt.Errorf("error creating %s because of: %w", filePath, err)
	}
	defer os.Remove(filePath)

	if err := runPS1FileWithoutOutput(filePath); err != nil {
		return fmt.Errorf("error executing %s because of: %w", filePath, err)
	}

	return nil
}

// createAndRunPS1FileWithOutput creates the ps1 file with the given content and name and executes it and returns the output of the excution
func createAndRunPS1FileWithOutput(ps1FileName string, ps1Content string) ([]byte, error) {
	filePath := filepath.Join(CymetricxPath, ps1FileName)

	if err := createExcutableFile(filePath, ps1Content); err != nil {
		return nil, fmt.Errorf("error creating %s because of: %w", filePath, err)
	}
	defer os.Remove(filePath)

	output, err := runPS1FileWithOutput(filePath)
	if err != nil {
		return nil, fmt.Errorf("error executing %s file because of: %w", filePath, err)
	}

	return output, nil
}

// createAndRunPS1FileWithOutputForExecCommand creates the ps1 file with the given content and name and executes it and returns the output of the excution
func createAndRunPS1FileWithOutputForExecCommand(ps1FileName string, ps1Content string) ([]byte, error) {
	filePath := filepath.Join(CymetricxPath, ps1FileName)

	// if err := createExcutableFile(ps1FileName, ps1Content); err != nil {
	if err := createExcutableFile(filePath, ps1Content); err != nil {
		return nil, fmt.Errorf("error creating %s because of: %w", filePath, err)
	}
	defer os.Remove(filePath)

	// output, err := runPS1FileWithOutputForexeccommand(ps1FileName)
	output, err := runPS1FileWithOutputForexeccommand(filePath)
	if err != nil {
		return nil, fmt.Errorf("error executing %s because of: %w", filePath, err)
	}

	return output, nil
}

func getAndUploadLocalUsersV2() error {
	log.Info().Msg("Starting the process of uploading local users...")

	// jsonPayload, err := getLocalUsersFromWindowsV2()
	jsonPayload, err := getLocalUsersFromWindowsV2_1()
	if err != nil {
		return err
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("local-users.txt", string(jsonPayload))
	if err != nil {
		return fmt.Errorf("error during hash file comparison or update for local-users.txt: %w", err)
	}
	if ifSame {
		return nil
	}

	filePath, err := createAndCompressPayloadIntoGZipFile(jsonPayload, "uploadusersfromwindows.gz")
	if err != nil {
		return err
	}

	responseBody, err := createAndExecuteFileUploadRequest("upload_local_users_from_windows/"+id, filePath)
	if err != nil {
		return err
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload local users: %w", err)
	}

	log.Info().Msg("Successfully uploaded local users.")

	return nil
}

func getLocalDomainUsersWithTheirInformationV2() ([]byte, string, error) {
	domainAdminsJsonPayload, err := processDomainAdmins()
	if err != nil {
		return nil, "", fmt.Errorf("error processing domain admins: %w", err)
	}

	usnFilePath := filepath.Join(CymetricxPath, "Agent Files", "usn.txt")
	csvFilePath := filepath.Join(CymetricxPath, "ad.csv")
	currentUSN, _, err := processUSN(usnFilePath)
	if err != nil {
		// Don't return an error here, just log it and continue
		// becuase we still want to get the domain users even if we can't process
		// the USN
		log.Error().Err(err).Msg("Failed to process USN")
	}

	// Store the new USN:
	if err := createFileWithPermissionsAndWriteToIt(usnFilePath, currentUSN, 0644); err != nil {
		log.Error().Err(err).Msg("Failed to write to usn.txt file")
	}

	if err = getDomainUsers(); err != nil {
		return nil, "", fmt.Errorf("error getting domain users: %w", err)
	}

	return domainAdminsJsonPayload, csvFilePath, nil
}
func uploadWindowsUsersInformationV2() error {
	log.Info().Msg("Starting the process of uploading Windows users' information...")

	if !featureToggleConfig.IdentityUsersCheck {
		return nil
	}

	if !activeDirectoryDomainController {
		// if err := getAndUploadLocalUsersV2(); err != nil {
		// 	return fmt.Errorf("failed to get and upload local users: %w", err)
		// }

		// if err := getAndUploadLocalGroups(); err != nil {
		// 	return fmt.Errorf("failed to upload local groups: %w", err)
		// }

		if err := getAndUploadLocalUsersAndGroups(); err != nil {
			return fmt.Errorf("failed to upload local users and groups: %w", err)
		}

		log.Info().Msg("Successfully uploaded local users' and groups' information.")

		return nil
	}

	if err := uploadDomainUsersInformation(); err != nil {
		return fmt.Errorf("failed to upload domain users information: %w", err)
	}

	if err := getAndUploadDomainGroups(); err != nil {
		return fmt.Errorf("failed to upload domain groups: %w", err)
	}

	log.Info().Msg("Successfully uploaded domain users' and groups' information.")

	return nil
}

func getAndUploadLocalUsersAndGroups() error {
	log.Info().Msg("Starting the process of uploading local users and groups...")

	if err := getAndUploadLocalUsersV2(); err != nil {
		return fmt.Errorf("failed to get and upload local users: %w", err)
	}

	if err := getAndUploadLocalGroups(); err != nil {
		return fmt.Errorf("failed to upload local groups: %w", err)
	}

	return nil
}

func uploadDomainUsersInformation() error {
	log.Info().Msg("Starting the process of uploading Domain users' information...")

	jsonPayloadAdmins, csvFilePath, err := getLocalDomainUsersWithTheirInformationV2()
	if err != nil {
		return fmt.Errorf("failed to get local domain users with their information: %w", err)
	}

	contentCSV, err := os.ReadFile(csvFilePath)
	if err != nil {
		log.Error().Err(err).Msg("Error in reading ad.csv file.")
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("domain-users.txt", string(jsonPayloadAdmins)+string(contentCSV))
	if err != nil {
		return fmt.Errorf("error during hash file comparison or update for domain-users.txt: %w", err)
	}
	if ifSame {
		return nil
	}

	zipFilePath, err := createLocalAdminUsersZipFile(jsonPayloadAdmins, csvFilePath)
	if err != nil {
		return fmt.Errorf("failed to create zip file for local domain users: %w", err)
	}

	responseBody, err := createAndExecuteFileUploadRequest("upload_domain_users_from_windows/"+id, zipFilePath)
	if err != nil {
		return fmt.Errorf("failed to upload windows users information: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload windows users information: %w", err)
	}

	log.Info().Msg("Successfully uploaded Domain users' information.")

	return nil
}

func getAndUploadLocalGroups() error {
	log.Info().Msg("Starting the process of uploading local groups...")

	jsonPayload, err := getLocalGroups()
	if err != nil {
		return fmt.Errorf("failed to get local groups: %w", err)
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("local-groups.txt", string(jsonPayload))
	if err != nil {
		return fmt.Errorf("error during hash file comparison or update for local-groups.txt: %w", err)
	}
	if ifSame {
		return nil
	}

	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", "upload-local-group-users/"+id, jsonPayload, 10)
	if err != nil {
		return fmt.Errorf("failed to upload local groups: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload local groups: %w", err)
	}

	log.Info().Msg("Successfully uploaded local groups.")

	return nil
}

func getLocalGroups() ([]byte, error) {
	if err := prepareAndExecuteDownloadHTTPRequestWithTokenValidityV2("getConfig/"+id+"/local_group", "localGroups.ps1", 10); err != nil {
		return nil, fmt.Errorf("failed to download local groups: %w", err)
	}

	ps1FilePath := filepath.Join(CymetricxPath, "localGroups.ps1")

	output, err := runPS1FileWithOutput(ps1FilePath)
	if err != nil {
		return nil, fmt.Errorf("error running local groups: %w", err)
	}

	output = bytes.TrimSpace(output)

	// Wrap the output string in a map with the key "groups"
	wrappedLocalGroups := map[string]string{
		"groups": string(output),
	}

	// Marshal the map into JSON
	jsonPayload, err := json.Marshal(wrappedLocalGroups)
	if err != nil {
		return nil, fmt.Errorf("error marshalling local groups: %w", err)
	}

	return jsonPayload, nil
}

func getAndUploadDomainGroups() error {
	log.Info().Msg("Starting the process of uploading domain groups...")

	jsonPayload, err := getDomainGroups()
	if err != nil {
		return fmt.Errorf("failed to get domain groups: %w", err)
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("domain-groups.txt", string(jsonPayload))
	if err != nil {
		return fmt.Errorf("error during hash file comparison or update for domain-groups.txt: %w", err)
	}
	if ifSame {
		return nil
	}

	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", "upload-domain-groups/"+id, jsonPayload, 10)
	if err != nil {
		return fmt.Errorf("failed to upload domain groups: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload domain groups: %w", err)
	}

	log.Info().Msg("Successfully uploaded domain groups.")

	return nil
}

func getDomainGroups() ([]byte, error) {
	if err := prepareAndExecuteDownloadHTTPRequestWithTokenValidityV2("getConfig/"+id+"/domain_group", "domainGroups.ps1", 10); err != nil {
		return nil, fmt.Errorf("failed to download domain groups: %w", err)
	}

	ps1FilePath := filepath.Join(CymetricxPath, "domainGroups.ps1")

	output, err := runPS1FileWithOutput(ps1FilePath)
	if err != nil {
		return nil, fmt.Errorf("error running domain groups: %w", err)
	}

	output = bytes.TrimSpace(output)

	// Wrap the output string in a map with the key "groups"
	wrappedDomainGroups := map[string]string{
		"groups": string(output),
	}

	// Marshal the map into JSON
	jsonPayload, err := json.Marshal(wrappedDomainGroups)
	if err != nil {
		return nil, fmt.Errorf("error marshalling domain groups: %w", err)
	}

	return jsonPayload, nil
}

func createLocalAdminUsersZipFile(jsonPayloadAdmins []byte, csvFilePath string) (string, error) {
	jsonPayloadFileName := fmt.Sprintf("%s_DomainUser.json", id)
	jsonPayloadFilePath := filepath.Join(CymetricxPath, jsonPayloadFileName)
	csvFileName := fmt.Sprintf("%s_ad.csv", id)
	zipFileName := fmt.Sprintf("%s_domain-users.zip", id)
	zipFilePath := filepath.Join(CymetricxPath, "Compressed Files", zipFileName)

	srcToDestMap := map[string]string{
		jsonPayloadFilePath: jsonPayloadFileName,
		csvFilePath:         csvFileName,
	}

	if err := createFileWithPermissionsAndWriteToIt(jsonPayloadFilePath, string(jsonPayloadAdmins), 0644); err != nil {
		return "", err
	}

	if err := createAndWriteToZipFile(zipFileName, srcToDestMap); err != nil {
		return "", err
	}

	os.Remove(csvFilePath)

	return zipFilePath, nil
}

// Function to process domain admins and marshal the JSON payload
func processDomainAdmins() ([]byte, error) {
	// Get Domain Admins:
	getDomainAdminsCommand := strings.Join([]string{
		"$groups = 'Domain Admins','Enterprise Admins'",
		"$members =@()",
		"foreach ($group in $groups)",
		"{",
		"$members = Get-ADGroupMember -Identity $group -Recursive | Select-Object  objectGUID, @{Label='Group Name';Expression={$group}}",
		"$members",
		"}",
	}, "\n")

	domainAdminsRaw, err := createAndRunPS1FileWithOutput("command1.ps1", getDomainAdminsCommand)
	if err != nil {
		log.Error().Err(err).Msg("Error executing command1.ps1.")
	}

	var domanAdminsMapList []map[string]string

	domainAdmins := strings.TrimSpace(string(domainAdminsRaw))
	lines := strings.Split(domainAdmins, "\n")
	for i := 2; i < len(lines); i++ {
		domainAdminsMap := make(map[string]string)

		parts := strings.SplitN(lines[i], " ", 2)
		if len(parts) < 2 {
			continue
		}

		objectGUID := strings.TrimSpace(parts[0])
		groupName := strings.TrimSpace(parts[1])

		domainAdminsMap["objectGUID"] = objectGUID
		domainAdminsMap["groupName"] = groupName

		domanAdminsMapList = append(domanAdminsMapList, domainAdminsMap)
	}

	jsonPayload, err := json.Marshal(domanAdminsMapList)
	if err != nil {
		return nil, fmt.Errorf("error marshalling domain admins map list: %w", err)
	}

	return jsonPayload, nil
}

// Function to process USN
func processUSN(usnFilePath string) (string, string, error) {
	// Get the current USN for the domain users to see if they have changed
	getUSNCommand2 := strings.Join([]string{
		`$users = Get-ADUser -Filter * -Properties usnChanged`,
		`Sort-Object usnChanged -Descending`,
		`Select-Object -First 1 usnChanged` + "\n" + `$users.usnChanged`,
	}, " | ")

	currentUSN, err := createAndRunPS1FileWithOutput("getAdUSN.ps1", getUSNCommand2)
	if err != nil {
		return "", "", fmt.Errorf("failed to retreive USN: %w", err)
	}

	// Read the Previous USN from the file
	var previousUSN string
	if fileExists(usnFilePath) {
		previousUSNRaw, err := os.ReadFile(usnFilePath)
		if err != nil {
			return "", "", fmt.Errorf("failed to read usn.txt file: %w", err)
		}

		previousUSN = strings.TrimSpace(string(previousUSNRaw))
	}

	return strings.TrimSpace(string(currentUSN)), previousUSN, nil
}

// getDomainUsers runs a powershell command to get Domain users and stores it
// into ad.csv file in Cymetricx path
func getDomainUsers() error {
	// Get Domain Users:
	commands := strings.Join([]string{
		` Get-ADUser -filter * -Properties msDS-UserPasswordExpiryTimeComputed,* | select *, @{Name='Password expires'`,
		`Expression={[DateTime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')}},@{Name='Password last set'`,
		`Expression={[DateTime]::FromFileTime($_.'pwdLastSet')}},@{Name='Bad Password Time'`,
		`Expression={[DateTime]::FromFileTime($_.'badPasswordTime')}}| export-csv -path "C:\Program Files\CYMETRICX\ad.csv" -Encoding UTF8`,
	}, "\n")

	if err := createAndRunPS1FileWithoutOutput("command12.ps1", commands); err != nil {
		return err
	}

	return nil
}

// func getLocalDomainUsersWithTheirInformationV2() ([]byte, string, error) {

// 	// Get Domain Admins:
// 	commands := strings.Join([]string{
// 		"$groups = 'Domain Admins','Enterprise Admins'",
// 		"$members =@()",
// 		"foreach ($group in $groups)",
// 		"{",
// 		"$members = Get-ADGroupMember -Identity $group -Recursive | Select-Object  objectGUID, @{Label='Group Name';Expression={$group}}",
// 		"$members",
// 		"}",
// 	}, "\n")
// 	if err := createExcutableFile("command1.ps1", commands); err != nil {
// 		log.Error().Err(err).Msg("Error in creating command1.ps1 script file.")
// 	}

// 	domainAdminsRaw, err := runPS1FileWithOutput("command1.ps1")
// 	if err != nil {
// 		log.Error().Err(err).Msg("Error executing command1.ps1.")

// 	}

// 	var domanAdminsMapList []map[string]string

// 	domainAdmins := strings.TrimSpace(string(domainAdminsRaw))
// 	lines := strings.Split(domainAdmins, "\n")
// 	for i := 2; i < len(lines); i++ {
// 		domainAdminsMap := make(map[string]string)

// 		parts := strings.SplitN(lines[i], " ", 2)
// 		objectGUID := strings.TrimSpace(parts[0])
// 		groupName := strings.TrimSpace(parts[1])

// 		domainAdminsMap["objectGUID"] = objectGUID
// 		domainAdminsMap["groupName"] = groupName

// 		domanAdminsMapList = append(domanAdminsMapList, domainAdminsMap)
// 	}

// 	// Get the current USN for the domain users to see if they have changed
// 	getUSNCommand2 := strings.Join([]string{
// 		`$users = Get-ADUser -Filter * -Properties usnChanged`,
// 		`Sort-Object usnChanged -Descending`,
// 		`Select-Object -First 1 usnChanged $users.usnChanged`,
// 	}, " | ")

// 	currentUSN, err := createAndRunPS1FileWithOutput("getAdUSN.ps1", getUSNCommand2)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to retreive USN")
// 	}

// 	csvFilePath := filepath.Join(CymetricxPath, "ad.csv")

// 	jsonPayload, err := json.Marshal(domanAdminsMapList)
// 	if err != nil {
// 		return nil, "", fmt.Errorf("error marshalling domain admins map list: %w", err)
// 	}

// 	// Read the Previous USN from the file
// 	var previousUSN string
// 	usnFilePath := filepath.Join(CymetricxPath, "Agent Files", "usn.txt")
// 	if fileExists(usnFilePath) {
// 		previousUSNRaw, err := os.ReadFile(usnFilePath)
// 		if err != nil {
// 			log.Error().Err(err).Msg("Failed to read usn.txt file")
// 		}

// 		previousUSN = strings.TrimSpace(string(previousUSNRaw))
// 	}

// 	if previousUSN != "" && previousUSN == strings.TrimSpace(string(currentUSN)) {
// 		// Return and don't rescan for the domain users
// 		return jsonPayload, csvFilePath, nil
// 	}

// 	// Store the new USN:
// 	if err := createFileWithPermissionsAndWriteToItRaw(usnFilePath, currentUSN, 0644); err != nil {
// 		log.Error().Err(err).Msg("Failed to write to usn.txt file")
// 	}

// 	// Get Domain Users:
// 	commands = strings.Join([]string{
// 		` Get-ADUser -filter * -Properties msDS-UserPasswordExpiryTimeComputed,* | select *, @{Name='Password expires'`,
// 		`Expression={[DateTime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')}},@{Name='Password last set'`,
// 		`Expression={[DateTime]::FromFileTime($_.'pwdLastSet')}},@{Name='Bad Password Time'`,
// 		`Expression={[DateTime]::FromFileTime($_.'badPasswordTime')}}| export-csv -path "C:\Program Files\CYMETRICX\ad.csv" -Encoding UTF8`,
// 	}, "\n")

// 	if err := createAndRunPS1FileWithoutOutput("command12.ps1", commands); err != nil {
// 		return nil, "", err
// 	}

// 	return jsonPayload, csvFilePath, nil
// }

// createAndWriteToZipFile creates a zip file and writes the given source files
// to it with the given destination names.
func createAndWriteToZipFile(zipFileName string, srcToDstMap map[string]string) error {
	// Create the zip file.
	zipFilePath := filepath.Join(CymetricxPath, "Compressed Files", zipFileName)
	zipFile, err := createFileWithPermissions(zipFilePath, 0644)
	if err != nil {
		return fmt.Errorf("error in creating zip file %s: %w", zipFilePath, err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Write the src files to their respective dst names in the zip file.
	for srcPath, destName := range srcToDstMap {
		srcFile, err := os.Open(srcPath)
		if err != nil {
			return fmt.Errorf("error in opening source file %s: %w", srcPath, err)
		}

		destFile, err := zipWriter.Create(destName)
		if err != nil {
			srcFile.Close()
			return fmt.Errorf("rror in creating entry %s in zip file: %w", destName, err)
		}

		if _, err := io.Copy(destFile, srcFile); err != nil {
			srcFile.Close()
			return fmt.Errorf("error in copying contents to the zip file: %w", err)
		}

		srcFile.Close()

		// Remove the original file after compression.
		if err := os.Remove(srcPath); err != nil {
			return fmt.Errorf("error in removing original file %s: %w", srcPath, err)
		}
	}

	return nil
}

type Win32_UserAccount struct {
	// PSComputerName     string
	Status             string
	AccountType        uint32
	Description        string
	Disabled           bool
	Domain             string
	LocalAccount       bool
	Lockout            bool
	Name               string
	PasswordChangeable bool
	PasswordRequired   bool
	PasswordExpires    bool
	SID                string
	SIDType            uint32
	FullName           string
}

func getLocalUsersFromWindowsV2_1() ([]byte, error) {
	var localUsersInfo []Win32_UserAccount
	query := "SELECT * FROM Win32_UserAccount WHERE LocalAccount = True"
	err := wmi.Query(query, &localUsersInfo)
	if err != nil {
		return nil, fmt.Errorf("error querying Win32_UserAccount: %w", err)
	}

	usersBlocksMap := parseLocalUserAccountsInfoV2_1(localUsersInfo)

	var allUsersInfoMap [](map[string]string)

	for _, userBlock := range usersBlocksMap {
		userName := userBlock["Name"]
		commandArgs := []string{`user`, userName}

		netCommandPath := getNetCommandPath()

		// Get the net user for the current user
		netusers, err := execCommandWithOutputRaw(netCommandPath, commandArgs...)
		if err != nil {
			return nil, fmt.Errorf("error executing net user command: %w", err)
		}

		// Parse the net user output
		netUserBlock := parseNetUserOutput(netusers)

		// Merge the two maps
		for k, v := range netUserBlock {
			userBlock[k] = v
		}

		// Add the user block to a list
		allUsersInfoMap = append(allUsersInfoMap, userBlock)
	}

	return json.Marshal(allUsersInfoMap)
}

// parseLocalUserAccountsInfo parses the entire output into a slice of maps
func parseLocalUserAccountsInfo(output string) []map[string]string {
	var userBlocks []map[string]string
	var currentMap map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		// New user blocks start with the PSComputerName key
		if strings.HasPrefix(line, "PSComputerName") {

			// Add the previous user block if it exists
			// (if we have already parsed one user block)
			if currentMap != nil {
				userBlocks = append(userBlocks, currentMap)
			}
			currentMap = make(map[string]string)
		}

		if currentMap != nil {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				currentMap[key] = value
			}
		}
	}

	// Add the last user block if it exists
	if currentMap != nil {
		userBlocks = append(userBlocks, currentMap)
	}

	return userBlocks
}

// parseLocalUserAccountsInfo parses the entire output into a slice of maps
func parseLocalUserAccountsInfoV2_1(localUsersInfo []Win32_UserAccount) []map[string]string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get hostname while parsing local user accounts info.")
		return nil
	}

	var usersWithHostnameMaps []map[string]string
	for _, u := range localUsersInfo {
		userMap := map[string]string{
			"Status":             u.Status,
			"AccountType":        fmt.Sprint(u.AccountType),
			"Description":        u.Description,
			"Disabled":           strings.Title(strings.Title(fmt.Sprint(u.Disabled))), // Capeitalize the first letter of the string cuz this is the way the server deals with it
			"Domain":             u.Domain,
			"LocalAccount":       strings.Title(fmt.Sprint(u.LocalAccount)),
			"Lockout":            strings.Title(fmt.Sprint(u.Lockout)),
			"Name":               u.Name,
			"PasswordChangeable": strings.Title(fmt.Sprint(u.PasswordChangeable)),
			"PasswordRequired":   strings.Title(fmt.Sprint(u.PasswordRequired)),
			"PasswordExpires":    strings.Title(fmt.Sprint(u.PasswordExpires)),
			"SID":                u.SID,
			"SIDType":            fmt.Sprint(u.SIDType),
			"PSComputerName":     hostname,
			"FullName":           u.FullName,
		}
		usersWithHostnameMaps = append(usersWithHostnameMaps, userMap)

	}

	return usersWithHostnameMaps

}

// Enhanced parsing to handle keys without immediate values more accurately.
func parseNetUserOutput(output []byte) map[string]string {
	// Map to store the output of the net user
	netUserMap := make(map[string]string)

	// List of keys to look for in the output
	netUserKeysList := []string{
		"User name",
		"Full Name",
		"Comment",
		"User's comment",
		"Country/region code",
		"Account active",
		"Account expires",
		"Password last set",
		"Password expires",
		"Password changeable",
		"Password required",
		"User may change password",
		"Workstations allowed",
		"Logon script",
		"User profile",
		"Home directory",
		"Last logon",
		"Logon hours allowed",
		"Local Group Memberships",
		"Global Group memberships",
	}

	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		// Skip the last line of the command line output
		if line == strings.TrimSpace("The command completed successfully.") {
			break
		}

		// Check if the line contains any of the keys and if so, add it to the map
		for _, key := range netUserKeysList {
			if strings.Contains(line, key) {
				value := strings.TrimPrefix(line, key)
				value = strings.TrimSpace(value)
				key = strings.ReplaceAll(key, " ", "_")
				netUserMap[key] = value
				continue
			}
		}
	}

	return netUserMap
}

func fetchAndExecutePatchesScript() error {
	err := prepareAndExecuteDownloadHTTPRequestWithTokenValidityV2("getConfig/"+id+"/patch", "getpatches.ps1", 10)
	if err != nil {
		return fmt.Errorf("error in getting getpatches.ps1: %w", err)
	}

	filePath := filepath.Join(CymetricxPath, "getpatches.ps1")

	if err := runPS1FileWithoutOutput(filePath); err != nil {
		return err
	}

	return nil
}

func processAndSendPatchResults() (err error) {
	defer catchPanic()

	// Use defer to log the error (if any) at the end of the function execution
	defer logError(&err, "Error in compressAndUploadPatchFiles")

	// Checking the patches activity flag
	if !featureToggleConfig.ActivePatchesCheck {
		log.Debug().Msg("Patches activity flag is off. Skipping patch file operations.")
		return nil
	}

	// Retrieving and executing the script that will get patches
	if err := fetchAndExecutePatchesScript(); err != nil {
		return err
	}

	// Reading patches files and storing into JSON
	if err := readPatchesFilesAndStoreItIntoJsonFile(); err != nil {
		return err
	}

	// Compressing the patch files
	filePath, err := compressPatchFiles()
	if err != nil {
		return err
	}

	// Executing the upload request
	responseBody, err := createAndExecuteFileUploadRequest("upload_patches/"+id, filePath)
	if err != nil {
		return err
	}

	// Reading the general response body
	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in compress and upload patch files: %w", err)
	}

	log.Info().Msg("Successfully compressed and uploaded patch files.")

	return nil
}

func readPatchesFilesAndStoreItIntoJsonFile() error {
	jsonPayload, err := readPatchesFileAndTurnItIntoJson()
	if err != nil {
		return err
	}

	jsonFilePath := filepath.Join(CymetricxPath, "patch_conf.json")

	if err := createFileWithPermissionsAndWriteToItRaw(jsonFilePath, jsonPayload, 0644); err != nil {
		return err
	}

	return nil
}

type PatchesFileOutput struct {
	WsusManaged             string `json:"wsusManaged"`
	WsusReachable           string `json:"wsusReachable"`
	WsusServer              string `json:"wsusServer"`
	UpdateSourceCheckStatus string `json:"updateSourceCheckStatus"`
	ResultCode              string `json:"resultCode"`
	AuOptions               string `json:"auOptions"`
	AutoUpdateEnabled       string `json:"autoUpdateEnabled"`
	RebootPending           string `json:"rebootPending"`
}

func readPatchesFileAndTurnItIntoJson() ([]byte, error) {
	patchsconfsFile := filepath.Join(CymetricxPath, "patchsconfs.txt")

	// Read the file:
	dataRaw, err := os.ReadFile(patchsconfsFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't read patchconfs.txt file: %w", err)
	}

	// Clean the data:
	// data := strings.TrimSpace(string(dataRaw))
	data, err := decodeUTF16toUTF8(bytes.TrimSpace(dataRaw))
	if err != nil {
		return nil, fmt.Errorf("couldn't decode data to utf8")
	}

	// Remove BOM if present at the begining of the file
	data = strings.TrimPrefix(data, "\uFEFF")

	// The file consists of 8 values separated by commas:
	// Ex: 0,0,,True,Succeeded,off,0,0
	values := strings.Split(data, ",")

	patchesFileOutput, err := fillPatchesFileOutput(values)
	if err != nil {
		return nil, err
	}

	jsonPayload, err := json.Marshal(patchesFileOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to marshel patchesFileOutput: %w", err)
	}

	return jsonPayload, nil
}

func fillPatchesFileOutput(values []string) (PatchesFileOutput, error) {
	var patchesFileOutput PatchesFileOutput

	if len(values) == 8 {
		patchesFileOutput = PatchesFileOutput{
			WsusManaged:             values[0],
			WsusReachable:           values[1],
			WsusServer:              values[2],
			UpdateSourceCheckStatus: values[3],
			ResultCode:              values[4],
			AuOptions:               values[5],
			AutoUpdateEnabled:       values[6],

			// tihs one might have space after the conversion from utf16 to 8
			RebootPending: strings.TrimSpace(values[7]),
		}
	} else {
		return patchesFileOutput, fmt.Errorf("the number of values in the patchsconfs file which is %d"+
			" does not equal to the number of fields in the struct which is %d ",
			// This returns the number of fields in the struct using reflect package
			len(values), reflect.TypeOf(patchesFileOutput).NumField())
	}

	return patchesFileOutput, nil
}

func compressPatchFiles() (string, error) {
	var srcToDstMap map[string]string
	zipFileName := fmt.Sprintf("patches_%s_uploadfilepatches.zip", id)

	jsonSourcePath := filepath.Join(CymetricxPath, "patch_conf.json")
	jsonDestinationName := fmt.Sprintf("patches_%s_patch_conf.json", id)

	csvSourcePath := filepath.Join(CymetricxPath, "patchs.csv")
	csvDestinationName := fmt.Sprintf("patches_%s_uploadfilepatches.csv", id)

	csvSourceInstalledPath := filepath.Join(CymetricxPath, "installedpatchs.csv")
	csvInstalledDestinationName := fmt.Sprintf("patches_%s_installedpatchs.csv", id)

	defer os.Remove(jsonSourcePath)
	defer os.Remove(csvSourcePath)

	if !fileExists(csvSourcePath) {
		srcToDstMap = map[string]string{
			jsonSourcePath: jsonDestinationName,
		}
	} else {
		srcToDstMap = map[string]string{
			csvSourcePath:          csvDestinationName,
			jsonSourcePath:         jsonDestinationName,
			csvSourceInstalledPath: csvInstalledDestinationName,
		}
	}

	if err := createAndWriteToZipFile(zipFileName, srcToDstMap); err != nil {
		return "", err
	}

	zipFilePath := filepath.Join(CymetricxPath, "Compressed Files", zipFileName)

	return zipFilePath, nil
}

// runCyscanAndUploadItsOutput runs cyscan and uploads its DB to the server
func runCyscanAndUploadItsOutput(jsonFileContent string) (err error) {
	defer catchPanic()

	// Defer a function to check if an error occurred, and log it
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("Error in compressAndUploadCommandsOutput")
		}
	}()

	log.Info().Msg("Starting the process of running cyscan and uploading its output ...")

	// Create the json file that the cyscan will use.
	jsonFilePath := filepath.Join(CymetricxPath, "ip-rules.json")
	if err = createFileWithPermissionsAndWriteToIt(jsonFilePath, jsonFileContent, 0644); err != nil {
		return fmt.Errorf("error in creating file and writing to it: %w", err)
	}

	cyscanPath := filepath.Join(CymetricxPath, "cyscan.exe")
	if err := execCommandWithoutOutput(cmdPath, "/c", cyscanPath); err != nil {
		return fmt.Errorf("error in executing cyscan command: %w", err)
	}

	// Verify the creation of the cyscan.txt file to confirm successful
	// execution of the cyscan command.This file is generated upon the command's
	// completion.
	cyscanTxtPath := filepath.Join(CymetricxPath, "cyscan.txt")
	if !fileExists(cyscanTxtPath) {
		return fmt.Errorf("error in finding cyscan.txt file after executing cyscan command")
	}

	// Collect
	if err := collectCyscanDBDataAndCompressAndUploadItV2(); err != nil {
		return err
	}
	log.Info().Msg("Successfully ran cyscan and uploaded its output.")

	return nil
}

// collectCyscanDBDataAndCompressAndUploadItV2 compresses the cyscan DB after writing it to CSV files and uploads it to the server after zipping it
func collectCyscanDBDataAndCompressAndUploadItV2() error {
	log.Info().Msg("Starting compression and upload process for Cyscan DB.")

	portsIPsPayload, err := getIPsAndPortsFromDBAndReturnJson()
	if err != nil {
		return fmt.Errorf("error while getting IPs and ports from DB and returning JSON: %w", err)
	}

	if string(portsIPsPayload) == "" || string(portsIPsPayload) == "null" || string(portsIPsPayload) == "[]" || portsIPsPayload == nil {
		log.Info().Msg("No data to upload for Cyscan DB.")
		return nil
	}

	filePath, err := createAndCompressPayloadIntoGZipFile(portsIPsPayload, "cyscan_db.gz")
	if err != nil {
		return err
	}

	// sleepForRandomDelayDuration(minimalUploadInterval, maximalUploadInterval)
	// minimalUploadInterval = 120
	// maximalUploadInterval = 600

	responseBody, err := createAndExecuteFileUploadRequest("upload_cyscan/"+id, filePath)
	if err != nil {
		return err
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in compress and upload cyscan DB: %w", err)
	}

	log.Info().Msg("Successfully executed the upload request for Cyscan DB.")

	return nil
}

type CyscanResult struct {
	ScanStartTime string   `json:"scanStartTime"`
	ScanEndTime   string   `json:"scanEndTime"`
	PortIpList    []PortIP `json:"portIpList"`
}

type PortIP struct {
	IP         string `json:"ip"`
	PortNumber *int64 `json:"portNumber"`
	MAC        string `json:"mac"`
	OS         string `json:"os"`
	Hostname   string `json:"hostname"`
	PortStatus string `json:"portStatus"`
	IPStatus   string `json:"ipStatus"`
	ScanTime   string `json:"scanTime"`
	OnTime     string `json:"onTime"`
}

func getIPsAndPortsFromDBAndReturnJson() ([]byte, error) {
	cyscanDBFilePath := filepath.Join(CymetricxPath, "cyscan.db")
	db, err := sql.Open("sqlite3", cyscanDBFilePath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	portIPs, err := fetchIPsAndPorts(db)
	if err != nil {
		return nil, err
	}

	// scanStartTime, scanEndTime, err := fetchStartAndEndTimeScanTime(db)
	// if err != nil {
	// 	return nil, err
	// }

	// cyscanResult := CyscanResult{
	// 	ScanStartTime: scanStartTime,
	// 	ScanEndTime:   scanEndTime,
	// 	PortIpList:    portIPs,
	// }

	// jsonPayload, err := json.Marshal(cyscanResult)
	// if err != nil {
	// 	return nil, err
	// }

	jsonPayload, err := json.Marshal(portIPs)
	if err != nil {
		return nil, err
	}

	return jsonPayload, nil
}

func fetchStartAndEndTimeScanTime(db *sql.DB) (string, string, error) {
	query := `
		SELECT 
			start_time,
			end_time
		FROM
			scan_time
		WHERE
			id = 1;
	`

	row := db.QueryRow(query)

	var scanStartTime, scanEndTime string
	err := row.Scan(&scanStartTime, &scanEndTime)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Warn().Msg("No results found while fetching scan times.")
			return "", "", nil // No results found
		}

		return "", "", fmt.Errorf("erro fetching scan times: %w", err)
	}

	return scanStartTime, scanEndTime, nil

}

func fetchIPsAndPorts(db *sql.DB) ([]PortIP, error) {
	query := `
        SELECT 
            a.ip,
            p.port_number,
            a.mac,
            a.os,
            a.hostname,
            p.status,
			a.status,
            a.scan_time,
            p.on_time
        FROM 
            ip_addresses AS a
        LEFT JOIN 
            ports AS p ON a.id = p.ip_address_id;
    `
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	portIPs, err := extractPortIPsFromRows(rows)
	if err != nil {
		return nil, err
	}

	return portIPs, nil
}

func extractPortIPsFromRows(rows *sql.Rows) ([]PortIP, error) {
	var portIPs []PortIP

	for rows.Next() {
		var ip, mac, os, hostname string
		var port_number sql.NullInt64                               // Changed to handle NULL values
		var portStatus, ipStatus, scan_time, on_time sql.NullString // Changed to handle NULL datetime values

		err := rows.Scan(&ip, &port_number, &mac, &os, &hostname, &portStatus, &ipStatus, &scan_time, &on_time)
		if err != nil {
			return nil, err
		}

		portIP := PortIP{
			IP:         ip,
			MAC:        mac,
			OS:         os,
			Hostname:   hostname,
			PortStatus: portStatus.String,
			IPStatus:   ipStatus.String,
			ScanTime:   scan_time.String,
			OnTime:     on_time.String,
		}

		// Set port number to nil if it is NULL in the database
		// This is so it can be marshalled to null in JSON instead of 0
		// because 0 is the zero value for int64
		if port_number.Valid {
			portIP.PortNumber = &port_number.Int64
		} else {
			portIP.PortNumber = nil // Set to nil to represent null in JSON
		}

		portIPs = append(portIPs, portIP)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return portIPs, nil
}

// decodeData use this function to decode data if exist data enc use base64
func decodeData(dataComing string) (string, error) {
	decodedBytes, err := b64.StdEncoding.DecodeString(dataComing)
	if err != nil {
		return "", fmt.Errorf("error in decoding data: %w", err)
	}

	return string(decodedBytes), nil
}

func runRecheckin(rdb *redis.Client) error {
	log.Info().Msg("Initiating rechecking.")

	recheckInIIS = true

	if !exitCommandCheck {
		return nil
	}

	if !complience {
		return nil
	}

	go processBenchmarkAndAuditResultForProducts()

	ifOldBenchmark, err := processBenchmarkAndAuditResultV2()
	if err != nil {
		log.Error().Err(err).Msg("error in processBenchmarkAndAuditResultV2")
	}

	if ifOldBenchmark {
		var err error
		command, err := getBenchMark()
		if err != nil {
			return fmt.Errorf("error in getbenchmarck: %w", err)
		}

		if _, err := audit_result(command, false); err != nil {
			log.Error().Err(err).Msg("error in audit_result")
			return fmt.Errorf("error in audit_result: %w", err)
		}
	}

	uploadIISGZPath := filepath.Join("Compressed Files", id+"_uploadiis.gz")
	if err := os.Remove(uploadIISGZPath); err != nil {
		log.Error().Err(err).Msg("Error while removing uploadiis.gz file.")
	}

	uploadIISTXTPath := filepath.Join("Hash Files", "uploadiis.txt")
	if err := os.Remove(uploadIISTXTPath); err != nil {
		log.Error().Err(err).Msg("Error while removing uploadiis.txt file.")
	}

	if !isDeletedIIS {
		processIISControlsV2()
	}

	if err := sendAckToRedisServer(rdb, "recheck_completed", nil, nil); err != nil {
		log.Error().Err(err).Msg("Failed to send recheck_completed message to redis server")
	}

	log.Info().Msg("Successfully ran rechecking.")
	return nil
}

func processBenchmarkAndAuditResultForProducts() {
	defer catchPanic()

	productsArray := []string{
		"google_chrome",
		"microsoft_edge",
		"office_2016",
	}

	for _, productName := range productsArray {
		productID, productVersion, err := checkAndGenerateProductID(productName)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to check and generate product ID for product %s.", productName)
			continue
		}

		if err := processBenchmarkAndAuditResultForSingleProduct(productName, productID, productVersion); err != nil {
			log.Error().Err(err).Msgf("Failed to process benchmark and audit result for product %s.", productName)
		}
	}
}

func processIISControlsV2() error {
	log.Info().Msg("Starting to process IIS controls v2.")

	createIISIDAndIISResultsFiles()

	iisData := getIISData()

	jsonPayload, err := processIISDataAndTurnIntoJson(iisData)
	if err != nil {
		log.Error().Err(err).Msg("Error while processing IIS data and turning it into JSON.")
		return fmt.Errorf("failed to process IIS data: %w", err)
	}

	iisResponseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", "upload_iis/"+id, jsonPayload, 10)
	if err != nil {
		log.Error().Err(err).Msg("Error while executing upload request for IIS.")
	}

	if err := readGeneralReponseBody(iisResponseBody); err != nil {
		return fmt.Errorf("failed to upload IIS: %w", err)
	}

	iisIDPath := filepath.Join(CymetricxPath, "iis_id.txt")
	iisIDDataRaw, err := os.ReadFile(iisIDPath)
	if err != nil {
		return fmt.Errorf("failed to read iis_id.txt file: %w", err)
	}

	iisIDData, err := decodeUTF16toUTF8(iisIDDataRaw)
	if err != nil {
		return fmt.Errorf("failed to decode iisIDData to utf8: %w", err)
	}

	// IIS ID is the 2nd line in the file
	iisID := strings.TrimSpace(strings.Split(string(iisIDData), "\n")[1])

	endPoint := "get-asset-controls/" + iisID
	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("GET", endPoint, nil, 10)
	if err != nil {
		return fmt.Errorf("failed to get asset controls for iis: %w", err)
	}

	controlsInputPath := filepath.Join(CymetricxPath, "Controls", "iis-controls-input.json")
	if err := createFileWithPermissionsAndWriteToIt(controlsInputPath, responseBody.String(), 0644); err != nil {
		log.Error().Err(err).Msgf("Failed to write to file: %s", controlsInputPath)
	}

	responseBodyStr := responseBody.String()
	if responseBodyStr == "" {
		log.Info().Msg("No asset controls to recheck for iis")
		return nil
	}

	var responseBodyData interface{}
	err = json.Unmarshal(responseBody.Bytes(), &responseBodyData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if checkIfOldBenchmarkResponse(responseBodyData) {
		log.Info().Msg("No IIS controls found for this client v2")
		if err := runIISUploadProcess(); err != nil {
			// log.Error().Err(err).Msg("error in callUploadIIS")
			return err
		}
		return nil
	}

	log.Info().Msg("IIS controls found for this client v2")

	//!
	// Initialize progress (it may be maintained globally or passed between calls).
	var controlsProgress ControlsProgress
	var combinedJsonDataOutput []byte

	for {
		// Process controls for a 10-second window.
		jsonDataOutput, updatedProgress, err := processControlsData(responseBodyStr, "IIS", &controlsProgress, 10*time.Second)
		if err != nil {
			return fmt.Errorf("failed to process controls data: %w", err)
		}
		controlsProgress = *updatedProgress

		combinedJsonDataOutput = append(combinedJsonDataOutput, jsonDataOutput...)

		if updatedProgress.FinishedControlsCount > 0 {
			// Upload the JSON output that includes any finished control results.
			endPoint := "audit-result/" + iisID
			_, err = prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", endPoint, jsonDataOutput, 10)
			if err != nil {
				return fmt.Errorf("failed to upload audit result: %w", err)
			}
		}

		// If there are no more controls to process, exit the loop.
		if len(controlsProgress.controlsQueue) == 0 && controlsProgress.ActiveProcessCount == 0 {
			break
		}
	}
	//!

	controlsOutputPath := filepath.Join(CymetricxPath, "Controls", "iis-controls-output.json")
	if err := createFileWithPermissionsAndWriteToIt(controlsOutputPath, string(combinedJsonDataOutput), 0644); err != nil {
		log.Error().Err(err).Msgf("Failed to write to file: %s", controlsOutputPath)
	}

	log.Info().Msg("Successfully processed IIS controls v2.")
	return nil
}

func createIISIDAndIISResultsFiles() error {
	script := `
	try {
    # Clear the contents of the iis_results.txt file or create it if it doesn't exist
    echo "" > "C:\Program Files\CYMETRICX\iis_results.txt"
    
    # Initialize a flag to track the installation status
    $newflag=0
    
    # Check if the IIS Web-Server feature is installed
    if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {
        Write-Host "installed,"  # Output to the console that IIS is installed
        Add-Content -Path "C:\Program Files\CYMETRICX\iis_results.txt" -Value "installed,"  # Log the status in iis_results.txt
        $newflag=1  # Set the flag indicating IIS is installed
        
        # Check if the iis_id.txt file already exists
        $CheckFileExistOrNot=[System.IO.File]::Exists("C:\Program Files\CYMETRICX\iis_id.txt")
        if($CheckFileExistOrNot){
            Write-Host "File Already Exists,"  # Notify that the iis_id.txt file already exists
        } else {
            # If the file doesn't exist, create it and add an ID
            echo "id::{" > "C:\Program Files\CYMETRICX\iis_id.txt"
            
            # Generate a random alphanumeric string (30 characters long)
            $GenRandomValue=-join ((65..90) + (97..122) | Get-Random -Count  30 | % {[char]$_}) 
            
            # Create an MD5 hash of the generated string
            $GetkeyHashedClientID=([System.BitConverter]::ToString((New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider).ComputeHash((New-Object -TypeName System.Text.UTF8Encoding).GetBytes($GenRandomValue)))).Replace("-","") 
            
            # Convert the hash to lowercase and save it to the iis_id.txt file
            Add-Content -Path "C:\Program Files\CYMETRICX\iis_id.txt" -Value $GetkeyHashedClientID.ToLower()
            Add-Content -Path "C:\Program Files\CYMETRICX\iis_id.txt" -Value "}"
        }
        
    } else {
        # If IIS is not installed, set the flag to 0 and log the status
        $newflag=0
        Write-Host "notinstalled"  # Output to the console that IIS is not installed
        Add-Content -Path "C:\Program Files\CYMETRICX\iis_results.txt" -Value "notinstalled,"
    }

    # Retrieve the IIS version from the registry
    $GetIISVersion=get-itemproperty HKLM:\SOFTWARE\Microsoft\InetStp\  | select  -ExpandProperty MajorVersion 
    
    # Output the IIS version to the console and log it in iis_results.txt
    Write-Output $GetIISVersion","
    Add-Content -Path "C:\Program Files\CYMETRICX\iis_results.txt" -Value  $GetIISVersion","
	}

	catch {
		# If an error occurs (e.g., IIS is not installed), output and log the error message
		Write-Host "IIS not Installed Or this is a WorkStation "
		Add-Content -Path "C:\Program Files\CYMETRICX\iis_results.txt" -Value "IIS not Installed Or this is a WorkStation"
	}

	`

	if err := createAndRunPS1FileWithoutOutput("createIISID.ps1", script); err != nil {
		return err
	}

	return nil
}

// processBenchmarkAndAuditResultV2 processes the benchmark and audit result and uploads it to the server
// If the returned boolean is true, it means that the benchmark is old and no controls were found.
// That means we need to use the old functions to get the audit result.
func processBenchmarkAndAuditResultV2() (bool, error) {
	if !exitCommandCheck {
		return false, nil
	}

	log.Info().Msg("Starting to process benchmark and audit result v2.")

	exitCommandCheck = false

	endPoint := "get-asset-controls/" + id
	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("GET", endPoint, nil, 10)
	if err != nil {
		exitCommandCheck = true
		return false, fmt.Errorf("failed to get asset controls: %w", err)
	}

	controlsInputPath := filepath.Join(CymetricxPath, "Controls", "system-controls-input.json")
	if err := createFileWithPermissionsAndWriteToIt(controlsInputPath, responseBody.String(), 0644); err != nil {
		log.Error().Err(err).Msgf("Failed to write to file: %s", controlsInputPath)
	}

	responseBodyStr := responseBody.String()
	if responseBodyStr == "" {
		log.Info().Msg("No asset controls to recheck.")
		exitCommandCheck = true
		return false, nil
	}

	var responseBodyData interface{}
	err = json.Unmarshal(responseBody.Bytes(), &responseBodyData)
	if err != nil {
		exitCommandCheck = true
		return false, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if checkIfOldBenchmarkResponse(responseBodyData) {
		log.Info().Msg("No new controls found for this client")
		exitCommandCheck = true

		return true, nil
	}

	// Initialize progress (it may be maintained globally or passed between calls).
	var controlsProgress ControlsProgress
	var combinedJsonDataOutput []byte

	for {
		// Process controls for a 10-second window.
		jsonDataOutput, updatedProgress, err := processControlsData(responseBodyStr, "System Controls", &controlsProgress, 10*time.Second)
		if err != nil {
			exitCommandCheck = true
			return false, fmt.Errorf("failed to process controls data: %w", err)
		}
		controlsProgress = *updatedProgress

		combinedJsonDataOutput = append(combinedJsonDataOutput, jsonDataOutput...)

		if updatedProgress.FinishedControlsCount > 0 {
			// Upload the JSON output that includes any finished control results.
			endPoint := "audit-result/" + id
			_, err = prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", endPoint, jsonDataOutput, 10)
			if err != nil {
				exitCommandCheck = true
				return false, fmt.Errorf("failed to upload audit result: %w", err)
			}
		}

		// If there are no more controls to process, exit the loop.
		if len(controlsProgress.controlsQueue) == 0 && controlsProgress.ActiveProcessCount == 0 {
			break
		}
	}

	controlsOutputPath := filepath.Join(CymetricxPath, "Controls", "system-controls-output.json")
	if err := createFileWithPermissionsAndWriteToIt(controlsOutputPath, string(combinedJsonDataOutput), 0644); err != nil {
		log.Error().Err(err).Msgf("Failed to write to file: %s", controlsOutputPath)
	}

	exitCommandCheck = true

	log.Info().Msg("Successfully processed benchmark and audit result v2.")
	return false, nil
}

func checkAndGenerateProductID(productName string) (string, string, error) {
	productVersion, err := checkIfProductInstalled(productName)
	if err != nil {
		return "", "", err
	}

	productID, err := generateIDAndWriteItToIDTxtFile2(productName)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate product ID: %w", err)
	}

	return productID, productVersion, nil
}

// processBenchmarkAndAuditResultV2 processes the benchmark and audit result and uploads it to the server
// If the returned boolean is true, it means that the benchmark is old and no controls were found.
// That means we need to use the old functions to get the audit result.
func processBenchmarkAndAuditResultForSingleProduct(productName, productID, productVersion string) error {
	log.Info().Msgf("Starting to process benchmark and audit result for product: %s.", productName)

	productDetails := map[string]interface{}{
		"productID":      productID,
		"productName":    productName,
		"productVersion": productVersion,
	}

	jsonPayload, err := json.Marshal(productDetails)
	if err != nil {
		return fmt.Errorf("failed to marshal jsonPayload: %w", err)
	}

	productResponseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", "upload_product/"+id, jsonPayload, 10)
	if err != nil {
		log.Error().Err(err).Msg("Error while executing upload request for IIS.")
	}

	if err := readGeneralReponseBody(productResponseBody); err != nil {
		return fmt.Errorf("failed to upload product: %w", err)
	}

	endPoint := "get-asset-controls/" + productID
	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("GET", endPoint, nil, 10)
	if err != nil {
		exitCommandCheck = true
		return fmt.Errorf("failed to get asset controls for products: %w", err)
	}

	controlsFileName := fmt.Sprintf("%s-controls-input.json", productName)
	controlsInputPath := filepath.Join(CymetricxPath, "Controls", controlsFileName)
	if err := createFileWithPermissionsAndWriteToIt(controlsInputPath, responseBody.String(), 0644); err != nil {
		log.Error().Err(err).Msgf("Failed to write to file: %s", controlsInputPath)
	}

	responseBodyStr := responseBody.String()
	if responseBodyStr == "" {
		log.Info().Msg("No asset controls to recheck for products.")
		exitCommandCheck = true
		return nil
	}

	var responseBodyData interface{}
	err = json.Unmarshal(responseBody.Bytes(), &responseBodyData)
	if err != nil {
		exitCommandCheck = true
		return fmt.Errorf("failed to unmarshal response body for products: %w", err)
	}

	// Initialize progress (it may be maintained globally or passed between calls).
	var controlsProgress ControlsProgress
	var combinedJsonDataOutput []byte

	for {
		// Process controls for a 10-second window.
		jsonDataOutput, updatedProgress, err := processControlsData(responseBodyStr, productName, &controlsProgress, 10*time.Second)
		if err != nil {
			return fmt.Errorf("failed to process controls data: %w", err)
		}
		controlsProgress = *updatedProgress

		combinedJsonDataOutput = append(combinedJsonDataOutput, jsonDataOutput...)

		if updatedProgress.FinishedControlsCount > 0 {
			// Upload the JSON output that includes any finished control results.
			endPoint = "audit-products-result/" + productID
			_, err = prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", endPoint, jsonDataOutput, 10)
			if err != nil {
				return fmt.Errorf("failed to upload audit result: %w", err)
			}
		}

		// If there are no more controls to process, exit the loop.
		if len(controlsProgress.controlsQueue) == 0 && controlsProgress.ActiveProcessCount == 0 {
			break
		}
	}

	controlsFileName = fmt.Sprintf("%s-controls-output.json", productName)
	controlsOutputPath := filepath.Join(CymetricxPath, "Controls", controlsFileName)
	if err := createFileWithPermissionsAndWriteToIt(controlsOutputPath, string(combinedJsonDataOutput), 0644); err != nil {
		log.Error().Err(err).Msgf("Failed to write to file: %s", controlsOutputPath)
	}

	exitCommandCheck = true

	log.Info().Msgf("Successfully processed benchmark and audit result for product: %s.", productName)
	return nil
}

func checkIfProductInstalled(productName string) (string, error) {
	var productCheckers = map[string]func() (string, error){
		"google_chrome":  checkIfChromeInstalledAndGetItsVersion,
		"microsoft_edge": checkIfEdgeInstalledAndGetItsVersion,
		"office_2016":    checkIfOffice2016InstalledAndGetItsVersion,
	}

	log.Info().Msgf("Checking if %s is installed.", productName)

	checker, exists := productCheckers[productName]
	if !exists {
		return "", fmt.Errorf("failed to check if %s is installed", productName)
	}

	productVersion, err := checker()
	if err != nil {
		return "", fmt.Errorf("failed to check if %s is installed: %w", productName, err)
	}

	log.Info().Msgf("%s is installed with version %s.", productName, productVersion)
	return productVersion, nil
}

func checkIfChromeInstalledAndGetItsVersion() (string, error) {
	if err := checkIfChromeInstalled(); err != nil {
		return "", err
	}

	// Get the version of Google Chrome
	version, err := getChromeVersion()
	if err != nil {
		return "", fmt.Errorf("failed to get the version of Google Chrome: %w", err)
	}

	return version, nil
}

func getChromeVersion() (string, error) {
	applicationName := "Google Chrome"
	application, err := getSingleOrAllInstalledApplicationsV2(&applicationName)
	if err != nil {
		return "", fmt.Errorf("failed to get the version of Google Chrome: %w", err)
	}

	version := *application[0].DisplayVersion

	return version, nil
}

func checkIfEdgeInstalledAndGetItsVersion() (string, error) {
	if err := checkIfEdgeInstalled(); err != nil {
		return "", err
	}

	// Get the version of Microsoft Edge
	version, err := getEdgeVersion()
	if err != nil {
		return "", fmt.Errorf("failed to get the version of Microsoft Edge: %w", err)
	}

	return version, nil
}

func getEdgeVersion() (string, error) {
	applicationName := "Microsoft Edge"
	application, err := getSingleOrAllInstalledApplicationsV2(&applicationName)
	if err != nil {
		return "", fmt.Errorf("failed to get the version of Microsoft Edge: %w", err)
	}

	version := *application[0].DisplayVersion

	return version, nil
}

func checkIfOffice2016InstalledAndGetItsVersion() (string, error) {
	if err := checkIfOffice2016Installed(); err != nil {
		return "", err
	}

	return "2016", nil
}

func checkIfChromeInstalled() error {
	paths := []struct {
		registryPath string
		keyItem      string
	}{
		{`HKLM\Software\Clients\Startmenuinternet\Google Chrome\Capabilities`, "ApplicationName"},
		{`HKLM\Software\Microsoft\Windows\Currentversion\Uninstall\Google Chrome`, "DisplayName"},
	}

	for _, path := range paths {
		if controls.KeyOrItemExists(path.registryPath, path.keyItem) {
			return nil
		}
	}

	return fmt.Errorf("google chrome is not installed")
}

func checkIfEdgeInstalled() error {
	ps1Script := `Get-AppxPackage -Name Microsoft.MicrosoftEdge | Select 'Name' | Format-List`
	output, err := execCommandWithOutput(powerShellPath, ps1Script)
	if err != nil {
		return fmt.Errorf("failed to run powershell script to check if Office 2016 is installed: %w", err)
	}

	if strings.Contains(string(output), "Name : Microsoft.MicrosoftEdge") || fileExists(`%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe`) {
		return nil
	}

	return fmt.Errorf("microsoft edge is not installed")
}

func checkIfOffice2016Installed() error {
	ps1Script := `$(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName) + $(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName)`
	output, err := execCommandWithOutput(powerShellPath, ps1Script)
	if err != nil {
		return fmt.Errorf("failed to run powershell script to check if Office 2016 is installed: %w", err)
	}

	// Create a regex to look for Microsoft Office *2016*
	// This is because the DisplayName might contain other versions of Microsoft Office
	// e.g., Microsoft Office 2016, Microsoft Office 2016 Pro, etc.
	regexPattern := `Microsoft Office.*2016.*`
	matched, err := regexp.MatchString(regexPattern, string(output))
	if err != nil {
		return fmt.Errorf("failed to match regex pattern: %w", err)
	}

	if matched {
		return nil
	}

	return fmt.Errorf("office 2016 is not installed")
}

func checkIfOldBenchmarkResponse(data interface{}) bool {
	if dataMap, ok := data.(map[string]interface{}); ok {
		if status, statusOK := dataMap["status"].(bool); statusOK && !status {
			if message, messageOK := dataMap["message"].(string); messageOK && message == "No controls found for this client" {
				return true
			}
		}
	}
	return false
}

func runIISUploadProcess() error {
	log.Info().Msg("Starting call upload IIS...")

	if err := prepareAndExecuteDownloadHTTPRequestWithTokenValidityV2("getConfig/"+id+"/iis", "iis_code.ps1", 10); err != nil {
		return fmt.Errorf("error in getting configurations: %w", err)
	}

	iisFilePath := filepath.Join(CymetricxPath, "iis_code.ps1")
	if err := runPS1FileWithoutOutput(iisFilePath); err != nil {
		log.Error().Err(err).Msg("error when  created And RunPS1FileWithoutOutput iis_code.ps1 ")
	}

	iisData := getIISData()

	if recheckInIIS {
		go uploadIIS(iisData)
		recheckInIIS = false

		log.Info().Msg("Successfully called upload IIS.")
		return nil
	}

	if err := startExcuteUploadIISIfTimeElapsed(iisData); err != nil {
		return fmt.Errorf("error in starting process to upload iis data v1: %w", err)
	}

	log.Info().Msg("Successfully called upload IIS.")

	return nil
}

func startExcuteUploadIISIfTimeElapsed(iisData string) error {
	filePath := filepath.Join(CymetricxPath, "Time Files", "upload_uploadiistime.txt")

	ifElapsed, err := isDurationElapsedSinceLastUpdate(filePath, 5)
	if err != nil {
		return err
	}

	if !ifElapsed {
		return nil
	}

	go uploadIIS(iisData)

	// Update the timer file with the current time
	createNowFileTimer(filePath)

	return nil
}

func getIISData() string {
	iisData := ""

	iisIDPath := filepath.Join(CymetricxPath, "iis_id.txt")
	if !fileExists(iisIDPath) {
		iisData = "" + "\n" + "id:" + ""
	} else {
		iisIDDataRaw, err := os.ReadFile(iisIDPath)
		if err != nil {
			log.Error().Err(err).Msg("error reading file iis_id.txt:")
		}

		iisIDData, err := decodeUTF16toUTF8(iisIDDataRaw)
		if err != nil {
			log.Error().Err(err).Msg("error in decoding iisIDData to utf8")
		}

		iisData = "" + "\n" + "id:" + string(iisIDData)
	}

	iisResultPath := filepath.Join(CymetricxPath, "iis_results.txt")
	if !fileExists(iisResultPath) {
		strings.Join([]string{iisData, "result:"}, "\n")
	} else {
		iisResultDataRaw, err := os.ReadFile(iisResultPath)
		if err != nil {
			log.Error().Err(err).Msg("error reading file iis_results.txt")

		}

		iisResultData, err := decodeUTF16toUTF8(iisResultDataRaw)
		if err != nil {
			log.Error().Err(err).Msg("error in decoding iisResultData to utf8")
		}
		iisData = iisData + "\nresult:" + string(iisResultData)
		strings.Join([]string{
			iisData,
			"result:" + string(iisResultData),
		}, "\n")
	}
	return iisData
}

func getBenchMark() (string, error) {
	log.Info().Msg("Initiating benchmark.")

	// fmt.Println("COMPLIANCE:", complience)

	err := prepareAndExecuteDownloadHTTPRequestWithTokenValidityV2("getConfig/"+id+"/benchmark", "benchmark.txt", 10)
	if err != nil {
		return "", fmt.Errorf("error in getting configurations: %w", err)
	}

	filePath := filepath.Join(CymetricxPath, "benchmark.txt")
	jsonDataRaw, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error in reading file benchmark.txt: %w", err)
	}
	jsonData := string(jsonDataRaw)

	defer os.Remove(filePath)

	log.Info().Msg("Successfully initiated benchmark.")
	return string(jsonData), nil
}

func uploadIIS(iisData string) {
	defer catchPanic()

	log.Info().Msg("Starting upload IIS...")

	jsonPayload, err := processIISDataAndTurnIntoJson(iisData)
	if err != nil {
		log.Error().Err(err).Msg("Error while processing IIS data and turning it into JSON.")
		return
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("uploadiis.txt", iisData)
	if err != nil {
		log.Error().Err(err).Msg("Error while checking if hash file is same or updated.")
		return
	}
	if ifSame {
		return
	}

	// sleepForRandomDelayDuration(minimalRecheckInterval, maximalRecheckInterval)

	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", "upload_iis/"+id, jsonPayload, 10)
	if err != nil {
		log.Error().Err(err).Msg("Error while executing upload request for IIS.")
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		log.Error().Err(err).Msg("Failed to upload IIS.")
	}

	log.Info().Msg("Successfully uploaded IIS.")

}

type IISData struct {
	ID          string   `json:"iisID"`
	IsInstalled string   `json:"isInsatlled"`
	IISVersion  string   `json:"iisVersion"`
	ControlsIIS []string `json:"iisContols,omitempty"`
}

func processIISDataAndTurnIntoJson(iisData string) ([]byte, error) {
	jsonData := IISData{
		ID:          "N/A",
		IsInstalled: "N/A",
		IISVersion:  "N/A",
		ControlsIIS: []string{}, // Empty value
	}

	if strings.Contains(iisData, "id::{") {
		idIndex := strings.Index(iisData, "id::{")
		idEndIndex := strings.Index(iisData[idIndex:], "}")
		jsonData.ID = strings.TrimSpace(iisData[idIndex+6 : idIndex+idEndIndex])

		if strings.Contains(iisData, "installed,") && !strings.Contains(iisData, "IIS not Installed Or this is a WorkStation") && !strings.Contains(iisData, "notinstalled") {
			jsonData.IsInstalled = "installed"
		} else if strings.Contains(iisData, "IIS not Installed Or this is a WorkStation") {
			jsonData.IsInstalled = "IIS not Installed Or this is a WorkStation"
		} else if strings.Contains(iisData, "notinstalled") {
			jsonData.IsInstalled = "notinstalled"
		}

		iisVersionIndex := strings.Index(iisData, ",")
		controlsIISIndex := strings.LastIndex(iisData, ",")

		jsonData.IISVersion = strings.TrimSpace(iisData[iisVersionIndex+1 : controlsIISIndex])

		// It has \r\n because it was read from a file that was utf16
		controlsIISData := strings.TrimSpace(iisData[controlsIISIndex+1:])
		if controlsIISData != "" {
			jsonData.ControlsIIS = strings.Split(strings.TrimSpace(iisData[controlsIISIndex+1:]), "\r\n")
		}
	} else {
		if strings.Contains(iisData, "IIS not Installed Or this is a WorkStation") {
			jsonData.IsInstalled = "IIS not Installed Or this is a WorkStation"
		} else if strings.Contains(iisData, "notinstalled") {
			jsonData.IsInstalled = "notinstalled"
		}
	}

	jsonPayload, err := json.Marshal(jsonData)
	if err != nil {
		return nil, err
	}

	return jsonPayload, nil
}

func emptyDirectory(dirName string) error {
	dirPath := filepath.Join(CymetricxPath, dirName)
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("error in reading dir %s: %w", dirPath, err)
	}

	for _, file := range files {
		filePath := filepath.Join(dirPath, file.Name())
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("error in removing file %s: %w", filePath, err)
		}
	}

	return nil

}

func rescanAndCompressAndUploadEverthing(rdb *redis.Client) error {
	log.Info().Msg("Initiating rescan and compress and upload everything.")

	if rescanStatus {
		log.Debug().Msg("Rescan is already on. Skipping rescan and compress and upload everything.")
		return nil
	}

	rescanStatus = true

	if err := emptyDirectory("Hash Files"); err != nil {
		rescanStatus = false
		return fmt.Errorf("error in emptying Hash Files: %w", err)
	}

	if err := collectAndUploadSystemDetails_start_windows(false, "system-details-hash.txt", "start_windows"); err != nil {
		// don't return and leave it to time duration to try again
		log.Error().Err(err).Msg("Error in compressing and uploading system data to server.")
	}

	if err := uploadWindowsUsersInformationV2(); err != nil {
		log.Error().Err(err).Msg("Error in uploading windows users information.")
	}

	if activeDirectoryDomainController {
		if err := compressAndUploadGPOsToServerV2(); err != nil {
			log.Error().Err(err).Msg("Error in compressing and uploading GPOs to server.")
		}
		if err := compressAndUploadActiveDirectoryObjectsV2(); err != nil {
			log.Error().Err(err).Msg("Error in compressing and uploading active directory objects to server.")
		}
	}

	if err := uploadPasswordPolicyResult(); err != nil {
		log.Error().Err(err).Msg("Error in uploading password policy result.")
	}

	if err := uploadAllSystemDataAndDetailsAsBulkCSV(); err != nil {
		log.Error().Err(err).Msg("Error in uploading group of data csv.")
	}

	if err := uploadAllSystemDataAndDetailsAsBulk(); err != nil {
		log.Error().Err(err).Msg("Error in uploading group of data.")
	}

	if err := compressAndUploadWindowsCertificatesV2(); err != nil {
		log.Error().Err(err).Msg("Error in compressing and uploading windows certificates.")
	}

	go processAndSendPatchResults()

	if err := uploadProcessFromDBV2(); err != nil {
		log.Error().Err(err).Msg("Error in uploading process from DB.")
	}

	if err := uploadServicesFromDB(); err != nil {
		log.Error().Err(err).Msg("Error in uploading services from DB.")
	}

	rescanStatus = false

	if err := sendAckToRedisServer(rdb, "rescan_completed", nil, nil); err != nil {
		log.Error().Err(err).Msg("Failed to send rescan_completed message to redis server")
	}

	log.Info().Msg("Successfully initiated rescan and compress and upload everything.")
	return nil
}

// createGPOsZipFile gets the GPOs, write them to an xml file and then compresses it into a zip file
func createGPOsZipFile() (string, error) {
	script := `Get-GPOReport -All -ReportType Xml 'C:\Program Files\CYMETRICX\gpos.xml'`
	if err := createAndRunPS1FileWithoutOutput("gposcommand.ps1", script); err != nil {
		return "", fmt.Errorf("error in creating gposcommand.ps1: %w", err)
	}

	zipFolderName := fmt.Sprintf("gpos_%s_uploadgpos.zip", id)
	xmlSourcePath := filepath.Join(CymetricxPath, "gpos.xml")
	xmlDestinationName := fmt.Sprintf("gpos_%s_uploadgpos.xml" + id + "_" + "uploadgpos.xml")

	srcToDstMap := map[string]string{
		xmlSourcePath: xmlDestinationName,
	}

	zipFolderPath := filepath.Join(CymetricxPath, "Compressed Files", zipFolderName)
	if err := createAndWriteToZipFile(zipFolderName, srcToDstMap); err != nil {
		return "", fmt.Errorf("error in creating and writing zip: %w", err)
	}

	return zipFolderPath, nil
}

func compressAndUploadGPOsToServerV2() error {
	if !getGPOReport {
		return nil
	}

	log.Info().Msg("Starting compression and upload process for GPOs...")

	filePath, err := createGPOsZipFile()
	if err != nil {
		return fmt.Errorf("error in getting GPOs: %w", err)
	}

	// sleepForRandomDelayDuration(minimalUploadInterval, maximalUploadInterval)

	responseBody, err := createAndExecuteFileUploadRequest("gpos/"+id, filePath)
	if err != nil {
		return fmt.Errorf("error in createAndExecuteUploadRequest: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in compress and upload GPOs: %w", err)
	}

	log.Info().Msg("Successfully compressed and uploaded GPOs to server.")

	return nil
}

func compressAndUploadActiveDirectoryObjectsV2() error {
	if !assetDiscoveryUsingADComputer {
		return nil
	}

	filePath, err := createZipFileForObjectsFromActiveDirectoryV2()
	if err != nil {
		return fmt.Errorf("error in getcompcs: %w", err)
	}

	// sleepForRandomDelayDuration(minimalUploadInterval, maximalUploadInterval)

	responseBody, err := createAndExecuteFileUploadRequest("compcs/"+id, filePath)
	if err != nil {
		return fmt.Errorf("error in createAndExecuteUploadRequest: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("could not compress and upload active directory objects")
	}

	return nil
}

func createZipFileForObjectsFromActiveDirectoryV2() (string, error) {
	script := `Get-ADComputer -Filter * -properties * | export-csv -path 'C:\Program Files\CYMETRICX\compcs.csv' -Encoding UTF8`

	if err := createAndRunPS1FileWithoutOutput("getcompcs.ps1", script); err != nil {
		return "", fmt.Errorf("error in creating getcompcs.ps1: %w", err)
	}

	zipFileName := fmt.Sprintf("compcs_%s_uploadcompcs.zip", id)
	csvSourcePath := filepath.Join(CymetricxPath, "compcs.csv")
	csvDestinationName := fmt.Sprintf("compcs_%s_uploadcompcs.csv", id)
	srcToDstMap := map[string]string{
		csvSourcePath: csvDestinationName,
	}

	if err := createAndWriteToZipFile(zipFileName, srcToDstMap); err != nil {
		return "", fmt.Errorf("error in creating and writing zip: %w", err)
	}

	zipFilePath := filepath.Join(CymetricxPath, "Compressed Files", zipFileName)
	return zipFilePath, nil
}

func uploadPasswordPolicyResult() error {
	log.Info().Msg("Starting upload password policy result...")

	dataFromLGPO, _, err := getLGPO()
	if err != nil {
		return fmt.Errorf("error in getLGPO: %w", err)
	}

	jsonPayload, err := processPasswordPolicyResultToJson(dataFromLGPO)
	if err != nil {
		return err
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("upload_getpasswordpolicyresult.txt", string(jsonPayload))
	if err != nil {
		log.Error().Err(err).Msg("Error while checking if hash file is same or updated.")
		return err
	}
	if ifSame {
		return nil
	}

	// sleepForRandomDelayDuration(minimalUploadInterval, maximalUploadInterval)

	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", "upload_windows_password_policy/"+id, jsonPayload, 10)
	if err != nil {
		return fmt.Errorf("error in upload_getpasswordpolicyresult: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in uploading password policy result: %w", err)
	}

	log.Info().Msg("Successfully uploaded password policy result.")

	return nil
}

type PasswordPolicy struct {
	MinimumPasswordAge           string `json:"minimumPasswordAge"`
	MaximumPasswordAge           string `json:"maximumPasswordAge"`
	MinimumPasswordLength        string `json:"minimumPasswordLength"`
	PasswordComplexity           string `json:"passwordComplexity"`
	LockoutBadCount              string `json:"lockoutBadCount"`
	ResetLockoutCount            string `json:"resetLockoutCount"`
	LockoutDuration              string `json:"lockoutDuration"`
	RequireLogonToChangePassword string `json:"requireLogonToChangePassword"`
}

func processPasswordPolicyResultToJson(dataFromLGPO string) ([]byte, error) {
	passwordPolicy := PasswordPolicy{
		MinimumPasswordAge:           "none",
		MaximumPasswordAge:           "none",
		MinimumPasswordLength:        "none",
		PasswordComplexity:           "none",
		LockoutBadCount:              "none",
		ResetLockoutCount:            "none",
		LockoutDuration:              "none",
		RequireLogonToChangePassword: "none",
	}

	lines := strings.Split(dataFromLGPO, "\n")

	foundMaxPasswordAge := false

	for _, line := range lines {
		parts := strings.Split(line, "=")
		if len(parts) < 2 { // Check if the split resulted in at least two parts
			continue // Skip processing this line if not
		}

		// key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if strings.Contains(line, "MinimumPasswordAge") {
			passwordPolicy.MinimumPasswordAge = value
		}
		if strings.Contains(line, "MaximumPasswordAge") && !foundMaxPasswordAge {
			passwordPolicy.MaximumPasswordAge = value
			foundMaxPasswordAge = true
		}
		if strings.Contains(line, "MinimumPasswordLength") {
			passwordPolicy.MinimumPasswordLength = value
		}
		if strings.Contains(line, "PasswordComplexity") {
			passwordPolicy.PasswordComplexity = value
		}
		if strings.Contains(line, "LockoutBadCount") {
			passwordPolicy.LockoutBadCount = value
		}
		if strings.Contains(line, "ResetLockoutCount") {
			passwordPolicy.ResetLockoutCount = value
		}
		if strings.Contains(line, "LockoutDuration") {
			passwordPolicy.LockoutDuration = value
		}
		if strings.Contains(line, "RequireLogonToChangePassword") {
			passwordPolicy.RequireLogonToChangePassword = value
		}
	}

	jsonPayload, err := json.Marshal(passwordPolicy)
	if err != nil {
		return nil, fmt.Errorf("error in marshalling password policy: %w", err)
	}

	return jsonPayload, nil

}

// ! Explain this more in details
func getLGPO() (string, string, error) {

	files, err := os.ReadDir(CymetricxPath)
	if err != nil {
		// ReadDir returns a slice of DirEntry sorted by filename, if an error occurs then it would still return a slice of files it was able to read
		// and the error for the file it couldn't read and stopped at. So we would still read the rest of files unless the length of the slice is 0
		log.Error().Err(err).Msgf("Error in reading directory %s.", CymetricxPath)
	}

	if len(files) == 0 {
		return "", "", fmt.Errorf("couldn't read any files in directory: %s", CymetricxPath)
	}

	for _, file := range files {
		//! What is the "{" and "}" for?
		if strings.Contains(file.Name(), "{") && strings.Contains(file.Name(), "}") {
			fileName := file.Name()
			err := os.RemoveAll(filepath.Join(CymetricxPath, fileName))
			if err != nil {
				return "", "", fmt.Errorf("error in removing file/directory %s: %w", fileName, err)
			}
		}
	}

	//! Are you sure you want to get the current working directory?
	// path, err := os.Getwd()
	// if err != nil {
	// 	return "", "", fmt.Errorf("error in getting current working directory: %w", err)
	// }

	batScriptContent := fmt.Sprintf(`"%s\LGPO.exe" /b "%s"`, CymetricxPath, CymetricxPath)
	if err := createAndRunBatScriptWithoutOutput("lgpo.bat", batScriptContent); err != nil {
		return "", "", err
	}

	files, err = os.ReadDir(CymetricxPath)
	if err != nil {
		log.Error().Err(err).Msgf("Error in reading directory %s.", CymetricxPath)
	}

	if len(files) == 0 {
		return "", "", fmt.Errorf("couldn't read any files in directory: %s", CymetricxPath)
	}

	var pathLGPOOutput = ""
	var pathLGPOOutputFromAudit = ""
	for _, file := range files {
		//! What is the "{" and "}" for?
		if strings.Contains(string(file.Name()), "{") && strings.Contains(string(file.Name()), "}") {
			fileName := file.Name()
			//! Why are you changing a global variable here and then using it afterwards
			pathLGPOOutput = fmt.Sprintf(`%s\%s\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf`, CymetricxPath, fileName)
			pathLGPOOutputFromAudit = fmt.Sprintf(`%s\%s\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv`, CymetricxPath, fileName)
		}
	}

	dat, err := os.ReadFile(pathLGPOOutput)
	if err != nil {
		return "", "", fmt.Errorf("error in reading file %s: %w", pathLGPOOutput, err)
	}
	dataFromLGPO, err := decodeUTF16toUTF8(dat)
	if err != nil {
		return "", "", fmt.Errorf("error in decoding utf16: %w", err)
	}

	dataFromAudits, err := os.ReadFile(pathLGPOOutputFromAudit)
	if err != nil {
		return "", "", fmt.Errorf("error in reading file %s: %w", pathLGPOOutputFromAudit, err)
	}

	getAuditFromCSV := string(dataFromAudits)

	//! Why are you sleeping here?
	time.Sleep(5 * time.Second)

	files, err = os.ReadDir(CymetricxPath)
	if err != nil {
		log.Error().Err(err).Msgf("Error in reading directory %s.", CymetricxPath)
	}

	if len(files) == 0 {
		return "", "", fmt.Errorf("couldn't read any files in directory: %s", CymetricxPath)
	}

	for _, file := range files {
		//! What is the "{" and "}" for?
		if strings.Contains(string(file.Name()), "{") && strings.Contains(string(file.Name()), "}") {
			fileName := file.Name()
			os.RemoveAll(filepath.Join(CymetricxPath, fileName))
		}
	}
	return dataFromLGPO, getAuditFromCSV, nil
}

func uploadProcessFromDBV2() error {
	if !featureToggleConfig.SystemProcessesAndServicesCheck {
		return nil
	}

	log.Info().Msg("Starting to upload processes from DB...")

	processData, err := getDataProcessFromDBV2()
	if err != nil {
		return fmt.Errorf("error in getting data process from db: %w", err)
	}

	if len(processData) == 0 || string(processData) == "null" || string(processData) == "[]" || string(processData) == "" || string(processData) == " " {
		if err := addAllSystemRunningProcessesToDBV2(); err != nil {
			return fmt.Errorf("error in adding all system running processes: %w", err)
		}

		processData, err = getDataProcessFromDBV2()
		if err != nil {
			return fmt.Errorf("error in getting data process from db: %w", err)
		}
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("upload_process.txt", string(processData))
	if err != nil {
		return err
	}
	if ifSame {
		return nil
	}

	filePath, err := createAndCompressPayloadIntoGZipFile(processData, "windowsinsertprocess.gz")
	if err != nil {
		return fmt.Errorf("error in creating and compressing payload into gzip file: %w", err)
	}

	// sleepForRandomDelayDuration(minimalUploadInterval, maximalUploadInterval)

	log.Info().Msg("FilePath for the process DB. About to start uploading...: " + filePath)

	responseBody, err := createAndExecuteFileUploadRequest("windows_insert_process/"+id, filePath)
	if err != nil {
		return fmt.Errorf("error in windowsinsertprocess: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("couldn't compress and upload processes from DB: %w", err)
	}

	return nil
}

type ProcessDBRow struct {
	Path           string `json:"path"`
	ProcessId      *int64 `json:"processId"`
	CreationDate   string `json:"creationDate"`
	Name           string `json:"name"`
	UserName       string `json:"userName"`
	CommandLine    string `json:"commandLine"`
	ExecutablePath string `json:"executablePath"`
}

func processRowsAndCreateJsonPayload(rows *sql.Rows) ([]byte, error) {
	var processDBRowList []ProcessDBRow

	// var id int
	var (
		Path           string
		CreationDate   string
		Name           string
		UserName       string
		CommandLine    string
		ExecutablePath string
	)
	var ProcessId sql.NullInt64 // Changed to handle NULL values

	for rows.Next() {
		// if err := rows.Scan(&id, &Path, &ProcessId, &CreationDate, &Name, &UserName, &CommandLine, &InstallDate, &ExecutablePath, &Description); err != nil {
		if err := rows.Scan(&Path, &ProcessId, &CreationDate, &Name, &UserName, &CommandLine, &ExecutablePath); err != nil {
			log.Error().Err(err).Msgf("An error occurred while scanning a row in process database."+
				"Values:, Path=%v, ProcessId=%v, CreationDate=%v, Name=%v, UserName=%v, CommandLine=%v, ExecutablePath=%v",
				Path, ProcessId, CreationDate, Name, UserName, CommandLine, ExecutablePath)
			continue
		}

		processDbRow := ProcessDBRow{
			Path:           Path,
			CreationDate:   CreationDate,
			Name:           Name,
			UserName:       UserName,
			CommandLine:    CommandLine,
			ExecutablePath: ExecutablePath,
		}

		if ProcessId.Valid {
			processDbRow.ProcessId = &ProcessId.Int64
		} else {
			processDbRow.ProcessId = nil // Set to nil to represent null in JSON
		}

		processDBRowList = append(processDBRowList, processDbRow)
	}

	jsonPayload, err := json.Marshal(processDBRowList)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the list of process db rows: %w", err)
	}

	return jsonPayload, nil
}

func getDataProcessFromDBV2() ([]byte, error) {
	db, err := ldb.InitDB()
	if err != nil {
		return nil, fmt.Errorf("couldn't connect to sqlite database because of: %w ", err)
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT DISTINCT
			Path, ProcessId, CreationDate, Name, UserName, CommandLine, ExecutablePath
		FROM
			processes
		WHERE ProcessID <> ''
	`)
	if err != nil {
		return nil, fmt.Errorf("error while querying processes table from process_service_w.db: %w", err)
	}
	defer rows.Close()

	jsonPayload, err := processRowsAndCreateJsonPayload(rows)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec("DELETE FROM processes")
	if err != nil {
		return nil, fmt.Errorf("error while deleting from processes table from process_service_w.db: %w", err)
	}

	_, err = db.Exec("VACUUM")
	if err != nil {
		return nil, fmt.Errorf("error while vacuuming processes table from process_service_w.db: %w", err)
	}

	return jsonPayload, nil
}

func uploadServicesFromDB() error {
	if !featureToggleConfig.SystemProcessesAndServicesCheck {
		return nil
	}

	jsonPayload, err := getDataListeningServicesFromDB()
	if err != nil {
		return fmt.Errorf("error in getting data from database: %w", err)
	}

	if jsonPayload == nil || string(jsonPayload) == "null" || string(jsonPayload) == "[]" {
		if err := addListeningServicesToDBV2(); err != nil {
			return fmt.Errorf("error in adding listining services to DB for the 2nd time: %w", err)
		}

		jsonPayload, err = getDataListeningServicesFromDB()
		if err != nil {
			return fmt.Errorf("error in getting data from database: %w", err)
		}
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("upload_services.txt", string(jsonPayload))
	if err != nil {
		log.Error().Err(err).Msg("Error while checking if hash file is same or updated.")
		return err
	}
	if ifSame {
		return nil
	}

	filePath, err := createAndCompressPayloadIntoGZipFile(jsonPayload, "windowsinsertservices.gz")
	if err != nil {
		return fmt.Errorf("error in creating and compressing payload into gzip file: %w", err)
	}

	// sleepForRandomDelayDuration(minimalUploadInterval, maximalUploadInterval)

	responseBody, err := createAndExecuteFileUploadRequest("windows_insert_services/"+id, filePath)
	if err != nil {
		return fmt.Errorf("error in windowsinsertservices: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("couldn't compress and upload services from DB: %w", err)
	}

	log.Info().Msg("Successfully uploaded services from DB.")

	return nil
}

type ServiceDBRow struct {
	PortNumber  *int64 `json:"portNumber"`
	Protocol    string `json:"protocol"`
	ServiceName string `json:"serviceName"`
	PID         *int64 `json:"PID"`
	Address     string `json:"address"`
}

func getDataListeningServicesFromDB() ([]byte, error) {
	db, err := ldb.InitDB()
	if err != nil {
		return nil, fmt.Errorf("couldn't connect to sqlite database because of: %w", err)
	}
	defer db.Close()
	rows, err := db.Query(`
		SELECT DISTINCT 
			Port_Number, Protocol, Service_Name, PID, Address
		FROM 
			listening_services
		WHERE PID <> ''
	`)
	if err != nil {
		return nil, fmt.Errorf("error in getting data from database: %w", err)
	}

	serviceDBRowList, err := processServiceDBRows(rows)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec("DELETE FROM listening_services")
	if err != nil {
		return nil, fmt.Errorf("error in deleting data from database: %w", err)
	}

	_, err = db.Exec("VACUUM")
	//db.Close()
	if err != nil {
		return nil, fmt.Errorf("error in vacuuming the database inside of getDataServiceFromDB function: %w", err)
	}

	jsonPayload, err := json.Marshal(serviceDBRowList)
	if err != nil {
		return nil, fmt.Errorf("error in marshalling the list of service db rows: %w", err)
	}

	return jsonPayload, nil
}

func processServiceDBRows(rows *sql.Rows) ([]ServiceDBRow, error) {
	var serviceDBRowList []ServiceDBRow

	for rows.Next() {
		// var Id int
		var Protocol, Service_Name, Address string
		var Port_Number, PID sql.NullInt64 // Changed to handle NULL values

		// err := rows.Scan(&Id, &Port_Number, &Protocol, &Service_Name, &PID, &Address)
		err := rows.Scan(&Port_Number, &Protocol, &Service_Name, &PID, &Address)

		if err != nil {
			return nil, fmt.Errorf("error in scanning rows: %w", err)
		}

		serviceDBRow := ServiceDBRow{
			Protocol:    Protocol,
			ServiceName: Service_Name,
		}

		if Port_Number.Valid {
			serviceDBRow.PortNumber = &Port_Number.Int64
		} else {
			serviceDBRow.PortNumber = nil // Set to nil to represent null in JSON
		}

		if PID.Valid {
			serviceDBRow.PID = &PID.Int64
		} else {
			serviceDBRow.PID = nil // Set to nil to represent null in JSON
		}

		if strings.Contains(Address, "::") {
			serviceDBRow.Address = Address + "(IPV6)"
		} else if strings.Contains(Address, "0.0.0.0") {
			serviceDBRow.Address = Address + "(IPV4)"
		}

		serviceDBRowList = append(serviceDBRowList, serviceDBRow)
	}

	return serviceDBRowList, nil
}

type GroupedPayload struct {
	GetKb                *string `json:"get_kb"`
	GetDisplayVersion    *string `json:"getDisplayVersion"`
	GetApplications      *string `json:"installedApplications"`
	GetNetwork           *string `json:"get_network"`
	GetAutofim           *string `json:"get_autofim"`
	GetWinScheduledTask  *string `json:"get_winScheduledTask"`
	GetLocaldns          *string `json:"localDNS"`
	GetService           *string `json:"get_GetService"`
	GetProxy             *string `json:"getproxy"`
	GetNetshare          *string `json:"getnetshare"`
	GetStartup           *string `json:"getstartup"`
	GetRdp               *string `json:"getrdp"`
	GetAV                *string `json:"getAV"`
	GetConnectionAnydesk *string `json:"getconnectionanydesk"`
}

type FeatureCSVFunctionConfig struct {
	Func         func() (string, error) // Function to call
	Toggle       bool                   // Feature toggle status
	HashFileName string                 // Hash file name for checking
}

// executeCSVFeatureFunctions executes the given list of feature function
// configurations and returns a map of the results of each function with the
// result key as the key and the result as the value.
func executeCSVFeatureFunctions(configs []FeatureCSVFunctionConfig) []string {
	filePaths := []string{}

	for _, config := range configs {
		if !config.Toggle {
			continue
		}

		filePath, err := config.Func()
		if err != nil {
			log.Error().Err(err).Msgf("Error executing csv feature function %s.", config.HashFileName)
			continue
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Error().Err(err).Msgf("Error in reading file %s inside of executeCSVFeatureFunctions.", filePath)
			continue
		}

		isSame, err := checkIfHashFileSameOrUpdateIt(config.HashFileName, string(data))
		if err != nil {
			log.Error().Err(err).Msg("Error in checking if hash file is same or not.")
			continue
		}
		if isSame {
			continue
		}

		filePaths = append(filePaths, filePath)
	}

	return filePaths
}

func createCSVFeatureConfigs() []FeatureCSVFunctionConfig {
	featureConfigs := []FeatureCSVFunctionConfig{
		{
			Func:         getChromeExtentions,
			Toggle:       Chromeextions,
			HashFileName: "getChromeextions.txt",
		},
		{
			Func:         retrieveComputerInfo,
			Toggle:       computerconfigrations,
			HashFileName: "getcomputerinfo.txt",
		},
		{
			Func:         getBitLockerInfo,
			Toggle:       bitlocker,
			HashFileName: "getbitlocker.txt",
		},
		{
			Func:         getTPMInfo,
			Toggle:       tpmwin,
			HashFileName: "get_tpm_win.txt",
		},
	}
	return featureConfigs
}

func uploadAllSystemDataAndDetailsAsBulkCSV() error {
	defer catchPanic()

	log.Info().Msg("Starting the process of uploading all system data and details as bulk CSV.")

	csvFeatureConfigs := createCSVFeatureConfigs()

	filePaths := executeCSVFeatureFunctions(csvFeatureConfigs)

	if len(filePaths) == 0 {
		return nil
	}

	zipFileName := fmt.Sprintf("%s_upload-group-of-date-csv.zip", id)
	zipFilePath := filepath.Join(CymetricxPath, "Compressed Files", zipFileName)
	srcToDstMap := make(map[string]string)
	for _, result := range filePaths {
		_, fileName := filepath.Split(result)
		srcToDstMap[result] = fmt.Sprintf("%s_%s", id, fileName)
	}

	if err := createAndWriteToZipFile(zipFileName, srcToDstMap); err != nil {
		return fmt.Errorf("error in creating and writing zip: %w", err)
	}

	// sleepForRandomDelayDuration(minimalUploadInterval, maximalUploadInterval)

	responseBody, err := createAndExecuteFileUploadRequest("upload_group_of_data_csv/"+id, zipFilePath)
	if err != nil {
		return fmt.Errorf("error in createAndExecuteUploadRequest: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in reading general response body: %w", err)
	}

	log.Info().Msg("Successfully uploaded a group of data CSV.")

	return nil
}

type FeatureFunctionConfig struct {
	Func         func() (string, error) // Function to call
	Toggle       bool                   // Feature toggle status
	HashFileName string                 // Hash file name for checking
	ResultKey    string                 // Key for the result in the final map
}

// uploadAllSystemDataAndDetailsAsBulk uploads a grouped set of data collected
// from the system. The data includes the system's users and their password
// status, whether splunk is running or not, the system's installed packages
// with their  details, whether falcon is installed or not, the system's cron
// jobs, the system's local DNS mappings, the system's SSH server
// configurations, the system's BIOS information, the system's general
// information, and the system's shadow file.
func uploadAllSystemDataAndDetailsAsBulk() error {
	defer catchPanic()

	log.Info().Msg("Starting the process of uploading all system data and details as bulk.")

	featureConfigs := createFeatureConfigs()

	results := executeFeatureFunctions(featureConfigs)

	data, err := createBulkSystemDataUploadJsonPayload(results)
	if err != nil {
		return fmt.Errorf("error in creating new function: %w", err)
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("upload_groupofdata.txt", string(data))
	if err != nil {
		log.Error().Err(err).Msg("Error while checking if hash file is same or updated.")
		// Continue your work and uplaod the data
	}
	if ifSame {
		return nil
	}

	filePath, err := createAndCompressPayloadIntoGZipFile(data, "uploadgroupofdata.gz")
	if err != nil {
		return fmt.Errorf("error in creating and compressing payload into gzip file for grouped data: %w", err)
	}

	responseBody, err := createAndExecuteFileUploadRequest("upload_group_of_data/"+id, filePath)
	if err != nil {
		return fmt.Errorf("error in uploading the grouped data: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in reading general response body: %w", err)
	}

	log.Info().Msg("Successfully uploaded a group of data.")

	return nil
}

// createFeatureConfigs creates a list of feature function configurations
// based on the feature toggle configuration.
func createFeatureConfigs() []FeatureFunctionConfig {
	featureConfigs := []FeatureFunctionConfig{
		{
			Func:         getAllInstalledApplicationsV2,
			Toggle:       applicationsandsoftwares,
			HashFileName: "getApplications.txt",
			ResultKey:    "getApplications",
		},
		{
			Func:         getNetworkInterfaceInfo,
			Toggle:       networksettings,
			HashFileName: "get_network.txt",
			ResultKey:    "get_network",
		},

		// Will be added in the future
		// {
		// 	Func:         getInstalledWindowsUpdatesAndHotfixesV2,
		// 	Toggle:       featureToggleConfig.InstalledPatchesCheck,
		// 	HashFileName: "get_kb.txt",
		// 	ResultKey:    "get_kb",
		// },

		{
			Func:         getSecureBootStatus,
			Toggle:       bootsecure,
			HashFileName: "get_autofim.txt",
			ResultKey:    "get_autofim",
		},

		{
			// Memory Leakage: This function is not working properly
			// Func:         getAllScheduledTasksInfoV2,
			Func:         getAllScheduledTasksInfo,
			Toggle:       scheduledtasks,
			HashFileName: "get_winScheduledTask.txt",
			ResultKey:    "get_winScheduledTask",
		},

		{
			Func:         getLocalDNSV2,
			Toggle:       featureToggleConfig.LocalDNSMonitoring,
			HashFileName: "get_localdns.txt",
			ResultKey:    "get_localdns",
		},
		{
			Func:         getAllWindowsServicesStatus,
			Toggle:       windowsservices,
			HashFileName: "get_GetService.txt",
			ResultKey:    "get_GetService",
		},
		{
			Func:         getFirewallValueV2,
			Toggle:       av,
			HashFileName: "getAV.txt",
			ResultKey:    "getAV",
		},
		{
			Func:         getProxySettingsV2,
			Toggle:       winproxysettings,
			HashFileName: "getproxy.txt",
			ResultKey:    "getproxy",
		},
		{
			Func:         getRDPStatusV2,
			Toggle:       rdpstatus,
			HashFileName: "getrdp.txt",
			ResultKey:    "getrdp",
		},
		{
			Func:         getStartupCommands2,
			Toggle:       windowsstartup,
			HashFileName: "getstartup.txt",
			ResultKey:    "getstartup",
		},
		{
			Func:         getNetworkShares,
			Toggle:       networkshares,
			HashFileName: "getnetshare.txt",
			ResultKey:    "getnetshare",
		},
		{
			Func:         getAnyDeskConnectionTrace,
			Toggle:       remotetoolslogs,
			HashFileName: "getconnectionanydesk.txt",
			ResultKey:    "getconnectionanydesk",
		},
		{
			Func:         getWindowsDisplayVersion,
			Toggle:       DisplayVersion,
			HashFileName: "getDisplayVersion.txt",
			ResultKey:    "getDisplayVersion",
		},
	}
	return featureConfigs
}

// executeFeatureFunctions executes the given list of feature function
// configurations and returns a map of the results of each function with the
// result key as the key and the result as the value.
func executeFeatureFunctions(configs []FeatureFunctionConfig) map[string]string {
	results := make(map[string]string)

	for _, config := range configs {
		var output string
		if config.Toggle {
			rawData, err := config.Func()
			if err != nil {
				log.Error().Err(err).Msgf("Error executing feature function for result key %s", config.ResultKey)
				continue
			}
			if config.ResultKey == "getnetshare" {
				output = b64Encoding(rawData)
			} else {
				output = rawData
			}

			isSame, err := checkIfHashFileSameOrUpdateIt(config.HashFileName, output)
			if err != nil {
				log.Error().Err(err).Msg("Error in checking if hash file is same or not.")
				continue
			}
			if isSame {
				// This is so the server would know to not update the database with the value
				// This is different from uploading an empty string which means
				// that the database should be updated with an empty string
				output = "no_uploaded_data"
			}
		} else {
			output = "no_uploaded_data"
		}

		results[config.ResultKey] = output
	}

	return results
}

// createBulkSystemDataUploadJsonPayload creates a json payload for the grouped
// data provided and returns it as a byte array.
func createBulkSystemDataUploadJsonPayload(results map[string]string) ([]byte, error) {
	groupedPayload := GroupedPayload{
		GetKb:                strToPtrOrNil(results["get_kb"]),
		GetDisplayVersion:    strToPtrOrNil(results["getDisplayVersion"]),
		GetApplications:      strToPtrOrNil(results["getApplications"]),
		GetNetwork:           strToPtrOrNil(results["get_network"]),
		GetAutofim:           strToPtrOrNil(results["get_autofim"]),
		GetWinScheduledTask:  strToPtrOrNil(results["get_winScheduledTask"]),
		GetLocaldns:          strToPtrOrNil(results["get_localdns"]),
		GetService:           strToPtrOrNil(results["get_GetService"]),
		GetProxy:             strToPtrOrNil(results["getproxy"]),
		GetNetshare:          strToPtrOrNil(results["getnetshare"]),
		GetStartup:           strToPtrOrNil(results["getstartup"]),
		GetRdp:               strToPtrOrNil(results["getrdp"]),
		GetAV:                strToPtrOrNil(results["getAV"]),
		GetConnectionAnydesk: strToPtrOrNil(results["getconnectionanydesk"]),
	}

	data, err := json.Marshal(groupedPayload)
	if err != nil {
		return nil, fmt.Errorf("error in marshalling grouped payload: %w", err)
	}
	return data, nil
}

// strToPtrOrNil returns a pointer to the given string if it is not empty,
// otherwise returns nil. This is useful for JSON serialization to output null for empty strings.
func strToPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func createCertificatesZipFile() (string, error) {
	script := `Get-ChildItem Cert:\LocalMachine\*\* | Export-CSV 'C:\Program Files\CYMETRICX\certs.csv' -Encoding UTF8`

	if err := writeToAndExcutePS1Script(script, "getcerts.ps1"); err != nil {
		return "", fmt.Errorf("error in creating excutable file: %w", err)
	}
	zipFileName := fmt.Sprintf("certs_%s_uploadcertswin.zip", id)
	csvSourcePath := filepath.Join(CymetricxPath, "certs.csv")
	csvDestinationName := fmt.Sprintf("certs_%s_uploadcertswin.csv", id)

	srcToDestMap := map[string]string{
		csvSourcePath: csvDestinationName,
	}

	if err := createAndWriteToZipFile(zipFileName, srcToDestMap); err != nil {
		return "", fmt.Errorf("error in creating and writing zip: %w", err)
	}

	zipFilePath := filepath.Join(CymetricxPath, "Compressed Files", zipFileName)
	return zipFilePath, nil
}

func addRunningProcessesAndServicesToDB() {
	defer catchAndRestartPanicForFunction(addRunningProcessesAndServicesToDB)

	log.Info().Msg("Initiating adding running processes and services to db")
	for {
		log.Info().Msg("Adding running processes and services to db")
		if featureToggleConfig.SystemProcessesAndServicesCheck {
			log.Debug().Msg("Adding all system running processes")
			if err := addAllSystemRunningProcessesToDBV2(); err != nil {
				log.Error().Err(err).Msg("Error in addAllSystemRunningProcesses.")
			}
		}

		if featureToggleConfig.SystemProcessesAndServicesCheck {
			log.Debug().Msg("Adding listening services to db")
			if err := addListeningServicesToDBV2(); err != nil {
				log.Error().Err(err).Msg("Error in addListiningServicesToDB.")
			}
		}

		log.Debug().Msg("Sleeping for 5 minutes before adding running processes and services to db")
		time.Sleep(5 * time.Minute)
	}
}

// & Benchmarkv1                1       56186352100 ns/op   (56 sec)        35916721 B/op      39273 allocs/op
// & Benchmarkv2                1        6079156900 ns/op   (6  sec)        25905152 B/op      76493 allocs/op
// & Benchmarkv3                1        2927373400 ns/op   (3  sec)        21952328 B/op      35750 allocs/op
func addAllSystemRunningProcessesToDBV2() error {
	log.Info().Msg("Starting the process of adding all system running processes to db ... ")
	db, err := ldb.InitDB()
	if err != nil {
		return fmt.Errorf("error in init db: %w", err)
	}
	defer db.Close()
	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() // Ensure rollback in case of failure

	// Insert the processes into the database if they don't already exist
	// This is done in a single transaction to ensure that all processes are added
	// or none are added.
	//
	// The select statement supplies the values to the insert statement only if
	// the values don't already exist in the database.
	query := `
		INSERT INTO processes (
			Path,
			ProcessId,
			CreationDate,
			Name,
			UserName,
			CommandLine,
			ExecutablePath
		) 
		SELECT ?, ?, ?, ?, ?, ?, ?
		WHERE NOT EXISTS (
			SELECT 1 FROM processes
			WHERE Path = ? AND ProcessId = ? AND CreationDate = ? AND Name = ? AND UserName = ? AND CommandLine = ? AND ExecutablePath = ?
		)
	`

	// Prepare the insert statement once and reuse it for each process
	// This is more efficient than preparing the statement for each process
	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("error preparing statement for processes: %w", err)
	}
	defer stmt.Close()

	// Get all the running processes
	processes, err := process.Processes()
	if err != nil {
		return fmt.Errorf("error getting processes: %w", err)
	}

	// Process and insert each process into the database
	for _, p := range processes {
		if err := processAndInsertProcessIntoDBV3(p, stmt); err != nil {
			return fmt.Errorf("error processing and inserting process into db: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	log.Info().Msg("Successfully added all system running processes to db")
	return nil
}

func processAndInsertProcessIntoDBV3(p *process.Process, stmt *sql.Stmt) error {
	name, _ := p.Name()
	processID := p.Pid                    // This is the process ID
	createTimeMillis, _ := p.CreateTime() // This is in milliseconds
	commandLine, _ := p.Cmdline()         // This is the command line used to start the process
	path, _ := p.Cwd()                    // This is the working directory of the process
	userName, _ := p.Username()           // This is the user who started the process
	executablePath, _ := p.Exe()          // This is the path to the executable

	createTime := time.Unix(0, createTimeMillis*int64(time.Millisecond))
	creationDate := createTime.Format("20060102150405.000000-0700")

	if processID == 0 {
		// Skip the system idle process
		return nil
	}

	_, err := stmt.Exec(
		path, processID, creationDate, name, userName, commandLine, executablePath,
		path, processID, creationDate, name, userName, commandLine, executablePath,
	)
	if err != nil {
		return fmt.Errorf("error executing insert: %w", err)
	}

	return nil
}

// & BenchmarkV1         1         4147675800 ns/op  (4.1 sec)         413320 B/op       5692 allocs/op
// & BenchmarkV2         10         105526767 ns/op  (.1 sec)           79136 B/op       2511 allocs/op
func addListeningServicesToDBV2() error {
	log.Info().Msg("Starting the process of adding listening services to db ... ")

	db, err := ldb.InitDB()
	if err != nil {
		return fmt.Errorf("error initializing database: %w", err)
	}
	defer db.Close()
	sockets, sockets6, err := getTCPAndTCP56ListeningServices()
	if err != nil {
		return err
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() // Ensure rollback in case of failure

	// Insert the services into the database if they don't already exist
	// This is done in a single transaction to ensure that all services are added
	// or none are added.
	//
	// The select statement supplies the values to the insert statement only if
	// the values don't already exist in the database.
	query := `
		INSERT INTO listening_services (
			Port_Number,
			Protocol,
			Service_Name,
			PID,
			Address
		)
		SELECT ?, ?, ?, ?, ?
		WHERE NOT EXISTS (
			SELECT 1 FROM listening_services
			WHERE Port_Number = ? AND Protocol = ? AND Service_Name = ? AND PID = ? AND Address = ?
		)
	`

	// Prepare the insert statement once and reuse it for each service
	// This is more efficient than preparing the statement for each service
	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("error preparing statement for listening_services: %w", err)
	}
	defer stmt.Close()

	// Process and insert each service into the database
	for _, socket := range sockets {
		if err := processAndInsertServiceIntoDBV2(socket, stmt, "TCP"); err != nil {
			return fmt.Errorf("error processing and inserting service into db: %w", err)
		}
	}

	for _, socket := range sockets6 {
		if err := processAndInsertServiceIntoDBV2(socket, stmt, "TCP6"); err != nil {
			return fmt.Errorf("error processing and inserting service into db: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	log.Info().Msg("Successfully added listening services to db")

	return nil

}

func getTCPAndTCP56ListeningServices() ([]netstat.SockTabEntry, []netstat.SockTabEntry, error) {

	// get only listening TCP sockets
	sockets, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error getting TCP sockets: %s", err)
	}

	// get only listening TCP6 sockets
	sockets6, err := netstat.TCP6Socks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error getting TCP6 sockets: %s", err)
	}

	return sockets, sockets6, nil
}

func processAndInsertServiceIntoDBV2(socket netstat.SockTabEntry, stmt *sql.Stmt, protocol string) error {
	// Get the process ID and name for the service
	pidAndName := socket.Process
	pid := pidAndName.Pid          // This is the process ID
	serviceName := pidAndName.Name // This is the name of the process

	// Get the address and port for the service
	addressAndPort := socket.LocalAddr
	address := addressAndPort.IP // This is the local address
	port := addressAndPort.Port  // This is the local port

	// Insert the service into the database
	_, err := stmt.Exec(
		port, protocol, serviceName, pid, address.String(),
		port, protocol, serviceName, pid, address.String(),
	)
	if err != nil {
		return fmt.Errorf("error executing insert into windows client services: %w", err)
	}

	return nil

}

func startCollectAndUploadMonitoringDataAndComputerUpTime() {
	defer catchAndRestartPanicForFunction(startCollectAndUploadMonitoringDataAndComputerUpTime)

	log.Info().Msg("Initiating compressing and uploading monitoring data")

	for {
		log.Info().Msg("Compressing and uploading monitoring data for windows in a loop")

		// Temp values in to fasten up the reupload if an error occurs from the psutil package:
		tempMinimalMonitoringInterval := minimalMonitoringInterval
		tempMaximalMonitoringInterval := maximalMonitoringInterval

		jsonPayload, err := getCPUAndMemoryAndDiskPartionsStats()
		if err != nil {
			// Reupload in 1-2 minutes as opposed to the typical 10-15 minutes
			tempMinimalMonitoringInterval = 1
			tempMaximalMonitoringInterval = 2
			log.Error().Err(err).Msg("error in getCPUAndMemoryAndDiskPartionsStats()")
		}

		responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", "upload_windows_system_monitoring/"+id, jsonPayload, 10)
		if err != nil {
			log.Error().Err(err).Msg("error in createAndExecuteUploadRequest")
		}

		if err := readGeneralReponseBody(responseBody); err != nil {
			log.Error().Err(err).Msg("error in  compressAndUploadMonitoringData to the server")
		}

		if !getuptimewin {
			sleepForRandomDelayDurationInMinutes(tempMinimalMonitoringInterval, tempMaximalMonitoringInterval) // sleep for 10 to 15 minutes by default
			continue
		}

		if err := getAndUploadComputerUpTimeV2(); err != nil {
			log.Error().Err(err).Msg("error in compressAndUploadComputerUpTime")
		}

		sleepForRandomDelayDurationInMinutes(tempMinimalMonitoringInterval, tempMaximalMonitoringInterval) // sleep for 10 to 15 minutes by default
	}
}

type MonitoringData struct {
	Memory         MemoryDetails `json:"memory"`
	CPUDetails     string        `json:"CPUDetails"`
	DiskPartitions string        `json:"diskPartitions"`
}

type MemoryDetails struct {
	Total      uint64  `json:"total"`
	Used       uint64  `json:"used"`
	Free       uint64  `json:"free"`
	Percentage float64 `json:"percentage"`
}

func getCPUAndMemoryAndDiskPartionsStats() ([]byte, error) {
	log.Info().Msg("Initiating getting CPU and memory and disk partions stats")

	memoryDetails, err := getMemoryStats()
	if err != nil {
		return nil, err
	}

	cpuDetails, err := getCPUStats()
	if err != nil {
		return nil, err
	}

	partitionsDetails, err := getDiskPartitionsStats()
	if err != nil {
		return nil, err
	}

	monitoringData := MonitoringData{
		Memory:         memoryDetails,
		CPUDetails:     cpuDetails,
		DiskPartitions: partitionsDetails,
	}

	jsonPayload, err := json.Marshal(monitoringData)
	if err != nil {
		return nil, fmt.Errorf("error in json.Marshal for monitoring data: %w", err)
	}

	log.Info().Msg("Successfully got CPU and memory and disk partions stats")
	return jsonPayload, nil
}

func getMemoryStats() (MemoryDetails, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return MemoryDetails{}, fmt.Errorf("error in mem.VirtualMemory: %w", err)
	}

	return MemoryDetails{
		Total:      v.Total,
		Used:       v.Used,
		Free:       v.Free,
		Percentage: v.UsedPercent,
	}, nil
}

func getCPUStats() (string, error) {
	cpuDetails := ""
	cpuPhyisicalCoresNo, err := cpu.Counts(false)
	if err != nil {
		return "", fmt.Errorf("error in cpu.Counts: %w", err)
	}

	cpuInfo, err := cpu.Info()
	if err != nil {
		return "", fmt.Errorf("error in cpu.Info: %w", err)
	}

	cpuLogicalCoresNo, err := cpu.Counts(true)
	if err != nil {
		return "", fmt.Errorf("error in cpu.Counts: %w", err)
	}

	cpuUtilization, err := cpu.Percent(time.Second, false)
	if err != nil {
		return "", fmt.Errorf("error in cpu.Percent: %w", err)
	}

	// Calculate average CPU load
	var totalLoad, avgLoad float64
	if len(cpuUtilization) > 0 {
		for _, load := range cpuUtilization {
			totalLoad += load
		}
		avgLoad = totalLoad / float64(len(cpuUtilization))
	} else {
		avgLoad = 0.0 // Handle case where cpuUtilization is empty
	}

	var vendorID, modelName string
	if len(cpuInfo) > 0 {
		vendorID = cpuInfo[0].VendorID
		modelName = cpuInfo[0].ModelName
	} else {
		vendorID = "N/A3"
		modelName = "N/A3"
	}

	cpuDetails = strings.Join([]string{
		"CPU",
		fmt.Sprintf("%f", avgLoad),
		vendorID,
		modelName,
		strconv.Itoa(cpuPhyisicalCoresNo),
		strconv.Itoa(cpuLogicalCoresNo),
		"OK",
		"\n",
		"##",
	}, "#")

	return cpuDetails, nil
}

func getDiskPartitionsStats() (string, error) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return "", fmt.Errorf("error in disk.Partitions: %w", err)
	}

	var sb strings.Builder
	for _, partition := range partitions {
		diskUsage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			return "", fmt.Errorf("error in disk.Usage: %w", err)
		}

		sb.WriteString(formateDiskUsageToString(diskUsage))
	}

	return sb.String(), nil
}

func formateDiskUsageToString(diskUsage *disk.UsageStat) string {
	result := ""

	unit := chooseUnit(diskUsage.Total) // Determine the appropriate unit based on total space

	result = formatDiskUsage(diskUsage.Path, diskUsage.UsedPercent, diskUsage.Total, unit, diskUsage.Free, diskUsage.Used)

	return result
}

func formatDiskUsage(path string, usedPercent float64, total uint64, unit string, free uint64, used uint64) string {
	return fmt.Sprintf(
		"%s#%.2f%%#Total: %.2f %s#Free: %.2f %s#Used: %.2f %s###",
		path,
		usedPercent,
		float64(total)/math.Pow(1024, float64(unitExponent(unit))),
		unit,
		float64(free)/math.Pow(1024, float64(unitExponent(unit))),
		unit,
		float64(used)/math.Pow(1024, float64(unitExponent(unit))),
		unit,
	)
}

func unitExponent(unit string) int {
	switch unit {
	case "B":
		return 0
	case "KB":
		return 1
	case "MB":
		return 2
	case "GB":
		return 3
	case "TB":
		return 4
	case "PB":
		return 5
	// Add more units as needed
	default:
		return 0 // Default to bytes if unit is not recognized
	}
}

func chooseUnit(value uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"} // Add more units as needed

	exponent := 0
	for value >= 1024 && exponent < len(units)-1 {
		value /= 1024
		exponent++
	}

	return units[exponent]
}

type ApiUpTimeResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

func scanActiveDirectoryAndLGPOAndUploadThem() {
	defer catchAndRestartPanicForFunction(scanActiveDirectoryAndLGPOAndUploadThem)

	log.Info().Msg("Starting the process of scanning active directory and LGPO and uploading them ... ")

	for {
		log.Debug().Msg("Scanning active directory and LGPO and uploading them")

		if err := startExcuteScanningAndUploadingDataIfTimeElapsed(); err != nil {
			log.Error().Err(err).Msg("error in startExcuteScanningAndUploadingDataIfTimeElapsed")
		}

		log.Info().Msg("Sleeping for 5 to 6 hours before scanning active directory and LGPO and uploading them again ...")

		sleepForRandomDelayDurationInMinutes(300, 360) // sleep for 5 to 6 hours by default
	}
}

func startExcuteScanningAndUploadingDataIfTimeElapsed() error {
	filePath := filepath.Join(CymetricxPath, "Time Files", "windows-users-LGPO-timer.txt")

	ifElapsed, err := isDurationElapsedSinceLastUpdate(filePath, 3)
	if err != nil {
		return err
	}

	if ifElapsed {
		// if err := excuteScanningAndUploadingData(filePath); err != nil {
		// return err
		// }
		excuteScanningAndUploadingData(filePath)

		createNowFileTimer(filePath)
	}

	return nil
}

// isDurationElapsedSinceLastUpdate checks if the duration has elapsed since
// the last update of the file.
func isDurationElapsedSinceLastUpdate(filePath string, durationInHours int) (bool, error) {
	// If file does not exist, then we should upload the data directly
	if !fileExists(filePath) {
		return true, nil
	}

	rawPreviousTime, err := os.ReadFile(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to read timer file %s: %w", filePath, err)
	}

	previousTime, err := strconv.ParseInt(string(rawPreviousTime), 10, 64)
	if err != nil {
		return false, fmt.Errorf("failed to parse the previous time %s of %s: %w", string(rawPreviousTime), filePath, err)
	}

	// Convert previousTime back to time.Time for comparison
	previousTimeParsed := time.Unix(0, previousTime*int64(time.Millisecond))

	durationInHoursParsed := time.Duration(durationInHours)

	// Check if the current time is after the previous time + 5 hours
	if time.Now().After(previousTimeParsed.Add(durationInHoursParsed * time.Hour)) {
		return true, nil
	}

	return false, nil
}

func excuteScanningAndUploadingData(filePath string) error {
	if err := uploadWindowsUsersInformationV2(); err != nil {
		log.Error().Err(err).Msg("error in uploading windows users information while excuting the scan every 5-6 hours")
	}

	if activeDirectoryDomainController {
		compressAndUploadGPOsToServerV2()

		if err := compressAndUploadActiveDirectoryObjectsV2(); err != nil {
			log.Error().Err(err).Msg("Error in compressing and uploading active directory objects to server inside of scanning and uploading data.")
		}
	}
	currentTime := fmt.Sprint(time.Now().UnixNano() / int64(time.Millisecond))

	if err := createNonExcutableFile(filePath, currentTime); err != nil {
		log.Error().Err(err).Msg("error in createNonExcutableFile")
	}

	log.Info().Msg("Successfully scanned and uploaded data")

	return nil
}

func processBenchmarkAndAuditResult() {
	log.Info().Msg("Initiating conf thread")

	if !SystemHardeningCheck {
		return
	}

	command, err := getBenchMark()
	if err != nil {
		log.Error().Err(err).Msg("error in getBenchMark")
	}

	if err := startExcuteAuditResultIfTimeElapsed(command, true); err != nil {
		log.Error().Err(err).Msg("error in startExcuteAuditResultIfTimeElapsed")
	}
}

func startExcuteAuditResultIfTimeElapsed(command string, ifCallLaravel bool) error {
	filePath := filepath.Join(CymetricxPath, "Time Files", "audit_resulttime2.txt")

	ifElapsed, err := isDurationElapsedSinceLastUpdate(filePath, 5)
	if err != nil {
		return err
	}

	if !ifElapsed {
		return nil
	}

	audit_result(command, ifCallLaravel)

	createNowFileTimer(filePath)

	return nil

}

func audit_result(command string, ifCallLaravel bool) (string, error) {
	log.Info().Msg("Initiating audit result")

	var tagforauditstat = "Kerberos_Authentication_Service:Kerberos Authentication Service\nKerberos_Service_Ticket_Operations:Kerberos Service Ticket Operations\nDetailed_File_Share:Detailed File Share\nFile_Share:File Share\nMPSSVC_Rule_Level_Policy_Change:MPSSVC Rule-Level Policy Change\nOther_Policy_Change_Events:Other Policy Change Events\ncredential_validation:Credential Validation\napplication_group_management:Application Group Management\ncomputer_account_management:Computer Account Management\ndistribution_group_management:Distribution Group Management\nother_account_management_events:Other Account Management Events\nsecurity_group_management:Security Group Management\nuser_account_management:User Account Management\npnp_activity:Plug and Play Events\nprocess_creation:Process Creation\ndirectory_service_access:Directory Service Access\ndirectory_service_changes:Directory Service Changes\naccount_lockout:Account Lockout\ngroup_membership:Group Membership\nlogoff:Logoff\nlogon:Logon\nother_logon_logoff_events:Other Logon/Logoff Events\nspecial_logon:Special Logon\nother_object_access_events:Other Object Access Events\nremovable_storage:Removable Storage\naudit_policy_change:Audit Policy Change\nauthentication_policy_change:Authentication Policy Change\nauthorization_policy_change:Authorization Policy Change\nsensitive_privilege_use:Sensitive Privilege Use\nipsec_driver:IPsec Driver\nother_system_events:Other System Events\nsecurity_state_change:Security State Change\nsecurity_system_extension:Security System Extension\nsystem_integrity:System Integrity"
	var tagforpolicylgpo = "min_passwd_age:MinimumPasswordAge\nreversible_encryption:ClearTextPassword\npassword_complexity:PasswordComplexity\nmin_passwd_len:MinimumPasswordLength\nmax_passwd_age:MaximumPasswordAge\npassword_hist_len:PasswordHistorySize"
	var tagusserright = "SE_TRUSTED_CREDMAN_ACCESS_NAME:SeTrustedCredManAccessPrivilege\nSE_NETWORK_LOGON_NAME:SeNetworkLogonRight\nSE_TCB_NAME:SeTcbPrivilege\nSE_MACHINE_ACCOUNT_NAME:SeMachineAccountPrivilege\nSE_INCREASE_QUOTA_NAME:SeIncreaseQuotaPrivilege\nSE_INTERACTIVE_LOGON_NAME:SeInteractiveLogonRight\nSE_REMOTE_INTERACTIVE_LOGON_NAME:SeRemoteInteractiveLogonRight\nSE_BACKUP_NAME:SeBackupPrivilege\nSE_SYSTEMTIME_NAME:SeSystemtimePrivilege\nSE_TIME_ZONE_NAME:SeTimeZonePrivilege\nSE_CREATE_PAGEFILE_NAME:SeCreatePagefilePrivilege\nSE_CREATE_TOKEN_NAME:SeCreateTokenPrivilege\nSE_CREATE_GLOBAL_NAME:SeCreateGlobalPrivilege\nSE_CREATE_PERMANENT_NAME:SeCreatePermanentPrivilege\nSE_CREATE_SYMBOLIC_LINK_NAME:SeCreateSymbolicLinkPrivilege\nSE_DEBUG_NAME:SeDebugPrivilege\nSE_DENY_NETWORK_LOGON_NAME:SeDenyNetworkLogonRight\nSE_DENY_BATCH_LOGON_NAME:SeDenyBatchLogonRight\nSE_DENY_SERVICE_LOGON_NAME:SeDenyServiceLogonRight\nSE_DENY_INTERACTIVE_LOGON_NAME:SeDenyInteractiveLogonRight\nSE_DENY_REMOTE_INTERACTIVE_LOGON_NAME:SeDenyRemoteInteractiveLogonRight\nSE_ENABLE_DELEGATION_NAME:SeEnableDelegationPrivilege\nSE_REMOTE_SHUTDOWN_NAME:SeRemoteShutdownPrivilege\nSE_AUDIT_NAME:SeAuditPrivilege\nSE_IMPERSONATE_NAME:SeImpersonatePrivilege\nSE_INC_BASE_PRIORITY_NAME:SeIncreaseBasePriorityPrivilege\nSE_LOAD_DRIVER_NAME:SeLoadDriverPrivilege\nSE_LOCK_MEMORY_NAME:SeLockMemoryPrivilege\nSE_BATCH_LOGON_NAME:SeBatchLogonRight\nSE_SERVICE_LOGON_NAME:SeServiceLogonRight\nSE_SECURITY_NAME:SeSecurityPrivilege\nSE_RELABEL_NAME:SeRelabelPrivilege\nSE_SYSTEM_ENVIRONMENT_NAME:SeSystemEnvironmentPrivilege\nSE_MANAGE_VOLUME_NAME:SeManageVolumePrivilege\nSE_PROF_SINGLE_PROCESS_NAME:SeProfileSingleProcessPrivilege\nSE_SYSTEM_PROFILE_NAME:SeSystemProfilePrivilege\nSE_ASSIGNPRIMARYTOKEN_NAME:SeAssignPrimaryTokenPrivilege\nSE_RESTORE_NAME:SeRestorePrivilege\nSE_SHUTDOWN_NAME:SeShutdownPrivilege\nSE_SYNC_AGENT_NAME:SeSyncAgentPrivilege\nSE_TAKE_OWNERSHIP_NAME:SeTakeOwnershipPrivilege"
	var tagforlockoutlgpo = "lockout_threshold:LockoutBadCount\nlockout_observation_window:ResetLockoutCount\nlockout_duration:LockoutDuration"

	if !exitCommandCheck {
		return "", nil
	}

	exitCommandCheck = false
	dataFromLGPO, getAuditFromCSV, err := getLGPO()
	if err != nil {
		exitCommandCheck = true
		return "", fmt.Errorf("error in getlgpo: %w", err)
	}

	var resultcommand = ""
	exccommand := strings.Split(command, "\n")
	var exceuteallcommand = ""
	var getCommandsWithInfo = ""

	for i := 0; i < len(exccommand); i++ {
		getCommandsWithInfo = getCommandsWithInfo + string(strings.Split(exccommand[i], "command######")[0]) + "\n######fort######fort######fort######\n"
		if strings.Contains(exccommand[i], "######notcommand") {
			resultcommand = resultcommand + exccommand[i] + "\n###############fortressfortress###############\n"
		} else if strings.Contains(exccommand[i], "operationComplexCheck") {
			exconecommand := strings.Split(exccommand[i], "command######")
			if !strings.Contains(exccommand[i], "script:::###") {
				if exconecommand[1] == "" {
					continue
				}

				if strings.Contains(string(exconecommand[1]), "check_existence_command:::##Manual:") {
					manualcommand := "echo '::Manual::'"
					exceuteallcommand = exceuteallcommand + manualcommand + "\necho '######fortress######fortress######'\n"
				} else if strings.Contains(string(exconecommand[1]), "check_existence_command") {
					check_existence := strings.Split(exconecommand[1], "::end::")[0]
					check_existence1 := strings.Replace(check_existence, ":::##check_existence_command:::##", "", -1)
					exceuteallcommand = exceuteallcommand + check_existence1 + "\necho '######fortress######fortress######'\n"
				} else {
					commandnreal := string(exconecommand[1])
					exceuteallcommand = exceuteallcommand + commandnreal + "\necho '######fortress######fortress######'\n"
				}
			}
		}
	}

	output, err := createAndRunPS1FileWithOutput("allcommands.ps1", exceuteallcommand)
	if err != nil {
		exitCommandCheck = true
		return "", fmt.Errorf("error in createAndRunPS1FileWithOutput: %w", err)
	}

	getResultFromOutput1 := strings.Split(string(string(output)), "######fortress######fortress######")
	getResultFromOutput2 := strings.Split(string(getCommandsWithInfo), "######fort######fort######fort######")

	for i := 0; i < len(getResultFromOutput1)-1; i++ {
		if getResultFromOutput2[i] == "" {
			continue
		}

		if strings.Contains(string(getResultFromOutput1[i]), "::Manual::") {
			resultcommand = resultcommand + string(getResultFromOutput2[i]) + "######output######::Manual::\n###############fortressfortress###############\n"
		} else if strings.Contains(string(getResultFromOutput2[i]), "::::passwordpolicy_state::::") {
			existauditsplit := strings.Split(tagforpolicylgpo, "\n")
			for j := 0; j < len(existauditsplit); j++ {
				existaudit := strings.Replace(string(getResultFromOutput1[i]), "\r", "", -1)
				existaudit1 := strings.Replace(existaudit, "\n", "", -1)
				existaudit2 := strings.Replace(existaudit1, " ", "", -1)

				exist_arg := strings.Split(existauditsplit[j], ":")[0]

				if exist_arg == existaudit2 && strings.Contains(existauditsplit[j], "none") {
					resultcommand = resultcommand + getResultFromOutput2[i] + "######output######::end::|" +
						(dataFromLGPO) + "\n###############fortressfortress###############\n"
					break
				} else if exist_arg == existaudit2 {
					resultcommand = resultcommand + string(getResultFromOutput2[i]) + "######output######" + string(getResultFromOutput1[i]) + "::end::|" +
						(dataFromLGPO) + "\n###############fortressfortress###############\n"
					break
				}
			}
		} else if strings.Contains(getResultFromOutput2[i], "::::lockoutpolicy_state::::") {
			existauditsplit := strings.Split(tagforlockoutlgpo, "\n")
			for j := 0; j < len(existauditsplit); j++ {
				existaudit := strings.Replace(string(getResultFromOutput1[i]), "\r", "", -1)
				existaudit1 := strings.Replace(existaudit, "\n", "", -1)
				existaudit2 := strings.Replace(existaudit1, " ", "", -1)
				exist_arg := strings.Split(existauditsplit[j], ":")[0]
				if exist_arg == existaudit2 && strings.Contains(existauditsplit[j], "none") {
					resultcommand = resultcommand + string(getResultFromOutput2[i]) + "######output######::end::|" +
						(dataFromLGPO) + "\n###############fortressfortress###############\n"
					break
				} else if exist_arg == existaudit2 {
					resultcommand = resultcommand + string(getResultFromOutput2[i]) + "######output######" + string(getResultFromOutput1[i]) + "::end::|" +
						(dataFromLGPO) + "\n###############fortressfortress###############\n"
					break
				}
			}
		} else if strings.Contains(string(getResultFromOutput2[i]), "::::auditeventpolicysubcategories_state::::") {
			existauditsplit := strings.Split(tagforauditstat, "\n")
			for j := 0; j < len(existauditsplit); j++ {
				existaudit := strings.Replace(string(getResultFromOutput1[i]), "\r", "", -1)
				existaudit1 := strings.Replace(existaudit, "\n", "", -1)
				existaudit2 := strings.Replace(existaudit1, " ", "", -1)
				exist_arg := strings.Split(existauditsplit[j], ":")[0]
				if exist_arg == existaudit2 && strings.Contains(existauditsplit[j], "none") {
					resultcommand = resultcommand + string(getResultFromOutput2[i]) + "######output######::end::|" +
						(getAuditFromCSV) + "\n###############fortressfortress###############\n"
					break
				} else if exist_arg == existaudit2 {
					resultcommand = resultcommand + string(getResultFromOutput2[i]) + "######output######" + string(getResultFromOutput1[i]) + "::end::|" +
						(getAuditFromCSV) + "\n###############fortressfortress###############\n"
					break
				}
			}
		} else if strings.Contains(string(getResultFromOutput2[i]), "::::userright_state::::") {
			existauditsplit := strings.Split(tagusserright, "\n")
			for j := 0; j < len(existauditsplit); j++ {
				existaudit := strings.Replace(string(getResultFromOutput1[i]), "\r", "", -1)
				existaudit1 := strings.Replace(existaudit, "\n", "", -1)
				existaudit2 := strings.Replace(existaudit1, " ", "", -1)
				exist_arg := strings.Split(existauditsplit[j], ":")[0]
				if exist_arg == existaudit2 && strings.Contains(existauditsplit[j], "none") {
					resultcommand = resultcommand + string(getResultFromOutput2[i]) + "######output######::end::|" +
						(dataFromLGPO) + "\n###############fortressfortress###############\n"
					break
				} else if exist_arg == existaudit2 {
					resultcommand = resultcommand + string(getResultFromOutput2[i]) + "######output######" + string(getResultFromOutput1[i]) + "::end::|" +
						(dataFromLGPO) + "\n###############fortressfortress###############\n"
					break
				}
			}
		} else {
			resultcommand = resultcommand + string(getResultFromOutput2[i]) + "######output######" + string(getResultFromOutput1[i]) + "::end::|" +
				string(getResultFromOutput1[i]) + "\n###############fortressfortress###############\n"
		}
	}

	if complience {
		uploadAuditToprocess(resultcommand, ifCallLaravel)
	}

	exitCommandCheck = true

	log.Info().Msg("Successfully audited result")
	return "", nil
}

func startInitialFullSystemDataAndDetailsScan() {
	log.Info().Msg("Starting the process of initial full scanning system data and details ... ")

	handleBenchmarkAndAuditResult()

	tasks := []*UploadTask{
		{
			File: "system-details-timer.txt",
			Action: func() error {
				return collectAndUploadSystemDetails_start_windows(false, "system-details-hash.txt", "start_windows")
			},
			RunAsGoroutine: false,
		},
		{
			File:           "upload_groupofdatatime.txt",
			Action:         uploadAllSystemDataAndDetailsAsBulk,
			RunAsGoroutine: false,
		},
		{
			File:           "certswintime.txt",
			Action:         compressAndUploadWindowsCertificatesV2,
			RunAsGoroutine: false,
		},
		{
			File:           "upload_getpasswordpolicyresulttime.txt",
			Action:         uploadPasswordPolicyResult,
			RunAsGoroutine: false,
		},
		{
			File:           "upload_processtime.txt",
			Action:         uploadProcessFromDBV2,
			RunAsGoroutine: false,
		},
		{
			File:           "upload_servicestime.txt",
			Action:         uploadServicesFromDB,
			RunAsGoroutine: false,
		},
		{
			File:           "uploadpatchesfilestime.txt",
			Action:         processAndSendPatchResults,
			RunAsGoroutine: true, // Run it as a goroutine becuase it may take a long time or get stuck
		},
	}

	for _, task := range tasks {
		handleUploadTask(task)
	}

	if err := uploadAllSystemDataAndDetailsAsBulkCSV(); err != nil {
		log.Error().Err(err).Msg("Error in uploading group of data csv.")
	}

	log.Info().Msg("Successfully completed the process of inital full scanning system data and details")
}

func handleBenchmarkAndAuditResult() {
	ifOldBenchmark, err := processBenchmarkAndAuditResultV2()
	if err != nil {
		log.Error().Err(err).Msg("error in processBenchmarkAndAuditResultV2")
	}

	go processBenchmarkAndAuditResultForProducts()

	if ifOldBenchmark {
		processBenchmarkAndAuditResult()
	}

	if !isDeletedIIS {
		if err := processIISControlsV2(); err != nil {
			log.Error().Err(err).Msg("error in processIISControlsV2")
		}
	}

}

type UploadTask struct {
	File           string
	Action         func() error
	RunAsGoroutine bool
}

func handleUploadTask(task *UploadTask) {
	log.Info().Msg("Initiating handle upload task for " + task.File + " file")

	filePath := filepath.Join(CymetricxPath, "Time Files", task.File)

	ifElapsed, err := isDurationElapsedSinceLastUpdate(filePath, 5)
	if err != nil {
		log.Error().Err(err).Msg("error in isDurationElapsedSinceLastUpdate")
		return
	}

	if !ifElapsed {
		log.Info().Msg("Duration has not elapsed since last update for " + task.File + " file")
		return
	}

	if task.RunAsGoroutine {
		go task.Action()
	} else {
		if err := task.Action(); err != nil {
			log.Error().Err(err).Msgf("error in task action for %s", task.File)
			return
		}
	}

	createNowFileTimer(filePath)

	log.Info().Msg("Successfully handled upload task for " + task.File + " file")
}

// ! Need to explain this more in the future:
func decodeUTF16toUTF8(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("must have even length byte slice")
	}

	// u16s is a slice of unsigned 16-bit integers and length 1
	u16s := make([]uint16, 1)

	result := &bytes.Buffer{}

	b8buf := make([]byte, 4)

	bLength := len(b)
	for i := 0; i < bLength; i += 2 {
		u16s[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		r := utf16.Decode(u16s)
		n := utf8.EncodeRune(b8buf, r[0])
		result.Write(b8buf[:n])
	}

	return result.String(), nil
}

func uploadAuditToprocess(command string, ifCallLaravel bool) error {
	encodedCommand := b64.StdEncoding.EncodeToString([]byte(command))

	jsonPayload, err := createJsonPayloadV1(command)
	if err != nil {
		return fmt.Errorf("error in createJsonPayload: %w", err)
	}

	ifSame, err := checkIfHashFileSameOrUpdateIt("uploadAuditToprocess.txt", encodedCommand)
	if err != nil {
		return fmt.Errorf("error in checkIfHashFileSameOrUpdateIt: %w", err)
	}
	if ifSame {
		return fmt.Errorf("error in checkIfHashFileSameOrUpdateIt: %w", err)
	}

	gzipPath, err := createAndCompressPayloadIntoGZipFile(jsonPayload, "uploaddatatoprocess.gz")
	if err != nil {
		return fmt.Errorf("error in createAndCompressPayloadIntoGZipFile: %w", err)
	}

	if ifCallLaravel {
		responseBody, err := createAndExecuteFileUploadRequest("upload_benchmark_audit/"+id, gzipPath)
		if err != nil {
			return fmt.Errorf("error in uploading benchmarking audit results to the server: %w", err)
		}

		if err := readGeneralReponseBody(responseBody); err != nil {
			return fmt.Errorf("failed to upload benchmarking audit results to the server: %w", err)
		}
	} else {
		extraParams := map[string]string{"application/gz": "true"}

		if _, err := createAndExecuteUploadRequestV1(id+"/uploaddatatoprocess", extraParams, gzipPath); err != nil {
			return fmt.Errorf("error in createAndExecuteUploadRequest: %w", err)
		}
	}

	return nil
}

func getFireWallValue() (string, error) {
	script := strings.Join([]string{
		`Get-ItemProperty -Path`,
		`"HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"`,
		`-Name EnableFirewall`,
		`| Select-Object -ExpandProperty EnableFirewall`,
	}, " ")

	output, err := createAndRunPS1FileWithOutput("firewall.ps1", script)
	if err != nil {
		return "", fmt.Errorf("error in creating or running firewall.ps1: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

func getFirewallValueV2() (string, error) {
	// Open the registry key containing the firewall setting
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	// Read the EnableFirewall value
	value, _, err := key.GetIntegerValue("EnableFirewall")
	if err != nil {
		return "", fmt.Errorf("failed to get EnableFirewall value: %w", err)
	}

	// Convert the registry value to a string to match the old function signature
	return fmt.Sprintf("%d", value), nil
}

// ! What is this function??
func getsplunk() string {
	var getvalue_data = "N/A"
	return (string(getvalue_data))
}

func getKBUpdates() ([]string, error) {
	kbUpdatesSet := make(map[string]struct{}) // Use a set to ensure uniqueness
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	kbPattern := regexp.MustCompile(`KB\d+`)
	for _, name := range names {
		match := kbPattern.FindString(name)
		if match != "" {
			kbUpdatesSet[match] = struct{}{}
		}
	}

	// Convert the set to a slice
	kbUpdates := make([]string, 0, len(kbUpdatesSet))
	for kb := range kbUpdatesSet {
		kbUpdates = append(kbUpdates, kb)
	}

	return kbUpdates, nil
}

func getWOW6432NodeUpdates() ([]string, error) {
	updatesSet := make(map[string]struct{}) // Use a set to ensure uniqueness
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Updates`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	kbPattern := regexp.MustCompile(`KB\d+`) // Regular expression to match KB updates
	for _, name := range names {
		subKey, err := registry.OpenKey(key, name, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		subNames, err := subKey.ReadSubKeyNames(-1)
		subKey.Close()
		if err != nil {
			continue
		}
		for _, subName := range subNames {
			if kbPattern.MatchString(subName) { // Check if the subName matches the KB pattern
				updatesSet[subName] = struct{}{}
			}
		}
	}

	// Convert the set to a slice
	updates := make([]string, 0, len(updatesSet))
	for update := range updatesSet {
		updates = append(updates, update)
	}

	return updates, nil
}

type RawHotFix struct {
	Description string
	HotFixID    string
	InstalledBy string
	InstalledOn string // Keep as string for custom parsing
}

type HotFix struct {
	PSComputerName string `json:"PSComputerName"`
	Description    string `json:"Description"`
	HotFixID       string `json:"HotFixID"`
	InstalledBy    string `json:"InstalledBy"`
	InstalledOnObj struct {
		Value    string `json:"value"`
		DateTime string `json:"DateTime"`
	} `json:"InstalledOn"`
}

func getHotfixes() ([]HotFix, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	var rawHotfixes []RawHotFix
	if err := wmi.Query("SELECT Description, HotFixID, InstalledBy, InstalledOn FROM Win32_QuickFixEngineering", &rawHotfixes); err != nil {
		return nil, fmt.Errorf("failed to query Win32_QuickFixEngineering: %w", err)
	}

	hotFixes := make([]HotFix, len(rawHotfixes))
	for i, raw := range rawHotfixes {
		// Attempt to parse the InstalledOn date
		var parsedTime time.Time
		if raw.InstalledOn != "" {
			var parseErr error
			// Ensure the time is parsed in the local time zone
			parsedTime, parseErr = time.ParseInLocation("1/2/2006", raw.InstalledOn, time.Local)
			if parseErr != nil {
				log.Printf("Failed to parse date '%s': %v", raw.InstalledOn, parseErr)
				continue // Or handle the error as appropriate
			}
		}

		hotFixes[i] = HotFix{
			PSComputerName: hostname,
			Description:    raw.Description,
			HotFixID:       raw.HotFixID,
			InstalledBy:    raw.InstalledBy,
			InstalledOnObj: struct {
				Value    string `json:"value"`
				DateTime string `json:"DateTime"`
			}{
				Value:    fmt.Sprintf("/Date(%d)/", parsedTime.Unix()*1000), // Unix timestamp in milliseconds
				DateTime: parsedTime.Format("Monday, January 2, 2006 3:04:05 PM"),
			},
		}
	}

	return hotFixes, nil
}

func getInstalledWindowsUpdatesAndHotfixesV2() (string, error) {
	kbUpdates, err := getKBUpdates()
	if err != nil {
		return "", fmt.Errorf("failed to get KB updates: %w", err)
	}

	wow6432NodeUpdates, err := getWOW6432NodeUpdates()
	if err != nil {
		return "", fmt.Errorf("failed to get WOW6432Node updates: %w", err)
	}

	hotfixes, err := getHotfixes()
	if err != nil {
		return "", fmt.Errorf("failed to get hotfixes: %w", err)
	}

	results := map[string]interface{}{
		"KBUpdates":          kbUpdates,
		"WOW6432NodeUpdates": wow6432NodeUpdates,
		"HotFixes":           hotfixes,
	}

	jsonData, err := json.Marshal(results)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON for updates and hotfixes: %w", err)
	}

	return string(jsonData), nil
}

func getWindowsDisplayVersion() (string, error) {
	key_reg, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("error in registry.OpenKey: %w", err)
	}
	defer key_reg.Close()

	// Retrieve the value
	value, _, err := key_reg.GetStringValue("DisplayVersion")
	if err != nil {
		return "", fmt.Errorf("error in key_reg.GetStringValue: %w", err)
	}

	return value, nil
}

func getAllWindowsServicesStatus() (string, error) {

	script := `
	# Retrieve information about services and format it
	$ServiceInfoText = Get-Service | Format-List -Property DisplayName, Name, Status | Out-String

	# Define a regular expression pattern to match the lines containing service information
	$Pattern = "DisplayName\s*:\s*(?<DisplayName>.+)\s*Name\s*:\s*(?<Name>.+)\s*Status\s*:\s*(?<Status>.+)"

	# Extract matches from the text using the regular expression pattern
	$Matches = $ServiceInfoText | Select-String -Pattern $Pattern -AllMatches | ForEach-Object { $_.Matches }

	# Create custom objects from the extracted matches
	$ServiceInfoObjects = $Matches | ForEach-Object {
		[PSCustomObject]@{
			DisplayName = $_.Groups["DisplayName"].Value.Trim()
			Name = $_.Groups["Name"].Value.Trim()
			Status = $_.Groups["Status"].Value.Trim()
		}
	}

	# Convert the custom objects to minified JSON format
	# $ServiceInfoJson = $ServiceInfoObjects | ConvertTo-Json -Compress
	$ServiceInfoObjects | ConvertTo-Json -Compress

	# Specify the path to the output JSON file
	# $jsonFilePath = 'C:\Program Files\CYMETRICX\service_info.json'

	# Write the minified JSON data to the output file
	# $ServiceInfoJson | Out-File -FilePath $jsonFilePath -Encoding UTF8
	`

	// output, err := createAndRunPS1FileWithOutput("GetService.ps1", "Get-Service | Format-List -Property DisplayName,Name,Status")
	output, err := createAndRunPS1FileWithOutput("GetService.ps1", script)
	if err != nil {
		return "", fmt.Errorf("error in creating or running GetService.ps1: %w", err)
	}

	return string(output), nil
}

// This function has memory leakage becauase of external library used:
func getAllScheduledTasksInfoV2() (string, error) {
	ts, err := taskmaster.Connect()
	if err != nil {
		return "", fmt.Errorf("failed to connect to task scheduler: %w", err)
	}
	defer ts.Disconnect()

	tasks, err := ts.GetRegisteredTasks()
	if err != nil {
		return "", fmt.Errorf("failed to get registered tasks: %w", err)
	}
	defer tasks.Release()

	var simplifiedTasks []map[string]interface{}

	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}

	for _, task := range tasks {
		// Split the path to extract the TaskPath without the task name
		pathSegments := strings.Split(task.Path, "\\")
		taskPath := strings.Join(pathSegments[:len(pathSegments)-1], "\\")

		simplified := map[string]interface{}{
			"TaskName":       task.Name,
			"Author":         task.Definition.RegistrationInfo.Author,
			"State":          task.State,
			"LastRunTime":    task.LastRunTime.Format(time.RFC3339),
			"Description":    task.Definition.RegistrationInfo.Description,
			"URI":            task.Path,
			"TaskPath":       taskPath + "\\",
			"PSComputerName": hostname,
		}
		simplifiedTasks = append(simplifiedTasks, simplified)
	}

	// Convert to JSON
	jsonData, err := json.Marshal(simplifiedTasks)
	if err != nil {
		return "", fmt.Errorf("Ffiled to marshal data to JSON: %w", err)
	}

	return string(jsonData), nil
}

func getAllScheduledTasksInfo() (string, error) {

	// script := "Get-ScheduledTask | select TaskName,Author,State,date,Description,PSComputerName,URI,TaskPath,'####fortress####'"
	script := `
# Retrieve information about scheduled tasks and select specific properties
$ScheduledTasks = Get-ScheduledTask | Select-Object TaskName, Author, State, LastRunTime, Description, PSComputerName, URI, TaskPath

# Convert it to minified JSON format
$ScheduledTasks | ConvertTo-Json -Depth 10 -Compress

# Specify the path to the output JSON file
# $jsonFilePath = 'C:\Program Files\CYMETRICX\scheduled_tasks.json'

# Convert the scheduled tasks to minified JSON format and write it to the output file
# $ScheduledTasks | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $jsonFilePath -Encoding UTF8
	
	`
	output, err := createAndRunPS1FileWithOutput("getwinScheduledTask.ps1", script)
	if err != nil {
		return "", fmt.Errorf("error in creating or running getwinScheduledTask.ps1: %w", err)
	}

	return string(output), nil
}

func getSecureBootStatus() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	secureBootEnabled, _, err := key.GetIntegerValue("UEFISecureBootEnabled")
	if err != nil {
		return "", fmt.Errorf("failed to get Secure Boot state from registry: %w", err)
	}

	type SecureBoot struct {
		SecureBootEnabled bool `json:"secureBootEnabled"`
	}

	secureBoot := SecureBoot{
		SecureBootEnabled: secureBootEnabled == 1,
	}

	jsonPayload, err := json.Marshal(secureBoot)
	if err != nil {
		return "", fmt.Errorf("error in json.Marshal: %w", err)
	}

	return string(jsonPayload), nil
}

func getNetworkInterfaceInfo() (string, error) {
	script := `
	# Get network interface configurations
	$NetIPConfigurations = Get-NetIPConfiguration -All

	# Get network interfaces
	$NetIPInterfaces = Get-NetIPInterface

	# Get network adapters for additional properties like InterfaceDescription
	$NetAdapters = Get-NetAdapter

	# Combine information from both commands
	$CombinedInfo = foreach ($interface in $NetIPInterfaces) {
		$config = $NetIPConfigurations | Where-Object { $_.InterfaceIndex -eq $interface.ifIndex }
		$adapter = $NetAdapters | Where-Object { $_.InterfaceIndex -eq $interface.ifIndex }
		
		# Extracting IPv4 and IPv6 addresses
		$IPv4Address = $config.IPv4Address.IPAddress
		$IPv6Address = $config.IPv6Address.IPAddress
		$IPv4Gateway = $config.IPv4DefaultGateway.NextHop
		$IPv6Gateway = $config.IPv6DefaultGateway.NextHop
		$DNSServer = $config.DNSServer.ServerAddresses -join ','
	$Status = if ($adapter.Status -eq 'Up' -and $adapter.LinkSpeed -ne '0 bps' -and $adapter.LinkSpeed -ne $null) { 'Connected' } else { 'Disconnected' }
		$SubnetMask = if ($config.IPv4Address) { Convert-PrefixLengthToSubnetMask -PrefixLength $config.IPv4Address.PrefixLength } else { $null }
		$SubnetMask = $config.IPv4Address.PrefixLength

	$PolicyStoreValue = $interface.Store
		[PSCustomObject]@{
			InterfaceIndex = $interface.ifIndex
			InterfaceAlias = $interface.InterfaceAlias
			AddressFamily = $interface.AddressFamily
			NlMtu = $interface.NlMtu
			InterfaceMetric = $interface.InterfaceMetric
			Dhcp = $interface.Dhcp
			ConnectionState = $Status
			PolicyStore = $PolicyStoreValue
			InterfaceDescription = $adapter.InterfaceDescription
			IPv4Address = $IPv4Address
			IPv6DefaultGateway = $IPv6Gateway
			IPv4DefaultGateway = $IPv4Gateway
			DNSServer = $DNSServer
			SubnetMask = $SubnetMask
		}
	}
	$CombinedInfo | ConvertTo-Json -Depth 5 -Compress
	#$jsonOutput = $CombinedInfo | ConvertTo-Json -Depth 5 -Compress

	# Optionally, you can export this information to a JSON file
	# $jsonOutput | Out-File -FilePath "C:\Program Files\CYMETRICX\net_ip_info.json" -Encoding UTF8
	`

	output, err := createAndRunPS1FileWithOutput("getnetworkinterface.ps1", script)
	if err != nil {
		return "", fmt.Errorf("error in creating or running getnetworkinterface.ps1: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func getProxySettingsV2() (string, error) {
	// Open the registry key containing the Internet Settings
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("error opening registry key: %w", err)
	}
	defer key.Close()

	// Structure to hold the proxy settings
	proxySettings := struct {
		ProxyServerIP   *string `json:"proxyServerIP"`
		ProxyServerPort *string `json:"proxyServerPort"`
		EnableHttp      *uint64 `json:"enableHttp"`
		ProxyEnabled    *uint64 `json:"proxyEnabled"`
		AutoConfigure   *uint64 `json:"autoConfigure"`
	}{}

	// Helper function to read string values safely
	readString := func(key registry.Key, name string) *string {
		val, _, err := key.GetStringValue(name)
		if err != nil {
			return nil
		}
		return &val
	}

	// Helper function to read DWORD (uint32) values safely, converting them to uint64 for consistency in JSON
	readDWORD := func(key registry.Key, name string) *uint64 {
		val, _, err := key.GetIntegerValue(name)
		if err != nil {
			return nil
		}
		val64 := uint64(val) // Convert uint32 to uint64
		return &val64
	}

	// Read the values from the registry
	proxySettings.ProxyServerIP = readString(key, "ProxyServer")
	// Note: ProxyServerPort is not a standard key. You would typically parse it from ProxyServer if needed.
	proxySettings.ProxyEnabled = readDWORD(key, "ProxyEnable")
	proxySettings.AutoConfigure = readDWORD(key, "AutoConfigURL")

	// Convert the struct to JSON
	jsonOutput, err := json.Marshal(proxySettings)
	if err != nil {
		return "", fmt.Errorf("error marshalling JSON: %w", err)
	}

	return string(jsonOutput), nil
}

func retrieveComputerInfo() (string, error) {
	filePath := filepath.Join(CymetricxPath, "computer_info.csv")

	//% This one retrieve more than 180 keys, so to turn it into pure go, we would need to look for them one by one
	//% or decied which ones are needed for cymetricx and then retrieve them one by one.
	script := fmt.Sprintf(`Get-ComputerInfo | Export-CSV '%s' -Encoding UTF8`, filePath)
	if err := createAndRunPS1FileWithoutOutput("getcomputerinfo.ps1", script); err != nil {
		return "", fmt.Errorf("error in creating or running getcomputerinfo.bat: %w", err)
	}

	return filePath, nil
}

func getTPMInfo() (string, error) {
	filePath := filepath.Join(CymetricxPath, "tpm_info.csv")

	script := fmt.Sprintf(`Get-Tpm | Export-CSV -Path '%s' -NoTypeInformation -Encoding UTF8`, filePath)
	if err := createAndRunPS1FileWithoutOutput("tpm_win.ps1", script); err != nil {
		return "", fmt.Errorf("error in creating or running tpm_win.bat: %w", err)
	}

	return filePath, nil

}

func getBitLockerInfo() (string, error) {
	filePath := filepath.Join(CymetricxPath, "bitlocker.csv")

	script := fmt.Sprintf(`Get-BitLockerVolume |  Export-CSV -Path '%s' -NoTypeInformation -Encoding UTF8`, filePath)
	if err := createAndRunPS1FileWithoutOutput("get_bitlocker.ps1", script); err != nil {
		return "", fmt.Errorf("error in creating or running get_bitlocker.bat: %w", err)
	}

	return filePath, nil
}

func getRDPStatusV2() (string, error) {
	// Open the registry key containing the fDenyTSConnections value
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("error opening registry key: %w", err)
	}
	defer key.Close()

	// Read the value of fDenyTSConnections
	fDenyTSConnections, _, err := key.GetIntegerValue("fDenyTSConnections")
	if err != nil {
		return "", fmt.Errorf("error reading fDenyTSConnections: %w", err)
	}

	// Create a map to hold the output structure
	output := map[string]uint64{"fDenyTSConnections": fDenyTSConnections}

	// Convert the output to JSON
	jsonOutput, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("error marshalling JSON: %w", err)
	}

	return string(jsonOutput), nil
}

func getStartupCommands2() (string, error) {
	script := `
		# Build a mapping of startup item names to their status
		$StartupApprovedPaths = @(
			"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
			"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
		)

		$StatusMap = @{}

		foreach ($Path in $StartupApprovedPaths) {
			try {
				$Items = Get-ItemProperty -Path $Path
				foreach ($Property in $Items.PSObject.Properties) {
					if ($Property.Name -notlike "PS*") {
						$Value = $Property.Value
						$Status = switch ($Value[0]) {
							2 { "Enabled" }
							3 { "Disabled" }
							6 { "Enabled" }
							Default { "Unknown" }
						}

						# Use the Name as the key
						$Key = $Property.Name

						# Add to the hashtable
						$StatusMap[$Key] = $Status

						# If the key ends with '.lnk', add another entry without '.lnk'
						if ($Key -like '*.lnk') {
							$KeyWithoutLnk = $Key -replace '\.lnk$', ''
							if (-not $StatusMap.ContainsKey($KeyWithoutLnk)) {
								$StatusMap[$KeyWithoutLnk] = $Status
							}
						}
					}
				}
			} catch {
				# Ignore errors (e.g., if the registry path doesn't exist)
			}
		}

		# Get information about Win32_StartupCommand and add Status
		$StartupCommands = Get-CimInstance -ClassName Win32_StartupCommand |
			Select-Object Caption, Description, SettingID, Command, Location, Name, User, UserSID, PSComputerName, CimClass |
			ForEach-Object {
				$LookupName = $_.Name

				# Attempt to find the status directly
				if ($StatusMap.ContainsKey($LookupName)) {
					$Status = $StatusMap[$LookupName]
				} else {
					# Try appending '.lnk' to the name
					$LookupNameWithLnk = $LookupName + '.lnk'
					if ($StatusMap.ContainsKey($LookupNameWithLnk)) {
						$Status = $StatusMap[$LookupNameWithLnk]
					} else {
						$Status = "Unknown"
					}
				}

				$_ | Add-Member -NotePropertyName 'Status' -NotePropertyValue $Status -Force
				$_
			}

		# Convert the information to JSON format
		$StartupCommands | ConvertTo-Json -Depth 2 -Compress

	`
	output, err := createAndRunPS1FileWithOutput("startup.ps1", script)
	if err != nil {
		return "", fmt.Errorf("error in creating or running startup.bat: %w", err)
	}

	return string(output), nil
}

func getNetworkShares() (string, error) {
	log.Info().Msg("initiating getting network shares...")

	netCommandPath := getNetCommandPath()
	script := fmt.Sprintf(`"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; %s share"`, netCommandPath)
	output, err := createAndRunBatScriptWithOutput("netshare.bat", powerShellPath+" "+script)
	if err != nil {
		return "", fmt.Errorf("error in creating or running netshare.bat: %w", err)
	}

	log.Info().Msg("successfully got network shares")
	return string(output), nil
}

func getNetworkSharesV2() (string, error) {
	shares, err := NetShareEnum("", 2) // Use level 2 to get SHARE_INFO_2 structure
	if err != nil {
		return "", fmt.Errorf("error in NetShareEnum: %w", err)
	}

	result, err := formatShares(shares)
	if err != nil {
		return "", fmt.Errorf("error in formatShares: %w", err)
	}

	return result, nil

}

type SHARE_INFO_2 struct {
	Netname     *uint16
	Type        uint32
	Remark      *uint16
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        *uint16
	Passwd      *uint16
}

func utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	return syscall.UTF16ToString((*[1 << 29]uint16)(unsafe.Pointer(ptr))[:])
}

func convertToShareInfo2(bufptr uintptr, entriesread uint32) []SHARE_INFO_2 {
	shares := make([]SHARE_INFO_2, entriesread)
	shareArrayPtr := (*[1 << 20]SHARE_INFO_2)(unsafe.Pointer(bufptr))[:entriesread:entriesread]

	for i, share := range shareArrayPtr {
		shares[i] = SHARE_INFO_2{
			Netname:     share.Netname,
			Type:        share.Type,
			Remark:      share.Remark,
			Permissions: share.Permissions,
			MaxUses:     share.MaxUses,
			CurrentUses: share.CurrentUses,
			Path:        share.Path,
			Passwd:      share.Passwd,
		}
	}
	return shares
}

func NetShareEnum(serverName string, level uint32) ([]SHARE_INFO_2, error) {
	modnetapi32 := windows.NewLazySystemDLL("Netapi32.dll")
	procNetShareEnum := modnetapi32.NewProc("NetShareEnum")

	var (
		bufptr        uintptr
		entriesread   uint32
		totalentries  uint32
		resume_handle uint32
	)
	serverNamePtr, err := syscall.UTF16PtrFromString(serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to convert server name to UTF-16: %w", err)
	}

	ret, _, _ := procNetShareEnum.Call(
		uintptr(unsafe.Pointer(serverNamePtr)),
		uintptr(level),
		uintptr(unsafe.Pointer(&bufptr)),
		0xFFFFFFFF,
		uintptr(unsafe.Pointer(&entriesread)),
		uintptr(unsafe.Pointer(&totalentries)),
		uintptr(unsafe.Pointer(&resume_handle)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("NetShareEnum call failed with error: %s", syscall.Errno(ret))
	}
	defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(bufptr)))

	return convertToShareInfo2(bufptr, entriesread), nil
}

func formatShares(shares []SHARE_INFO_2) (string, error) {
	var builder strings.Builder

	builder.WriteString("Share name   Resource                        Remark\n")
	builder.WriteString("-------------------------------------------------------------------------------\n")

	for _, share := range shares {
		netname := utf16PtrToString(share.Netname)
		path := utf16PtrToString(share.Path)
		remark := utf16PtrToString(share.Remark)
		_, err := fmt.Fprintf(&builder, "%-12s %-30s %-10s\n", netname, path, remark)
		if err != nil {
			return "", fmt.Errorf("failed to write to string builder: %w", err)
		}
	}

	return builder.String(), nil
}

type AnyDeskConnection struct {
	ConnectionType string  `json:"connectionType"`
	DateConnection *string `json:"dateConnection"`
	ApprovedBy     string  `json:"approvedBy"`
	SrcID          string  `json:"srcID"`
	DestID         string  `json:"destID"`
}

func getAnyDeskConnectionTrace() (string, error) {
	filePath := filepath.Join(`C:\`, "ProgramData", "AnyDesk", "connection_trace.txt")
	dataUTF16, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error in reading connection_trace.txt file: %w", err)
	}

	data, err := decodeUTF16toUTF8(dataUTF16)
	if err != nil {
		return "", fmt.Errorf("error in decoding connection trace data from UTF16 to UTF8: %w", err)
	}

	var connections []AnyDeskConnection

	// lines := strings.Split(string(data), "\n")
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)

		var connection AnyDeskConnection
		if len(fields) == 6 {
			date := strings.Replace(fields[1], ",", "", 1)
			time := fields[2]
			dateTime := date + " " + time
			connection = AnyDeskConnection{
				ConnectionType: fields[0],
				DateConnection: &dateTime,
				ApprovedBy:     fields[3],
				SrcID:          fields[4],
				DestID:         fields[5],
			}
		} else if len(fields) == 4 {
			// No date and time is available
			connection = AnyDeskConnection{
				ConnectionType: fields[0],
				ApprovedBy:     fields[1],
				SrcID:          fields[2],
				DestID:         fields[3],
			}
		}

		connections = append(connections, connection)
	}

	jsonPayload, err := json.Marshal(connections)
	if err != nil {
		return "", fmt.Errorf("error in marshalling any desk connections: %w", err)
	}

	return string(jsonPayload), nil
}

func getChromeExtentions() (string, error) {
	if err := prepareAndExecuteDownloadHTTPRequestWithTokenValidityV2("getConfig/"+id+"/chrome", "ChromeExtensionRTRScript.ps1", 10); err != nil {
		return "", fmt.Errorf("error in getting configurations: %w", err)
	}

	ps1FilePath := filepath.Join(CymetricxPath, "ChromeExtensionRTRScript.ps1")

	if err := runPS1FileWithoutOutput(ps1FilePath); err != nil {
		return "", err
	}

	filePath := filepath.Join(CymetricxPath, "chrome_report.csv")
	newFIlePath := filepath.Join(CymetricxPath, "chrome_extension.csv")

	// rename the file to chrome_extension.csv
	if err := os.Rename(filePath, newFIlePath); err != nil {
		return filePath, nil
	}

	return newFIlePath, nil
}

//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
//@----------------------------------------------------------------------------------------------------------------------------------------------------
// @ NEW LARAVEL VERSION:

// getAndUploadComputerUpTimeV2 retrieves the computer uptime,
// and uploads it to the server.
func getAndUploadComputerUpTimeV2() error {
	log.Info().Msg("Starting the process of compressing and uploading computer uptime.")

	upTime, err := getComputerUpTime2()
	if err != nil {
		return fmt.Errorf("error in getComputerUpTime: %w", err)
	}

	jsonPayload, err := createUpTimeJsonPayload(upTime)
	if err != nil {
		return fmt.Errorf("error in createUpTimeJsonPayload: %w", err)
	}

	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("POST", "upload_uptime/"+id, jsonPayload, 10)
	if err != nil {
		return fmt.Errorf("error in prepareAndExecuteUploadUpTimeHTTPRequest: %w", err)
	}

	var apiResponse ApiUpTimeResponse

	if err := json.Unmarshal(responseBody.Bytes(), &apiResponse); err != nil {
		return fmt.Errorf("error in unmarshalling response body: %w", err)
	}

	if !apiResponse.Status {
		return fmt.Errorf("error in uploading computer uptime: %s", apiResponse.Message)
	}

	log.Info().Msg("Successfully uploaded computer uptime.")
	return nil
}

func getComputerUpTime() (string, error) {
	script := []string{"(get-date)", "-", "(gcim Win32_OperatingSystem).LastBootUpTime"}
	computerUpTime, err := execCommandWithOutput(powerShellPath, script...)
	if err != nil {
		return "", fmt.Errorf("error in exec.Command: %w", err)
	}

	// Keep this like this to give a certain format
	string1 := strings.Replace(string(computerUpTime), "\n", "##", -1)
	string2 := strings.Replace(string1, "\r", "##", -1)
	string3 := strings.Replace(string2, " ", "", -1)
	string4 := strings.Replace(string3, "##", "#", -1)
	string5 := strings.Replace(string4, "##", "#", -1)
	string6 := strings.Replace(string5, "##", "#", -1)
	string7 := strings.Replace(string6, "##", "#", -1)

	return string7, nil
}

func getComputerUpTime2() (string, error) {
	// Get tick count since boot in milliseconds
	tickCount := getTickCount64()
	// Convert milliseconds to duration
	upTime := time.Duration(tickCount) * time.Millisecond

	// Breaking down the duration
	days := int(upTime.Hours()) / 24
	hours := int(upTime.Hours()) % 24
	minutes := int(upTime.Minutes()) % 60
	seconds := int(upTime.Seconds()) % 60
	milliseconds := int(upTime.Milliseconds()) % 1000

	// Formatted string based on the output you provided
	result := fmt.Sprintf("#Days:%d#Hours:%d#Minutes:%d#Seconds:%d#Milliseconds:%d#Ticks:%d#TotalDays:%f#TotalHours:%f#TotalMinutes:%f#TotalSeconds:%f#TotalMilliseconds:%f#",
		days, hours, minutes, seconds, milliseconds,
		upTime.Nanoseconds()/100,
		upTime.Hours()/24,
		upTime.Hours(),
		upTime.Minutes(),
		upTime.Seconds(),
		float64(upTime.Milliseconds()),
	)

	return result, nil
}
func getTickCount64() uint64 {
	var (
		kernel32           = syscall.NewLazyDLL("kernel32.dll")
		procGetTickCount64 = kernel32.NewProc("GetTickCount64")
	)

	ret, _, _ := procGetTickCount64.Call()
	return uint64(ret)
}

// checkIfHashFileSameOrUpdateIt checks if a hash file exists. If not, it
// creates one and returns true. If it exists, it compares the previous hash
// value with the new one. If they match, it returns true.
func checkIfHashFileSameOrUpdateIt(hashFileName string, data string) (bool, error) {
	log.Info().Str("HashFileName", hashFileName).Msg("Checking hash file or updating it if required.")

	hashFilePath := filepath.Join(CymetricxPath, "Hash Files", hashFileName)

	encodedDataHex, err := getHexHash(data)
	if err != nil {
		return true, fmt.Errorf("failed to calculate hash value of the encoded data in hex value: %w", err)
	}

	if !fileExists(hashFilePath) {
		log.Info().Str("Hash File Name", hashFileName).Msg("Hash file does not exist. Creating a new hash file.")

		err := createFileWithPermissionsAndWriteToIt(hashFilePath, encodedDataHex, 0644)
		if err != nil {
			return true, fmt.Errorf("failed to create/write to hash file name: %s, because of error: %w", hashFileName, err)
		}
		return false, nil
	}

	matches, err := checkIfPreviousHashFileMatches(hashFileName, hashFilePath, encodedDataHex)
	if err != nil {
		return true, fmt.Errorf("failed to check if previous hash file matches: %w", err)
	}

	if matches {
		log.Info().Str("Hash File Name", hashFileName).Msg("Hash matches with the previous hash file for the encoded data.")
		return true, nil
	}

	log.Info().Msg("Hash does not match with the previous hash file.")
	return false, nil
}

// getHexHash computes the hexadecimal hash of the given data.
func getHexHash(data string) (string, error) {

	// Create a new md5 hasher object.
	md5Hasher := md5.New()

	// feed the data into the hasher object, which processes it in preparation
	// for hashing
	_, err := md5Hasher.Write([]byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to write encoded data to md5 hasher: %w", err)
	}

	// compute the MD5 hash of the data that has been written to the hasher
	// The hased output is 128 bits long (16 bytes).
	hashedValue := md5Hasher.Sum(nil)

	// encode the byte slice into a string, where each byte is represented
	// by two hexadecimal characters.
	// Ex: []byte{72} in decimal -> "48" in hexadecimal which stands for "H"
	// in ASCII.
	// Or []byte{1} in decimal -> "01" in hexadecimal.
	encodedDataHex := hex.EncodeToString(hashedValue)

	// Returns 32 hexadecimal characters.
	return encodedDataHex, nil
}

// createFileWithPermissionsAndWriteToIt creates a new file with the specified content and
// permissions not adhering to the system's umask. It takes the full path of the
// file to be created, the content to write to the file, and the permissions to
// set for the new file. The permissions should be specified in octal format e.g. 0644.
//
// Example Usage:
//
//	createFileWithPermissionsAndWriteToIt("test.txt", "Hello, world!", 0644)
func createFileWithPermissionsAndWriteToIt(filePath, fileContent string, permissions os.FileMode) error {
	if err := os.WriteFile(filePath, []byte(fileContent), permissions); err != nil {
		return fmt.Errorf("error writing to file %s: %w", filePath, err)
	}

	// Set the file permissions using the os.Chmod function in case of umask
	// exiting and messing up the permissions
	if err := os.Chmod(filePath, permissions); err != nil {
		return fmt.Errorf("error setting file permissions for file %s: %w", filePath, err)
	}

	return nil
}

// createFileWithPermissionsAndWriteToIt creates a new file with the specified content and
// permissions not adhering to the system's umask. It takes the full path of the
// file to be created, the content to write to the file, and the permissions to
// set for the new file. The permissions should be specified in octal format e.g. 0644.
//
// Example Usage:
//
//	createFileWithPermissionsAndWriteToIt("test.txt", "Hello, world!", 0644)
func createFileWithPermissionsAndWriteToItRaw(filePath string, fileContent []byte, permissions os.FileMode) error {
	if err := os.WriteFile(filePath, fileContent, permissions); err != nil {
		return fmt.Errorf("error writing to file %s: %w", filePath, err)
	}

	// Set the file permissions using the os.Chmod function in case of umask
	// exiting and messing up the permissions
	if err := os.Chmod(filePath, permissions); err != nil {
		return fmt.Errorf("error setting file permissions for file %s: %w", filePath, err)
	}

	return nil
}

// sleepForRandomDelayDuration sleeps for a random duration between minSleepTime
// and maxSleepTime seconds, inclusive of minSleepTime and exclusive of maxSleepTime.
// The resulting sleep duration is computed by generating a random number within the
// range of 0 to (maxSleepTime-minSleepTime-1), which is then added to minSleepTime.
// For example, if minSleepTime is 10 and maxSleepTime is 60, the function will sleep
// for a random duration between 10 and 59 seconds.
func sleepForRandomDelayDuration(minSleepTime, maxSleepTime int) {
	randomSleepTime := getRandomSleepTime(maxSleepTime, minSleepTime)
	time.Sleep(time.Duration(randomSleepTime) * time.Second)
}

// sleepForRandomDelayDuration sleeps for a random duration between minSleepTime
// and maxSleepTime seconds, inclusive of minSleepTime and exclusive of maxSleepTime.
// The resulting sleep duration is computed by generating a random number within the
// range of 0 to (maxSleepTime-minSleepTime-1), which is then added to minSleepTime.
// For example, if minSleepTime is 10 and maxSleepTime is 60, the function will sleep
// for a random duration between 10 and 59 seconds.
func sleepForRandomDelayDurationInMinutes(minSleepTime, maxSleepTime int) {
	randomSleepTime := getRandomSleepTime(maxSleepTime, minSleepTime)
	time.Sleep(time.Duration(randomSleepTime) * time.Minute)
}

func getRandomSleepTime(maxSleepTime int, minSleepTime int) int {
	seed := time.Now().UnixNano()
	randInstance := mRand.New(mRand.NewSource(seed))
	randomSleepTime := randInstance.Intn(maxSleepTime-minSleepTime) + minSleepTime
	return randomSleepTime
}

type UpTimePayload struct {
	UpTime string `json:"uptime"`
}

func createUpTimeJsonPayload(upTime string) ([]byte, error) {
	// func createUpTimeJsonPayload(upTime string) (UpTimePayload, error) {
	passwordPolicyStruct := UpTimePayload{
		UpTime: upTime,
	}

	data, err := json.Marshal(passwordPolicyStruct)
	if err != nil {
		return nil, fmt.Errorf("error in marshalling password policy: %w", err)
	}

	return data, nil
	// return passwordPolicyStruct, nil
}

func prepareAndExecuteHTTPRequestWithTokenValidityForWindowsV2(httpMethod, apiEndpoint string, jsonPayload []byte, retries int) (bytes.Buffer, error) {
	// Create HTTP Request with Timeout
	req, cancel, err := createHTTPRequestWithTimeoutForWindowsV2(httpMethod, apiEndpoint, jsonPayload)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer cancel()

	// Execute HTTP Request
	responseBody, err := executeHTTPRequestWithTokenValidtyV2(req, retries)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error sending %s request to %s: %w", req.Method, req.URL.Path, err)
	}

	return responseBody, nil
}

// createHTTPRequestWithTimeout creates a new HTTP request method to the specified endpoint
// with a 5 minute timeout.
// It returns the created HTTP request object, the context for handling request timeout,
// and the function to cancel the context responsible for handling the request timeout.
func createHTTPRequestWithTimeoutForWindowsV2(httpMethod string, endPoint string, jsonPayload []byte) (*http.Request, context.CancelFunc, error) {

	req, err := createHttpRequestForWindowsV2(httpMethod, endPoint, jsonPayload, "application/json")
	if err != nil {
		return nil, nil, err
	}

	// Implement a 5-minute timeout for requests to prevent indefinite hanging.
	// A duration of 5 minutes is chosen as some requests, particularly uploads,
	// can take a substantial amount of time to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	// TODO: This needs more testing to see how it performs and acts when actually combined
	// TODO: with the timeout above.
	req = req.WithContext(ctx)

	return req, cancel, nil
}

func createHttpRequestForWindowsV2(httpMethod string, endPoint string, jsonPayload []byte, MIMEType string) (*http.Request, error) {
	// req, err := http.NewRequest(httpMethod, apiURLFlask+"api/"+endPoint, nil)
	req, err := http.NewRequest(httpMethod, apiURLLaravel+"api/windows/"+endPoint, nil)
	if err != nil {
		return nil, err
	}

	if httpMethod != "GET" {
		// The payload is only set for None GET requests and it's given the no operation closer so it does not close the body as it's unnecessary
		req.Body = io.NopCloser(bytes.NewBuffer(jsonPayload))
		req.Header.Set("Content-Type", MIMEType)
	}
	req.Header.Set("Accept", "application/json")

	return req, nil
}

func prepareAndExecuteHTTPRequestWithTokenValidityV2(httpMethod, apiEndpoint string, jsonPayload []byte, retries int) (bytes.Buffer, error) {
	// Create HTTP Request with Timeout
	req, cancel, err := createHTTPRequestWithTimeoutV2(httpMethod, apiEndpoint, jsonPayload)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer cancel()

	// Execute HTTP Request
	responseBody, err := executeHTTPRequestWithTokenValidtyV2(req, retries)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error sending %s request to %s: %w", req.Method, req.URL, err)
	}

	return responseBody, nil
}

// func prepareAndExecuteHTTPRequestWithTokenValidityNopCloserV2(httpMethod, apiEndpoint string, jsonPayload io.ReadCloser, retries int) (bytes.Buffer, error) {
// 	// Create HTTP Request with Timeout
// 	req, cancel, err := createHTTPRequestWithTimeoutV2(httpMethod, apiEndpoint, jsonPayload)
// 	if err != nil {
// 		return bytes.Buffer{}, err
// 	}
// 	defer cancel()

// 	// Execute HTTP Request
// 	responseBody, err := executeHTTPRequestWithTokenValidtyV2(req, retries)
// 	if err != nil {
// 		return bytes.Buffer{}, fmt.Errorf("error sending %s request to %s: %w", req.Method, req.URL, err)
// 	}

// 	return responseBody, nil
// }

func prepareAndExecuteDownloadHTTPRequestWithTokenValidityV2(apiEndpoint, newFileName string, retries int) error {

	newFilePath := filepath.Join(CymetricxPath, newFileName)
	// Create the file that the data will be downloaded to
	file, err := createFileWithPermissions(newFilePath, 0744)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	// Create HTTP Request with Timeout
	req, cancel, err := createHTTPRequestWithTimeoutV2("GET", apiEndpoint, nil)
	if err != nil {
		return err
	}
	defer cancel()

	// Execute HTTP Request
	_, err = executeDownloadHTTPRequestWithTokenValidtyV2(req, file, retries)
	if err != nil {
		return fmt.Errorf("error sending %s request to %s: %w", req.Method, req.URL, err)
	}

	return nil
}

// executeHTTPRequestWithTokenValidtyV2 excutes the file upload request provided
// in the req parameter using the HTTP client provided in the client parameter.
// It retries the request up to 10 times if it fails or the response status code
// is not 200. It also checks if the token is valid, if not, it updates the token.
// The retries are set to 10 times.
func executeDownloadHTTPRequestWithTokenValidtyV2(req *http.Request, file *os.File, retries int) (bytes.Buffer, error) {
	req.Header.Set("Authorization", "Bearer"+authenticationTokenV2)

	responseBody, err := excuteDownloadAndWriteToFileV2(req, file, retries)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to execute %s request to %s, %w", req.Method, req.URL, err)
	}

	// TODO: Double check if this is actually being checked.
	if err := handleTokenValidityForDownloadV2(responseBody, file, req); err != nil {
		return bytes.Buffer{}, err
	}

	log.Info().Msgf("Successfully executed %s request to %s with token validity.", req.Method, req.URL)
	return responseBody, nil
}

func handleTokenValidityForDownloadV2(responseBody bytes.Buffer, file *os.File, req *http.Request) error {
	isValid, err := checkTokenValidityAndUpdateHeaderV2(responseBody, req)
	if err != nil {
		return fmt.Errorf("failed to check token validity in URL Path: %s, because of error: %w", req.URL, err)
	}

	// If the token is valid, then return.
	if isValid {
		return nil
	}

	// If the token is not valid, then retry the upload request after updating
	// the header of authorization with the new token.
	if _, err := executeDownloadHTTPRequestWithTokenValidtyV2(req, file, 10); err != nil {
		return fmt.Errorf("failed to excute HTTP request after re-authentication in URL Path: %s, because of error: %w", req.URL, err)
	}

	return nil
}

// executeHTTPRequest executes the HTTP request and returns the
// response body as bytes.Buffer. It takes the request, client, and
// number of retries as parameters. If retries is <1, it retries the
// request forever. Otherwise, it retries the request up to the given
// number of retries.
func excuteDownloadAndWriteToFileV2(req *http.Request, file *os.File, retries int) (bytes.Buffer, error) {
	log.Info().Msgf("Starting excuting %s request to %s ...", req.Method, req.URL)

	resp, cancel, err := sendRequestWithRetriesV2(req, retries)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer resp.Body.Close()
	defer cancel()

	if resp.StatusCode == http.StatusNotFound {
		return bytes.Buffer{}, fmt.Errorf("this %s request to %s was not found 404, %w", req.Method, req.URL, err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// Create a response body with the word "unauthenticated"
		responseBody := []byte("Unauthenticated")
		return *bytes.NewBuffer(responseBody), nil
	}

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error reading response body from %s: %w", req.URL, err)
	}

	log.Info().Msgf("Successfully excuted %s request to download %s from %s.", req.Method, file.Name(), req.URL)

	return bytes.Buffer{}, nil
}

func prepareAndExecuteHTTPRequestWithTokenValidityV1(httpMethod, apiEndpoint string, jsonPayload []byte, retries int) (bytes.Buffer, error) {
	// Create HTTP Request with Timeout
	req, cancel, err := createHTTPRequestWithTimeoutV1(httpMethod, apiEndpoint, jsonPayload)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer cancel()

	// Execute HTTP Request
	responseBody, err := executeHTTPRequestWithTokenValidtyV1(req, retries)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error sending %s request to %s: %w", req.Method, req.URL, err)
	}

	return responseBody, nil
}

// createHTTPRequestWithTimeout generates the HTTP request and adds a context timeout
func createHTTPRequestWithTimeoutV2(httpMethod string, endPoint string, jsonPayload []byte) (*http.Request, context.CancelFunc, error) {

	req, err := createHttpRequestV2(httpMethod, endPoint, jsonPayload, "application/json")
	if err != nil {
		log.Error().Err(err).Str("EndPoint", endPoint).Msg("Failed to create HTTP request.")
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)

	// TODO: This needs more testing to see how it performs and acts when actually combined
	// TODO: with the timeout above.
	req = req.WithContext(ctx)

	return req, cancel, nil
}

// createHTTPRequestWithTimeout generates the HTTP request and adds a context timeout
// func createHTTPRequestWithTimeoutNopCloserV2(httpMethod string, endPoint string, jsonPayload io.ReadCloser) (*http.Request, context.CancelFunc, error) {

// 	req, err := createHttpRequestV2(httpMethod, endPoint, jsonPayload, "application/json")
// 	if err != nil {
// 		log.Error().Err(err).Str("EndPoint", endPoint).Msg("Failed to create HTTP request.")
// 		return nil, nil, err
// 	}

// 	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)

// 	// TODO: This needs more testing to see how it performs and acts when actually combined
// 	// TODO: with the timeout above.
// 	req = req.WithContext(ctx)

// 	return req, cancel, nil
// }

func createHTTPRequestWithTimeoutForContentTypeV2(httpMethod string, endPoint string, jsonPayload []byte) (*http.Request, context.CancelFunc, error) {

	req, err := createHttpRequestForContentTypeV2(httpMethod, endPoint, jsonPayload, "application/json")
	if err != nil {
		log.Error().Err(err).Str("EndPoint", endPoint).Msg("Failed to create HTTP request.")
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)

	// TODO: This needs more testing to see how it performs and acts when actually combined
	// TODO: with the timeout above.
	req = req.WithContext(ctx)

	return req, cancel, nil
}

// createHTTPRequestWithTimeout generates the HTTP request and adds a context timeout
func createHTTPRequestWithTimeoutV1(httpMethod string, endPoint string, jsonPayload []byte) (*http.Request, context.CancelFunc, error) {

	req, err := createHttpRequestV1(httpMethod, endPoint, jsonPayload, "application/json")
	if err != nil {
		log.Error().Err(err).Str("EndPoint", endPoint).Msg("Failed to create HTTP request.")
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)

	// TODO: This needs more testing to see how it performs and acts when actually combined
	// TODO: with the timeout above.
	req = req.WithContext(ctx)

	return req, cancel, nil
}

// createHttpRequest creates the http request for a specific endpoint and sets the headers.
func createHttpRequestOriginalV2(httpMethod string, endPoint string, jsonPayload []byte, MIMEType string) (*http.Request, error) {
	// req, err := http.NewRequest(httpMethod, apiURLFlask+"api/"+endPoint, nil)
	req, err := http.NewRequest(httpMethod, apiURLLaravel+"api/"+endPoint, nil)
	if err != nil {
		return nil, err
	}

	if httpMethod != "GET" {
		// The payload is only set for None GET requests and it's given the no operation closer so it does not close the body as it's unnecessary
		req.Body = io.NopCloser(bytes.NewBuffer(jsonPayload))
		// req.Body = io.NopCloser(bytes.NewReader(jsonPayload))
		req.Header.Set("Content-Type", MIMEType)
	}
	req.Header.Set("Accept", "application/json")

	return req, nil
}

func createHttpRequestV2(httpMethod string, endPoint string, jsonPayload []byte, MIMEType string) (*http.Request, error) {
	var req *http.Request
	var err error

	if httpMethod == "GET" {
		req, err = http.NewRequest(httpMethod, apiURLLaravel+"api/"+endPoint, nil)
	} else {
		// For POST, PUT, DELETE, etc., use the jsonPayload to create the request body.
		// Use NopeCloser to avoid closing the body when the request is done.
		// This is because for POST requests the body is set and it's not needed to be closed
		// by the caller. Unlike the GET requests where the body needs to be closed by the caller (defer resp.Body.Close())
		bodyReader := io.NopCloser(bytes.NewReader(jsonPayload)) // Create a new reader for each request
		req, err = http.NewRequest(httpMethod, apiURLLaravel+"api/"+endPoint, bodyReader)
		if err == nil {
			req.Header.Set("Content-Type", MIMEType) // Set Content-Type for non-GET requests
		}
	}

	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json") // Set Accept header for all requests

	return req, nil
}

// createHttpRequest creates the http request for a specific endpoint and sets the headers.
func createHttpRequestNopCloserV2(httpMethod string, endPoint string, jsonPayload io.ReadCloser, MIMEType string) (*http.Request, error) {
	// req, err := http.NewRequest(httpMethod, apiURLFlask+"api/"+endPoint, nil)
	req, err := http.NewRequest(httpMethod, apiURLLaravel+"api/"+endPoint, nil)
	if err != nil {
		return nil, err
	}

	if httpMethod != "GET" {
		// The payload is only set for None GET requests and it's given the no operation closer so it does not close the body as it's unnecessary
		// req.Body = io.NopCloser(bytes.NewBuffer(jsonPayload))
		req.Header.Set("Content-Type", MIMEType)
	}
	req.Header.Set("Accept", "application/json")

	return req, nil
}

func createHttpRequestForContentTypeV2(httpMethod string, endPoint string, jsonPayload []byte, MIMEType string) (*http.Request, error) {
	// req, err := http.NewRequest(httpMethod, apiURLFlask+"api/"+endPoint, nil)
	req, err := http.NewRequest(httpMethod, apiURLLaravel+"api/"+endPoint, nil)
	if err != nil {
		return nil, err
	}

	if httpMethod != "GET" {
		// The payload is only set for None GET requests and it's given the no operation closer so it does not close the body as it's unnecessary
		req.Body = io.NopCloser(bytes.NewBuffer(jsonPayload))
		req.Header.Set("Content-Type", MIMEType)
	}

	return req, nil
}

// createHttpRequest creates the http request for a specific endpoint and sets the headers.
func createHttpRequestV3(httpMethod string, endPoint string, jsonPayload *bytes.Buffer, MIMEType string) (*http.Request, error) {
	// req, err := http.NewRequest(httpMethod, apiURLFlask+"api/"+endPoint, nil)
	req, err := http.NewRequest(httpMethod, apiURLLaravel+"api/"+endPoint, jsonPayload)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", MIMEType)
	// if httpMethod != "GET" {
	// 	// The payload is only set for None GET requests and it's given the no operation closer so it does not close the body as it's unnecessary
	// 	req.Body = io.NopCloser(bytes.NewBuffer(jsonPayload))
	// }

	return req, nil
}

func checkIfTokenDateExpiredAndUpdateHeader(req *http.Request) error {
	if time.Now().After(tokenExpirationData) || tokenExpirationData.IsZero() {

		log.Info().Msgf("Token when requesting %s has been expired before. Reauthenticating ...", req.URL)
		var err error
		authenticationTokenV2, tokenExpirationData, err = loginAndReturnTokenV2(loginPassword)
		if err != nil {
			fmt.Println("Error in loginAndReturnTokenV2: ", err)
			return fmt.Errorf("could not login and get authentication token when accessing %s: %w", req.URL, err)
		}
		req.Header.Set("Authorization", "Bearer"+authenticationTokenV2)

	}

	return nil

}

// executeHTTPRequestWithTokenValidtyV2 excutes the file upload request provided
// in the req parameter using the HTTP client provided in the client parameter.
// It retries the request up to 10 times if it fails or the response status code
// is not 200. It also checks if the token is valid, if not, it updates the token.
// The retries are set to 10 times.
func executeHTTPRequestWithTokenValidtyV2(req *http.Request, retries int) (bytes.Buffer, error) {
	req.Header.Set("Authorization", "Bearer"+authenticationTokenV2)

	responseBody, err := executeHTTPRequestV2(req, retries)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to execute %s request to %s, %w", req.Method, req.URL, err)
	}

	if err := handleTokenValidityV2(responseBody, req); err != nil {
		return bytes.Buffer{}, err
	}

	log.Info().Msgf("Successfully executed %s request to %s with token validity.", req.Method, req.URL)
	return responseBody, nil
}

// executeHTTPRequestWithTokenValidtyV2 excutes the file upload request provided
// in the req parameter using the HTTP client provided in the client parameter.
// It retries the request up to 10 times if it fails or the response status code
// is not 200. It also checks if the token is valid, if not, it updates the token.
// The retries are set to 10 times.
func executeHTTPRequestWithTokenValidtyV1(req *http.Request, retries int) (bytes.Buffer, error) {
	req.Header.Set("Authorization", authenticationTokenV1)

	responseBody, err := executeHTTPRequestV1(req, retries)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to execute %s request to %s, %w", req.Method, req.URL, err)
	}

	// TODO: Double check if this is actually being checked.
	if err := handleTokenValidityV1(responseBody, req); err != nil {
		return bytes.Buffer{}, err
	}

	log.Info().Msgf("Successfully executed %s request to %s with token validity.", req.Method, req.URL)
	return responseBody, nil
}

// executeHTTPRequest executes the HTTP request and returns the
// response body as bytes.Buffer. It takes the request, client, and
// number of retries as parameters. If retries is <1, it retries the
// request forever. Otherwise, it retries the request up to the given
// number of retries.
func executeHTTPRequestV2(req *http.Request, retries int) (bytes.Buffer, error) {
	log.Info().Msgf("Starting excuting %s request to %s ...", req.Method, req.URL)

	resp, cancel, err := sendRequestWithRetriesV2(req, retries)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer resp.Body.Close()
	defer cancel()

	responseBody, err := readResponseBody(resp)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to read response body of %s request to %s, %w", req.Method, req.URL, err)
	}

	if resp.StatusCode == http.StatusNotFound && strings.Contains(responseBody.String(), "Client not found") {
		return responseBody, nil
	}

	if resp.StatusCode == http.StatusNotFound {
		return bytes.Buffer{}, fmt.Errorf("this %s request to %s was not found 404, %w", req.Method, req.URL, err)
	}

	log.Info().Msgf("Successfully executed %s request to %s.", req.Method, req.URL)
	return responseBody, nil
}

// executeHTTPRequest executes the HTTP request and returns the
// response body as bytes.Buffer. It takes the request, client, and
// number of retries as parameters. If retries is <1, it retries the
// request forever. Otherwise, it retries the request up to the given
// number of retries.
func executeHTTPRequestV1(req *http.Request, retries int) (bytes.Buffer, error) {
	log.Info().Msgf("Starting excuting %s request to %s ...", req.Method, req.URL)

	resp, err := sendRequestWithRetriesV1(req, retries)
	if err != nil {
		return bytes.Buffer{}, err
	}
	defer resp.Body.Close()

	responseBody, err := readResponseBody(resp)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to read response body of %s request to %s, %w", req.Method, req.URL, err)
	}

	log.Info().Msgf("Successfully executed %s request to %s.", req.Method, req.URL)
	return responseBody, nil
}

// sendRequestWithRetries sends the given request using the given client and
// retries up to 10 times if it fails or the response status code is not 200.
// It returns the response of the request.
func attemptRequest(req *http.Request, i int) (*http.Response, error) {
	resp, err := sendCustomHTTPClientRequest(req)
	if err != nil {
		handleFailedRequest(req, resp, i, err)
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		log.Error().Msgf("Unauthorized request to %s", req.URL)
		return resp, nil
	}

	if resp.StatusCode == http.StatusNotFound {
		log.Error().Msgf("Not Found request to %s", req.URL)
		return resp, nil
	}

	if resp.StatusCode != http.StatusOK {
		handleFailedRequest(req, resp, i, nil)
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return resp, nil
}

func sendRequestWithRetriesV2(req *http.Request, retries int) (*http.Response, context.CancelFunc, error) {

	if retries < 1 {
		// set the default number of retries to infinity
		retries = math.MaxInt32
	}

	if err := checkIfTokenDateExpiredAndUpdateHeader(req); err != nil {
		return nil, nil, fmt.Errorf("couldn't check if token expired for %s request to %s ", req.Method, req.URL)
	}

	var originalBody []byte

	if req != nil && req.Body != nil {
		var err error
		// Copy the request body so it can be read again later.
		originalBody, err = copyBody(req.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to copy request body: %w", err)
		}
		resetBody(req, originalBody)
	}

	for i := 0; i < retries; i++ {
		// Create a new context with a fresh timeout for each attempt
		// This is so when the deadline is exceeded, it would be refreshed as opposed to using the same deadline
		// for all the attempts. This is to avoid the deadline being exceeded for all the attempts even if the
		// deadline is exceeded for the first attempt and the subsequent attempts are made and should be successful.
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		req = req.WithContext(ctx) // Apply the new context to the existing request

		resp, err := attemptRequest(req, i)
		if err != nil {
			// For requests that failed, reset the request body so it can be
			// read again later.
			if req.Body != nil {
				resetBody(req, originalBody)
			}
			cancel() // Cancel early only if the request is going to be retried
			continue
		}
		// Return cancel function to be deferred by the caller
		// We don't cancel it inside as it would cancel the whole response and
		// the caller would not be able to read the response body.
		return resp, cancel, nil
	}

	return nil, nil, fmt.Errorf("reached maximum retry attempts for %s request to %s", req.Method, req.URL)
}

// copyBody reads the body of the given request and returns it as a byte slice.
func copyBody(src io.ReadCloser) ([]byte, error) {
	b, err := io.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	src.Close()
	return b, nil
}

// resetBody resets the body of the given request to the original body.
func resetBody(request *http.Request, originalBody []byte) {
	request.Body = io.NopCloser(bytes.NewBuffer(originalBody))
}

// readResponseBody reads the response body from the given response and returns
// it as a string.
func readResponseBody(resp *http.Response) (bytes.Buffer, error) {

	// Read the response body into a buffer to read it efficiently.
	var responseBody bytes.Buffer

	// Copy the response body into the buffer.
	_, err := io.Copy(&responseBody, resp.Body)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error reading response body: %w", err)
	}

	// Return the response body as a string.
	return responseBody, nil
}

// handleTokenValidityV2 checks if the token is valid, if not, it updates the
// token again, updated the header of Authorization and retries the upload
// request.
//
// TODO: Check this if needed in the server later on.
func handleTokenValidityV2(responseBody bytes.Buffer, req *http.Request) error {
	isValid, err := checkTokenValidityAndUpdateHeaderV2(responseBody, req)
	if err != nil {
		return fmt.Errorf("failed to check token validity in URL Path: %s, because of error: %w", req.URL, err)
	}

	// If the token is valid, then return.
	if isValid {
		return nil
	}

	// If the token is not valid, then retry the upload request after updating
	// the header of authorization with the new token.
	if _, err := executeHTTPRequestWithTokenValidtyV2(req, 10); err != nil {
		return fmt.Errorf("failed to excute HTTP request after re-authentication in URL Path: %s, because of error: %w", req.URL, err)
	}

	return nil
}

// handleTokenValidityV2 checks if the token is valid, if not, it updates the
// token again, updated the header of Authorization and retries the upload
// request.
//
// TODO: Check this if needed in the server later on.
func handleTokenValidityV1(responseBody bytes.Buffer, req *http.Request) error {
	isValid, err := checkTokenValidityAndUpdateHeaderV1(responseBody, req)
	if err != nil {
		return fmt.Errorf("failed to check token validity in URL Path: %s, because of error: %w", req.URL, err)
	}

	// If the token is valid, then return.
	if isValid {
		return nil
	}

	// If the token is not valid, then retry the upload request after updating
	// the header of authorization with the new token.
	if _, err := executeHTTPRequestWithTokenValidtyV1(req, 10); err != nil {
		return fmt.Errorf("failed to excute HTTP request after re-authentication in URL Path: %s, because of error: %w", req.URL, err)
	}

	return nil
}

// checkTokenValidityAndUpdateHeaderV1 checks if the token is valid, if not, it updates the token again and updates the header of Authorization.
func checkTokenValidityAndUpdateHeaderV2(responseBody bytes.Buffer, req *http.Request) (bool, error) {
	if !strings.Contains(responseBody.String(), "Unauthenticated.") {
		return true, nil
	}

	log.Info().Msgf("Token for %s has return Unathenticated response, reauthinticating ...", req.URL)

	var err error
	authenticationTokenV2, tokenExpirationData, err = loginAndReturnTokenV2(loginPassword)
	if err != nil {
		return false, fmt.Errorf("could not login and get authentication token while uploading after re-authentication")
	}

	req.Header.Set("Authorization", "Bearer"+authenticationTokenV2)
	return false, nil
}

//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------

// sendOnlineStatusToServerV2 sends a heartbeat to the server indicating that
// this agent is still online. It sends the heartbeat every 10 minutes minimum.
func sendOnlineStatusToServerV2() {
	defer catchAndRestartPanicForFunction(sendOnlineStatusToServerV2)

	log.Info().Msg("Starting the send online status to server loop...")

	for {
		_, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("GET", "keep_alive/"+id, nil, 1)
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute send online status.")
		}

		maxDuration := getMaxOnlineStatusDelay()
		sleepForRandomDelayDuration(600, maxDuration) // Minumum every 10 minutes.
	}
}

// getMaxOnlineStatusDelay retrieves the maximum time to wait before sending
// the next online status and returns it.
func getMaxOnlineStatusDelay() int {
	const defaultDelay = 700
	const minDelay = 600

	// Time to keep waiting before sending online status again
	maxDelay := keepAlive

	if maxDelay <= minDelay {
		log.Warn().Int("TimeToKeepAlive", maxDelay).Msgf("Specified time to keep alive is less than %d seconds. Adjusting to %d seconds.", minDelay, defaultDelay)
		return defaultDelay
	}

	// Every 600-1200 seconds, send that the agent is still online
	log.Debug().Int("MinDelay", minDelay).Int("MaxDelay", maxDelay).Msg("Sleeping for a random duration before sending the next online status.")
	return maxDelay
}

//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------

// catchAndRestartPanicForRealTime catches a panic, logs it, and restarts the
// real time website interaction thread.
func catchAndRestartPanicForRealTime(serialNumber string) {
	if r := recover(); r != nil {
		// Log the panic as before
		logPanic(r)

		// Restart the goroutine
		go realTimeWebsiteInteractionThreadV2(serialNumber)
	}
}

// func to catch and restart the passed function:
func catchAndRestartPanicForFunction(f func()) {
	if r := recover(); r != nil {
		// Log the panic as before
		logPanic(r)

		// Restart the goroutine
		go f()
	}
}

// logPanic is a modified version of catchPanic that logs the panic.
// It's similar to your catchPanic function but simplified for demonstration.
func logPanic(r interface{}) {
	// Create a buffer with a size of 1024 bytes to hold the stack trace
	stackTrace := make([]byte, 1024)
	for {

		// Retrieve the stack trace only for this goroutine and fill it
		// into the buffer. False means that we only want the stack trace
		// for this goroutine and not all of them.
		n := runtime.Stack(stackTrace, false)

		// If the buffer was large enough to fit the stack trace, break
		if n < len(stackTrace) {
			stackTrace = stackTrace[:n]
			break
		}

		// If the buffer was too small to fit the stack trace, double its size
		stackTrace = make([]byte, len(stackTrace)*2)
	}

	// Convert the stack trace to a string and concatenate it with the panic message
	err := fmt.Errorf("%v\nStack Trace:\n%s", r, stackTrace)

	// Use Msgf to log the error formatter as opposed in one line when
	// using Err()
	time.Sleep(15 * time.Second)
	log.Error().Msgf("Panic recovered and logged with stack trace: %v", err)
}

type ApiRealTimeRedisResponse struct {
	StopAgent   bool `json:"StopAgent"`
	DeleteAgent bool `json:"DeleteAgent"`

	TaskList           bool   `json:"tasklist"`
	RealService        bool   `json:"realservice"`
	Patches            bool   `json:"patches"`
	Cyscan             bool   `json:"cyscan,omitempty"`
	JsonFile           string `json:"jsonfile,omitempty"`
	Rescan             bool   `json:"rescan"` // Only rescan
	Recheckin          bool   `json:"recheckin"`
	IsDeletedIIS       bool   `json:"isDeletedIIS"`
	Updates            bool   `json:"updates"`
	Log                bool   `json:"log"` // To update the logs to the server
	Leader             bool   `json:"leader"`
	IDCommands         int    `json:"idcommands"`
	Commands           string `json:"commands"`
	TypeOfStringBase64 int    `json:"typeofstringBase64"`
	RefreshSettings    bool   `json:"refreshSettings"`
	UploadUsers        bool   `json:"uploadUsers"`
	RecheckinProduct   bool   `json:"recheckinProduct"` // Only recheckin product, eg: Chrome, Firefox, Office.
	ProductName        string `json:"productName"`      // The name of the product to recheckin, eg: Chrome, Firefox, Office.
}

func initRedis(iniData ini.IniConfig) *redis.Client {
	log.Info().Msg("Starting real time redis interaction thread...")

	port := getIniValue(&iniData, "API", "PortRedis")
	parts := strings.Split(apiURLLaravel, "/")
	if len(parts) < 3 {
		log.Error().Msg("Failed to get the IP address from the API URL.")
		return nil
	}
	ip := parts[2]

	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", ip, port),                                     // we want get this ip from cymetricx ini like this '157.175.205.169'    or hostname 'example.com'  and port for recleadis      // Redis server address
		Password: "74b7e3fc918b41e7b57938ec578c0c223a28bbcbe91e9e5ba490cbf7e3bdea50", // no password set, adjust as necessary
		DB:       0,                                                                  // default DB
	})

	return rdb
}

func realTimeRedisWebsiteInteractionThreadV2(iniData ini.IniConfig, serialNumber string) {
	defer catchAndRestartPanicForRealTimeRedis(iniData, serialNumber)

	log.Info().Msgf("Starting real time redis website interaction thread...")

	rdb := initRedis(iniData)
	ctx := context.Background()

	go checkAgentRedisOnlineStatus(rdb, ctx)

	pubsub := rdb.Subscribe(ctx, id)

	for {
		log.Info().Msgf("Starting to listen to Pub/Sub channel: %s", id)
		ch := pubsub.Channel()

		log.Debug().Msgf("Listening to Pub/Sub channel: %s", id)

		for msg := range ch {
			log.Info().Msgf("Received message from Pub/Sub: %s", msg.Payload)

			responseBody, err := readAndUnmarshellRedisResponseV2(msg)
			if err != nil {
				log.Error().Err(err).Msg("Failed to read and unmarshal redis response.")
			}

			log.Info().Msgf("Received real time redis response: %+v", responseBody)

			go processRealTimeRedisInstructions(responseBody, serialNumber, rdb)
		}

		log.Info().Msgf("Stopping to listen to Pub/Sub channel: %s", id)
	}
}

// Works the same as the agent's online check (keep_alive). The point of this is to check
// on the website GUI if the redis status is online or not. If it is, then it will
// push the ID to the onlineQueue list for the server to read it every 10-20 seconds.
func checkAgentRedisOnlineStatus(rdb *redis.Client, ctx context.Context) {
	for {

		// The name of the list in Redis that contains the IDs of the online
		// agents
		queueListName := "onlineQueue"

		// Get the elements from the onlineQueue list in Redis that contains
		// the IDs of the online agents. 0 and -1 are the start and end indices
		// of the list, respectively. Meaning that we want to get all the elements
		// in the list.
		elements, err := rdb.LRange(ctx, queueListName, 0, -1).Result()
		if err != nil {
			log.Error().Err(err).Msg("Failed to get elements from Redis.")
		}

		// Check if the ID exists in the fetched elements
		var idExists bool
		for _, element := range elements {
			if element == id {
				idExists = true
				break
			}
		}

		// If the ID does not exist in the list, then push it to the list
		// It will pushed to the right of the list.
		if !idExists {
			err := rdb.RPush(ctx, queueListName, id).Err()
			if err != nil {
				log.Error().Err(err).Msg("Failed to push ID to Redis.")
			}
			log.Debug().Msgf("Pushed ID to Redis onlineQueue list: %s", id)
		}

		sleepForRandomDelayDuration(10, 20)
	}
}

type RedisReplyMessage struct {
	ClientID  string `json:"client_id"`
	Content   string `json:"content"`
	CommandID *int   `json:"command_id,omitempty"`
}

func sendAckToRedisServer(rdb *redis.Client, msgContent string, commandID *int, productID *string) error {
	clientID := id
	if productID != nil {
		clientID = *productID
	}

	redisReplyMessage := RedisReplyMessage{
		ClientID:  clientID,
		Content:   msgContent,
		CommandID: commandID,
	}

	// Serialize the message to JSON
	jsonPayload, err := json.Marshal(redisReplyMessage)
	if err != nil {
		return fmt.Errorf("failed to marshel redis reply message %+v to JSON: %w", redisReplyMessage, err)
	}

	// Publish the message to the specified channel (static for all agents)
	ackChannel := "client_acknowledgments"

	// Publish the message to the specified channel, the server will receive it.
	ctx := context.Background()
	err = rdb.Publish(ctx, ackChannel, jsonPayload).Err()
	if err != nil {
		return fmt.Errorf("failed to publish message %+v to Redis channel %s: %w", redisReplyMessage, ackChannel, err)
	}

	return nil
}

func readAndUnmarshellRedisResponseV2(msg *redis.Message) (ApiRealTimeRedisResponse, error) {
	var responseBody ApiRealTimeRedisResponse

	if err := json.Unmarshal([]byte(msg.Payload), &responseBody); err != nil {
		return ApiRealTimeRedisResponse{}, fmt.Errorf("error unmarshalling redis response: %w", err)
	}
	return responseBody, nil
}

func processRealTimeRedisInstructions(responseBody ApiRealTimeRedisResponse, serialNumber string, rdb *redis.Client) {

	if responseBody.StopAgent {
		// Restart the agent
		log.Info().Msg("Received stop agent instruction. Restarting the agent service...")
		stopAgent()
	}

	if responseBody.DeleteAgent {
		// Restart the agent
		log.Info().Msg("Received delete agent instruction. Restarting the agent service...")
		deleteAgent()
	}

	if responseBody.TaskList {
		if err := getAndCompressAndUploadListTaskMangerV2(); err != nil {
			log.Error().Err(err).Msg("Failed to compress and upload tasklist.")
		}
	}

	if responseBody.RealService {
		if err := getAndcompressAndUploadWindowsServicesV2(); err != nil {
			log.Error().Err(err).Msg("Failed to compress and upload windows services.")
		}
	}

	if responseBody.Commands != "" {
		if err := sendAckToRedisServer(rdb, "command_received", &responseBody.IDCommands, nil); err != nil {
			log.Error().Err(err).Msg("Failed to send command_received message to redis server.")
		}

		go runAndUploadCommandsOutputV2(responseBody.Commands, responseBody.IDCommands, responseBody.TypeOfStringBase64)
	}

	if responseBody.Patches {
		// This is so we don't wait in this specific funciton for the configuration to come back
		// because we need some of the data in the uploadPatchesFIles function, so we need to run it
		// fast and not sleep for 30-120 seconds before retrieving the data

		// So it is a routine cuz it would take a long time (could be an hour)
		go processAndSendPatchResults()
		// Return the time to wait back to its normal time range
	}

	// This does not return "cyscan=0", only if the json configurations for cyscan exit, then it would return "cyscan=1"
	if responseBody.Cyscan {
		go runCyscanAndUploadItsOutput(responseBody.JsonFile)
	}

	if responseBody.Recheckin {
		if err := sendAckToRedisServer(rdb, "recheck_received", nil, nil); err != nil {
			log.Error().Err(err).Msg("Failed to send recheck_received message to redis server.")
		}
		isDeletedIIS = responseBody.IsDeletedIIS

		if SystemHardeningCheck {
			os.Remove("Hash Files/uploadAuditToprocess.txt")
			go runRecheckin(rdb)
		}
	}

	if responseBody.RecheckinProduct {
		productID, productVersion, err := checkAndGenerateProductID(responseBody.ProductName)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to check and generate product ID for product %s.", responseBody.ProductName)
			return
		}

		if err := sendAckToRedisServer(rdb, "recheck_product_received", nil, &productID); err != nil {
			log.Error().Err(err).Msgf("Failed to send recheck_product_received message to redis server for product %s.", responseBody.ProductName)
		}

		if err := processBenchmarkAndAuditResultForSingleProduct(responseBody.ProductName, productID, productVersion); err != nil {
			log.Error().Err(err).Msgf("Failed to process benchmark and audit result for product %s.", responseBody.ProductName)
			return
		}

		if err := sendAckToRedisServer(rdb, "recheck_product_completed", nil, &productID); err != nil {
			log.Error().Err(err).Msgf("Failed to send recheck_product_completed message to redis server for product %s.", responseBody.ProductName)
		}
	}

	// Only rescan
	if responseBody.Rescan {
		activeDirectoryDomainController = responseBody.Leader
		if err := sendAckToRedisServer(rdb, "rescan_received", nil, nil); err != nil {
			log.Error().Err(err).Msg("Failed to send rescan_received message to redis server.")
		}

		rescanAndCompressAndUploadEverthing(rdb)
	}

	if responseBody.Updates {
		if err := sendAckToRedisServer(rdb, "update_received", nil, nil); err != nil {
			log.Error().Err(err).Msg("Failed to send update_received message to redis server.")
		}

		if err := downloadAndUpdateNewMajorAgentV2(serialNumber); err != nil {
			log.Error().Err(err).Msg("Failed to download and update new major agent.")
		}
	}

	if responseBody.Log {
		if err := sendAckToRedisServer(rdb, "logs_received", nil, nil); err != nil {
			log.Error().Err(err).Msg("Failed to send logs_received message to redis server.")
		}

		if err := compressAndUploadLogs("regular"); err != nil {
			log.Error().Err(err).Msg("Failed to compress and upload agent logs from redis response.")
		}

		// Only send ack to the server if the logs are uploaded when request is done through redis.
		if err := sendAckToRedisServer(rdb, "logs_completed", nil, nil); err != nil {
			log.Error().Err(err).Msg("Failed to send logs_completed message to redis server")
		}
	}

	if responseBody.RefreshSettings {
		// Add a delay before refreshing the settings so we don't spam the
		// realtime api with requests.
		sleepForRandomDelayDuration(1, 50)

		if err := callRealTimeAndProcessFeatureSettings(serialNumber); err != nil {
			log.Error().Err(err).Msg("Failed to call real time and process feature settings.")
		}
	}

	if responseBody.UploadUsers {
		if err := uploadWindowsUsersInformationV2(); err != nil {
			log.Error().Err(err).Msg("Failed to upload windows users information.")
		}
	}
}

// compressAndUploadLogs compresses the agent logs, truncates the original
// logs, and uploads the compressed logs to the server. It removes the logs.zip
// file after the successful upload. It takes the upload type as a parameter
// which might be "regular" or "before_update_<Agent_Version>" or "after_update_<Agent_Version>".
// Where each one indicates when the logs where uploaded to the server.
func compressAndUploadLogs(uploadType string) error {
	log.Info().Msg("Starting to compress and upload agent logs...")

	srcDir := filepath.Join(CymetricxPath, "logs")
	destZipPath := filepath.Join(CymetricxPath, "logs.zip")

	if err := zipDirAndTruncate(srcDir, destZipPath); err != nil {
		return fmt.Errorf("failed to compress and truncate agent logs: %w", err)
	}

	endPoint := fmt.Sprintf("upload_logs_agents/%s/%s", id, uploadType)
	responseBody, err := createAndExecuteFileUploadRequest(endPoint, destZipPath)
	if err != nil {
		return fmt.Errorf("failed to execute upload logs request: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload agent logs: %w", err)
	}

	// After the successful upload, delete the logs.zip file
	if err := os.Remove(destZipPath); err != nil {
		return fmt.Errorf("failed to delete logs.zip file: %w", err)
	}

	log.Info().Msg("Successfully compressed and uploaded agent logs.")

	return nil
}

// zipDir compresses the specified source directory (including all subdirectories and files)
// into a ZIP archive at the destination path. It preserves the directory structure, applies
// Deflate compression to files, and includes directory entries to ensure the structure is
// preserved even for empty directories. It takes two parameters: the source directory and the
// destination path of the ZIP archive to create.
func zipDir(source, destination string) error {
	outFile, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Initialize a new ZIP writer.
	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	// Calculate the base directory to create relative paths for ZIP entries.
	// Ex: zipping "C:\photos\summer" should create entries like "summer/..."
	// and not "C:\photos\summer/...".
	// BaseDIr is "C:\photos" in this case.
	baseDir := filepath.Dir(source)

	// Walk through all files and directories in the source directory.
	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {

		// If the walk function returns an error, return this error to the caller.
		if err != nil {
			return err
		}

		// Compute the relative path of the file or directory from the source
		// directory. This ensures the ZIP structure mirrors the original directory
		// structure. For example, if the file is "C:\photos\summer\beach.jpg",
		// the header name should be "summer/beach.jpg".
		headerName, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}

		// Create a new ZIP file header based on the file information.
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = headerName // Set the entry name to the relative path.

		// If the entry is a directory, append a '/' to indicate it in the ZIP file.
		// This is a non-standard but widely accepted behavior to distinguish directories.
		if info.IsDir() {
			header.Name += "/"
		} else {
			// Use Deflate compression for file entries to reduce file size.
			header.Method = zip.Deflate
		}

		// Create a writer for the current entry in the ZIP writer.
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		// If the entry is a file, copy its contents to the ZIP file.
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(writer, file) // Copy the file content to the ZIP entry.
			return err
		}
		return nil
	})

	return err
}

// zipDirAndTruncate compresses the specified source directory (including all subdirectories and files)
// into a ZIP archive at the destination path. After a file is added to the ZIP archive, its content
// is truncated, effectively emptying the file without deleting it. This is particularly useful for
// log files that are actively used by an application and cannot be deleted.
// It takes two parameters: the source directory and the
// destination path of the ZIP archive to create.
func zipDirAndTruncate(source, destination string) error {
	outFile, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Initialize a new ZIP writer.
	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	// Calculate the base directory to create relative paths for ZIP entries.
	// Ex: zipping "C:\photos\summer" should create entries like "summer/..."
	// and not "C:\photos\summer/...".
	// BaseDIr is "C:\photos" in this case.
	baseDir := filepath.Dir(source)

	// Walk through all files and directories in the source directory.
	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {

		// If the walk function returns an error, return this error to the caller.
		if err != nil {
			return err
		}

		// Compute the relative path of the file or directory from the source
		// directory. This ensures the ZIP structure mirrors the original directory
		// structure. For example, if the file is "C:\photos\summer\beach.jpg",
		// the header name should be "summer/beach.jpg".
		headerName, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}

		// Create a new ZIP file header based on the file information.
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = headerName // Set the entry name to the relative path.

		// If the entry is a directory, append a '/' to indicate it in the ZIP file.
		// This is a non-standard but widely accepted behavior to distinguish directories.
		if info.IsDir() {
			header.Name += "/"
		} else {
			// Use Deflate compression for file entries to reduce file size.
			header.Method = zip.Deflate
		}

		// Create a writer for the current entry in the ZIP writer.
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		// If the entry is a file, copy its contents to the ZIP file.
		if !info.IsDir() {

			// Open the file for reading and writing.This is necessary to truncate
			// the file after its contents have been written to the ZIP.
			file, err := os.OpenFile(path, os.O_RDWR, 0644)
			if err != nil {
				return err
			}
			defer file.Close()

			// Copy the file content to the ZIP entry.
			_, err = io.Copy(writer, file)
			if err != nil {
				return err
			}

			// Truncate the file after its contents have been written to the ZIP.
			if err := file.Truncate(0); err != nil {
				return err
			}
		}
		return nil
	})

	return err
}

// catchAndRestartPanicForRealTime catches a panic, logs it, and restarts the
// real time website interaction thread.
func catchAndRestartPanicForRealTimeRedis(iniData ini.IniConfig, serialNumber string) {
	if r := recover(); r != nil {
		// Log the panic as before
		logPanic(r)

		// Restart the goroutine
		go realTimeRedisWebsiteInteractionThreadV2(iniData, serialNumber)
	}
}

// realTimeWebsiteInteractionThreadV2 is responsible for interacting with the
// server in real time. It sends a request to the server every 500 milliseconds
// or the time specified by the server. It checks checks if the server has sent
// sent any instructions to the agent to excute them.
func realTimeWebsiteInteractionThreadV2(serialNumber string) {
	defer catchAndRestartPanicForRealTime(serialNumber)

	log.Info().Msg("Starting real time website interaction thread...")

	// var isFirstRun bool = true // Flag to check if this is the first run

	for {

		// If it's not the first run, sleep for the defined duration.
		// If not, we need to call real time.
		// Call real time for the first time to get configuration and process instructions
		// that were triggered while the agent was not running. Also, get the Feature settings.
		// if !isFirstRun {
		sleepForRandomDelayDurationInMinutes(30, 60) // Sleep for 30-60 Minutes
		// } else {
		// 	isFirstRun = false // Set to false after the first run.
		// }

		if err := callRealTimeAndProcessFeatureSettings(serialNumber); err != nil {
			log.Error().Err(err).Msg("Failed to call real time and process feature settings.")
			continue
		}
	}
}

func callRealTimeAndProcessFeatureSettings(serialNumber string) error {
	responseBody, err := callRealTimeAndProcessInstructionsV2(serialNumber)
	if err != nil {
		return fmt.Errorf("failed to call real time and process instructions: %w", err)
	}

	// Extract feature settings from responseBody and compare with oldDataFeatures.
	dataFeatures := extractFeatureSettings(responseBody.FeaturesSettingsAgent)
	filePath := filepath.Join(CymetricxPath, "FeaturesSettings.ini")
	if err := createFileWithPermissionsAndWriteToIt(filePath, dataFeatures, 0644); err != nil {
		return fmt.Errorf("failed to create FeaturesSettings.ini file: %w", err)
	}

	return nil
}

func callRealTimeAndProcessInstructionsV2(serialNumber string) (ApiRealTimeResponse, error) {
	log.Info().Msg("Initiating real time request to the server...")

	responseBody, err := sendRealTimeRequest()
	if err != nil {
		return ApiRealTimeResponse{}, fmt.Errorf("failed to send real time request to the server: %w", err)
	}

	processRealTimeServerInstructions(responseBody, serialNumber)

	return responseBody, nil
}

type ApiRealTimeResponse struct {
	IDCommands            int    `json:"idcommands"`
	Commands              string `json:"commands"`
	TypeOfStringBase64    int    `json:"typeofstringBase64"`
	TimeSleepForRealtime  int    `json:"TimeSleepForrealtime"`
	StopAgent             bool   `json:"StopAgent"`
	DeleteAgent           bool   `json:"DeleteAgent"`
	Recheckin             bool   `json:"recheckin"`
	Rescan                bool   `json:"rescan"`
	Updates               bool   `json:"updates"`
	FeaturesSettingsAgent string `json:"FeaturesSettings"`
	ApplicationRealtime   bool   `json:"applicationrealtime"`
	LocalDNS              bool   `json:"localdns"`
	LocalUsers            bool   `json:"localusers"`
	Patches               bool   `json:"patches"`
	CyScanUpdate          bool   `json:"cyscanupdate"`
	CyScanNewVersion      string `json:"cyscannewversion"`
	RealService           bool   `json:"realservice"`
	TaskList              bool   `json:"tasklist"`
	AppManager            bool   `json:"appmanager"`
	Cyscan                bool   `json:"cyscan,omitempty"`
	JsonFile              string `json:"jsonfile,omitempty"`

	TimeUSN                   int  `json:"timeUSN"`
	Leader                    bool `json:"leader"`
	Compliance                bool `json:"compliance"`
	KeepAlive                 int  `json:"keepAlive"`
	MinimalRescanInterval     int  `json:"minimalRescanInterval"`
	MaximalRescanInterval     int  `json:"maximalRescanInterval"`
	MinimalMonitoringInterval int  `json:"minimalMonitoringInterval"`
	MaximalMonitoringInterval int  `json:"maximalMonitoringInterval"`

	IsDeletedIIS bool `json:"isDeletedIIS"`
}

// sendRealTimeRequest sends a request to the server to retrieve real time
// data. It takes a counter, a default sleep time as parameters.
// It uses the counter to log every 100th iteration. It uses the default sleep
// time to sleep for 500 milliseconds or the time specified by the server.
// It returns the response body as a string.
// func sendRealTimeRequest(counter *int, defaultSleepTime int) (string, error) {
func sendRealTimeRequest() (ApiRealTimeResponse, error) {
	responseBody, err := prepareAndExecuteHTTPRequestWithTokenValidityV2("GET", "realtime/"+id, nil, -1)
	if err != nil {
		return ApiRealTimeResponse{}, fmt.Errorf("failed to execute /realtime API call: %w", err)
	}

	var apiRealTimeResponse ApiRealTimeResponse

	if err := json.Unmarshal(responseBody.Bytes(), &apiRealTimeResponse); err != nil {
		return ApiRealTimeResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	return apiRealTimeResponse, nil
}

func processRealTimeServerInstructions(responseBody ApiRealTimeResponse, serialNumber string) {
	activeDirectoryDomainController = responseBody.Leader
	complience = responseBody.Compliance
	keepAlive = responseBody.KeepAlive                                 // TIme in milliseconds
	timeUSN = responseBody.TimeUSN                                     // Time in minutes
	minimalRescanInterval = responseBody.MinimalRescanInterval         // Time in minutes
	maximalRescanInterval = responseBody.MaximalRescanInterval         // Time in minutes
	minimalMonitoringInterval = responseBody.MinimalMonitoringInterval // Time in minutes
	maximalMonitoringInterval = responseBody.MaximalMonitoringInterval // Time in minutes
	isDeletedIIS = responseBody.IsDeletedIIS

	if responseBody.StopAgent {
		// Restart the agent
		log.Info().Msg("Received stop agent instruction. Restarting the agent service...")
		stopAgent()
	}

	if responseBody.DeleteAgent {
		// Restart the agent
		log.Info().Msg("Received delete agent instruction. Restarting the agent service...")
		deleteAgent()
	}

	if responseBody.TaskList {
		if err := getAndCompressAndUploadListTaskMangerV2(); err != nil {
			log.Error().Err(err).Msg("Failed to compress and upload tasklist.")
		}
	}

	if responseBody.RealService {
		if err := getAndcompressAndUploadWindowsServicesV2(); err != nil {
			log.Error().Err(err).Msg("Failed to compress and upload windows services.")
		}
	}

	if responseBody.AppManager {
		if err := getAndCompressAndUploadWindowsInstallerApplicationsV2(); err != nil {
			log.Error().Err(err).Msg("Failed to compress and upload app mananger")
		}
	}

	if responseBody.ApplicationRealtime {
		if err := getAndCompressAndUploadAllInstalledApplications(); err != nil {
			log.Error().Err(err).Msg("Failed to compress and upload all installed applications.")
		}
	}

	if responseBody.LocalDNS {
		if err := getAndCompressAndUploadLocalDNS(); err != nil {
			log.Error().Err(err).Msg("Failed to compress and upload local DNS.")
		}
	}

	if responseBody.LocalUsers {
		filePath := filepath.Join(CymetricxPath, "Hash Files", "uploadusersfromwindows.txt")
		if err := os.Remove(filePath); err != nil {
			log.Warn().Err(err).Msg("Failed to remove uploadusersfromwindows.txt file.")
		}

		uploadWindowsUsersInformationV2()
	}

	if responseBody.Patches {
		go processAndSendPatchResults()
	}

	// This does not return "cyscan=0", only if the json configurations for cyscan exit, then it would return "cyscan=1"
	if responseBody.Cyscan {
		go runCyscanAndUploadItsOutput(responseBody.JsonFile)
	}

	if responseBody.CyScanUpdate {
		// if err := startCyscanUpdateProcessV2(responseBody); err != nil {
		// 	log.Error().Err(err).Msg("Failed to update cyscan.")
		// }
		go startCyscanUpdateProcessV2(responseBody)
	}

	if responseBody.Commands != "" {
		go runAndUploadCommandsOutputV2(responseBody.Commands, responseBody.IDCommands, responseBody.TypeOfStringBase64)
	}

}

//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------

// startCyscanUpdateProcessV2 is resoponsible for updating cyscan.exe if there is an update for it and the user clicks on the update button on the website.
// It would download the new cyscan.exe and remove the old one. This means that there is no need to update the whole agent to update cyscan.
func startCyscanUpdateProcessV2(responseBody ApiRealTimeResponse) error {
	log.Info().Msg("Starting the process of updating cyscan...")

	newCyscanVersionNumber := responseBody.CyScanNewVersion

	// Path for the text file that holds the version of the cyscan
	cyscanVersionPath := filepath.Join(CymetricxPath, "CYSCAN_Version.txt")
	if err := updateCyscanIfNewVersion(cyscanVersionPath, newCyscanVersionNumber); err != nil {
		return err
	}

	if err := sendNewCyscanVersionToServerToUpdateDBV2(newCyscanVersionNumber); err != nil {
		return err
	}

	log.Info().Msg("Successfully updated cyscan.")
	return nil
}

// updateCyscanIfNewVersion checks if there is a new version for cyscan.exe, if so, it would remove the old one and download the new one.
/*
	2 cases:

	1- "CYSCAN_Version.txt" does not exist:
		- cyscan.exe already exit, because it was installed by advance installer
		- cyscan_Version.txt does not exist, because it exist after you run cyscan.exe
		- Remove both cyscan.exe, and download the new one

	2- "CYSCAN_Version.txt" exist:
		- cyscan.exe already exit, because it was installed by advance installer
		- cyscan_Version.txt
		- read cyscan_Version file
		Here we have two cases:
			1. the response didn't include the new number for the cyscan version:
				- Remove old cyscan
				- install new cyscan.exe
			2. the response included the new number for the cyscan version,
				- check if the old cyscan.exe version is not the same as the one in the response
				- if so, remove old cyscan
				- install new cyscan
*/
func updateCyscanIfNewVersion(cyscanVersionPath string, newCyscanVersionNumber string) error {
	// if the file does not exist.
	if !fileExists(cyscanVersionPath) {
		if err := downloadAndReplaceCyscanFile(); err != nil {
			return err
		}
		return nil
	}

	// If file exists, read the version number from it.
	cyscanVersionRaw, err := os.ReadFile(cyscanVersionPath)
	if err != nil {
		return fmt.Errorf("error reading file %s: %w", cyscanVersionPath, err)
	}
	cyscanVersion := string(cyscanVersionRaw)

	// If the version number in the response is not the same as the one in the
	// file, then download the new cyscan. Also, if the version number in the
	// response is empty, then download the new cyscan.exe.
	if cyscanVersion != newCyscanVersionNumber || newCyscanVersionNumber == "" {
		if err := downloadAndReplaceCyscanFile(); err != nil {
			return err
		}
	}

	return nil
}

// downloadAndReplaceCyscanFile downloads the new cyscan and replaces the
// old one with it.
func downloadAndReplaceCyscanFile() error {
	// Cyscan file path on the system.
	fileName := filepath.Join(CymetricxPath, "cyscan.exe")

	// Create or truncate the file with excute permissions.
	file, err := createFileWithPermissions(fileName, 0744)
	if err != nil {
		return fmt.Errorf("error while creating %s: %w", fileName, err)
	}
	defer file.Close()

	// Create a new HTTP request with a timeout.
	req, cancel, err := createHTTPRequestWithTimeoutForNoAPIEndpointsV1("GET", "download/cyscan.exe", nil)
	if err != nil {
		return fmt.Errorf("could not create http request with timeout for /download/cyscan: %w", err)
	}
	defer cancel()

	if err := excuteDownloadAndWriteToFile(req, file); err != nil {
		return fmt.Errorf("error executing download cyscan file: %w", err)
	}

	return nil
}

// excuteDownloadAndWriteToFile executes the download cyscan file request.
// It takes the request and the file as parameters. It downloads the new cyscan
// and overwrites the data to the passed file parameter.
func excuteDownloadAndWriteToFile(req *http.Request, file *os.File) error {
	// Added logs because sendRequestWithRetries does not log anything.
	log.Info().Msgf("Starting to excute %s request to download %s from %s...", req.Method, file.Name(), req.URL)

	resp, err := sendRequestWithRetriesV1(req, 10)
	if err != nil {
		return fmt.Errorf("error sending request with retries: %w", err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body from %s: %w", req.URL.Path, err)
	}

	log.Info().Msgf("Successfully excuted %s request to download %s from %s.", req.Method, file.Name(), req.URL)
	return nil

}

//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------

func downloadAndUpdateNewMajorAgentV2(serialNumber string) error {
	log.Info().Msg("Starting the process of updating the Linux agent ...")

	agentFullName, err := fetchLatestMajorAgentVersionFromServer(id)
	if err != nil {
		return fmt.Errorf("error in updateagents: %w", err)
	}

	// So when the new agent starts working again, it wouldn't find this and it would upload the data directly
	filePath := filepath.Join(CymetricxPath, "Time Files", "system-details-timer.txt")
	if err := os.Remove(filePath); err != nil {
		log.Error().Err(err).Msg("Error in removing the system-details-timer.txt file ")
	}

	apiDownloadURL := "download/" + agentFullName //url+"downloads/agents/"+agentnamr
	agentVersionNumber := strings.TrimPrefix(agentFullName, "windowsagent")
	agentVersionNumber = strings.TrimSuffix(agentVersionNumber, ".zip")

	if agentVersionNumber == AgentVersion {
		log.Info().Msg("The agent is already up to date.")
		return nil
	}

	newAgentZipFilePath := filepath.Join(CymetricxPath, agentFullName)
	if err := downloadNewAgentFile(apiDownloadURL, newAgentZipFilePath); err != nil {
		log.Error().Err(err).Msg("Error in downloading the new agent ")
		return err
	}

	//I used it here to make sure that the values inside Registry  are 100% correct and there are no errors
	setCymetricxRegistryKeyValuesAPIandCID(apiURLFlask, serialNumber)

	// script := fmt.Sprintf(`"%s" /qn API_URL="%s" PIDKEY="%s"`,
	// 	filepath.Join(`C:\`, "Program Files", "runservice", agentFullName),
	// 	apiURLFlask,
	// 	serialNumber,
	// )

	// if err := createExcutableFileBat("upgradeversion.bat", script); err != nil {
	// 	return fmt.Errorf("error in creating excutable file: %w", err)
	// }

	// defer os.Remove("upgradeversion.bat")

	baseDirRun := filepath.Join(`C:\`, "Program Files", "runservice")

	// NSSM. The one that runs the agent as a service. It creates and runs the services on windows.
	cymetricxMPath := filepath.Join(baseDirRun, "cymetricxm.exe")

	script := strings.Join([]string{
		fmt.Sprintf(`mkdir "%s"`, baseDirRun),
		// fmt.Sprintf(`move "%s" "%s"`, filepath.Join(CymetricxPath, "upgradeversion.bat"), baseDirRun),
		fmt.Sprintf(`move "%s" "%s"`, newAgentZipFilePath, baseDirRun),
		fmt.Sprintf(`copy "%s" "%s"`, filepath.Join(CymetricxPath, "cymetricxm.exe"), baseDirRun), // NSSM. The one that runs the agent as a service
		fmt.Sprintf(`copy "%s" "%s"`, filepath.Join(CymetricxPath, "cymetricx.ini"), baseDirRun),
		fmt.Sprintf(`copy "%s" "%s"`, filepath.Join(CymetricxPath, "cymetricxService.exe"), baseDirRun), // This is what extracts the zip file and installs the agent to its correct location (CYMETRICX)
		fmt.Sprintf(`ren  "%s" "%s"`, filepath.Join(baseDirRun, "cymetricxService.exe"), "cymetricxService_N.exe"),
		fmt.Sprintf(`"%s" install runupgrade "%s"`, cymetricxMPath, filepath.Join(baseDirRun, "cymetricxService_N.exe")), // Create runupgrade service. This is what runs `cymetircxService.exe` to unzip and install the agent (update)
		fmt.Sprintf(`"%s" set runupgrade AppThrottle 1`, cymetricxMPath),
		fmt.Sprintf(`"%s" start runupgrade`, cymetricxMPath), // Start the runupgrade service that will run cymetricxService.exe which will do the update, which will run the agent as a service.
	}, "\n")

	//  Send the logs to the server with type `before_update`
	if err := compressAndUploadLogs("before_update_" + AgentVersion); err != nil {
		log.Error().Err(err).Msg("Error in compressing and uploading logs before update")
	}

	// Create a text file that indicates that an update occured.
	// So we could upload the new logs `after_update` right when we launch the agent again.
	updateFilePath := filepath.Join(CymetricxPath, "update-occured.txt")
	if err := createFileWithPermissionsAndWriteToIt(updateFilePath, "update occured from", 0644); err != nil {
		log.Error().Err(err).Msg("Error in creating update-occured.txt file")
	}

	// Run the bat script to update the agent and restart the service.
	if err := createAndRunBatScriptWithoutOutput("execsomcommand.bat", script); err != nil {
		return fmt.Errorf("error in creating and running bat script: %w", err)
	}

	return nil
}

type ApiUpdateAgentResponse struct {
	Status    bool   `json:"status"`
	AgentName string `json:"agentName,omitempty"`
	Message   string `json:"message,omitempty"`
}

// fetchLatestMajorAgentVersionFromServer fetches the version of the Linux agent from
// a server. It returns the version as a string that looks like "Linux-agent1.4.147.zip".
func fetchLatestMajorAgentVersionFromServer(id string) (string, error) {

	req, cancel, err := createHTTPRequestWithTimeoutV2("GET", id+"/update_agents/win", nil)
	if err != nil {
		return "", fmt.Errorf("error in creating http request with timeout: %w", err)
	}
	defer cancel()

	req.Header.Set("Authorization", "Bearer"+authenticationTokenV2)

	responseBody, err := executeHTTPRequestWithTokenValidtyV2(req, 10)
	if err != nil {
		return "", err
	}

	var apiUpdateAgentResponse ApiUpdateAgentResponse

	if err := json.Unmarshal(responseBody.Bytes(), &apiUpdateAgentResponse); err != nil {
		return "", fmt.Errorf("error in unmarshalling the agent version: %s", err)
	}

	if !apiUpdateAgentResponse.Status {
		return "", fmt.Errorf("error in getting the agent version: %s", apiUpdateAgentResponse.Message)
	}

	// Output: windowsagent1.4.147.zip
	return apiUpdateAgentResponse.AgentName, nil
}

// downloadNewAgentFile downloads the new agent file from a predefined server
// endpoint and saves it to the provided agentFullName path.
func downloadNewAgentFile(urldownload, newAgentFilePath string) error {
	// Create the file of the new agent file with excute permissions.
	file, err := createFileWithPermissions(newAgentFilePath, 0744)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	req, cancel, err := createHTTPRequestWithTimeoutV2("GET", urldownload, nil)
	if err != nil {
		return fmt.Errorf("error in creating http request with timeout: %w", err)
	}
	defer cancel()

	if err := excuteDownloadAndWriteToFile(req, file); err != nil {
		return fmt.Errorf("error executing download cyscan file: %w", err)
	}

	return nil
}

//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------

// getAndcompressAndUploadWindowsServicesV2 gets all the Windows services and
// saves them to a CSV file. It then compresses the CSV file into a zip file
// and uploads it to the server.
func getAndcompressAndUploadWindowsServicesV2() error {
	log.Info().Msg("Starting compression and upload for Windows services.")

	if err := getAllWindowsServicesAndCompressIntoZipFile(); err != nil {
		return fmt.Errorf("error in creating real service zip folder: %w", err)
	}

	zipFileName := fmt.Sprintf("realservice_%s_uploadrealservice.zip", id)
	zipFilePath := filepath.Join(CymetricxPath, "Compressed Files", zipFileName)

	responseBody, err := createAndExecuteFileUploadRequest("real_service_win/"+id, zipFilePath)
	if err != nil {
		return fmt.Errorf("error in uploading compressed Windows services: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in uploading compressed Windows services: %w", err)
	}

	log.Info().Msg("Successfully compressed and uploaded Windows services.")

	return nil
}

func getAllWindowsServicesAndCompressIntoZipFile() error {
	csvSourcePath, err := getAndStoreAllWindowsServicesInCSVFile()
	if err != nil {
		return err
	}

	csvDestinationName := fmt.Sprintf("realservice_%s_uploadrealservice.csv", id)
	zipFileName := fmt.Sprintf("realservice_%s_uploadrealservice.zip", id)
	srcToDstMap := map[string]string{
		csvSourcePath: csvDestinationName,
	}

	if err := createAndWriteToZipFile(zipFileName, srcToDstMap); err != nil {
		return err
	}

	return nil
}

// getAndStoreAllWindowsServicesInCSVFile gets all the Windows services and
// saves them to a CSV file. It returns the path of the CSV file.
func getAndStoreAllWindowsServicesInCSVFile() (string, error) {
	CSVPath := filepath.Join(CymetricxPath, "windows-services.csv")

	// Get-Service: Gets the services on a local or remote computer.
	// 				(whether it is running or not)
	// |: The pipe operator sends the output of one command to another command.
	// select *: Selects all the properties of each service one by one.
	// 		     (Name, DisplayName, Status, ServiceType, etc.)
	// Export-Csv: The Export-Csv cmdlet has a single purpose; to save the output
	//			   of a command to a CSV file.
	// -Path: Specifies the path to the CSV file.
	// -NoTypeInformation: Omits the type information from the CSV file.
	//					   In this case, it would be of value in the header of file
	//					   with value #TYPE System.ServiceProcess.ServiceController.
	// -Encoding UTF8: Specifies the type of encoding for the CSV file.
	ps1Content := fmt.Sprintf(`Get-Service | select * | Export-Csv -Path '%s' -NoTypeInformation -Encoding UTF8`, CSVPath)
	if err := execCommandWithoutOutput(powerShellPath, ps1Content); err != nil {
		return "", fmt.Errorf("failed to execute command for getting system services: %w", err)
	}

	return CSVPath, nil
}

//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------

type CommandOutputPayload struct {
	CommandID string `json:"commandID"`
	Output    string `json:"output"`
}

func runAndUploadCommandsOutputV2(commands string, commandID int, TypeOfStringBase64 int) (err error) {
	// Catch any panics.
	defer catchPanic()

	// Defer a function to check if an error occurred, and log it
	defer logError(&err, "error in runAndUploadCommandsOutputV2")

	log.Info().Str("Command:", commands).Msg(`Starting the process of running and uploading commands output...`)

	if TypeOfStringBase64 == 1 {
		commands, err = decodeData(commands)
		if err != nil {
			return fmt.Errorf("error in decoding data: %w", err)
		}
	}

	// var commandOutput string
	commandOutput, err := runRMMCommand(commands, commandID)
	if err != nil {
		return fmt.Errorf("error in runRMMCommand: %w", err)
	}

	// Specific case where a command will output to a folder and need to zip and upload this
	// folder directly.
	if strings.Contains(commands, `cypasswordaudit`) {
		srcDir := `C:\Program Files\CYMETRICX\cypasswordaudit`
		destZipPath := filepath.Join(CymetricxPath, "Compressed Files", "cypasswordaudit.zip")

		endPoint := fmt.Sprintf("upload-ntds/%s/%d", id, commandID)

		// Call the new zipAndUploadFolder function
		if err := zipAndUploadFolder(srcDir, destZipPath, endPoint); err != nil {
			return err
		}

		return nil
	}

	// jsonPayload, err := createCommandOutputPayload(strconv.Itoa(commandID), []byte(commandOutputRaw))
	jsonPayload, err := createCommandOutputPayload(commandID, commandOutput)
	if err != nil {
		return err
	}

	filePath, err := createAndCompressPayloadIntoGZipFile(jsonPayload, "uploadoutput.gz")
	if err != nil {
		return err
	}

	responseBody, err := createAndExecuteFileUploadRequest("upload_output/"+id, filePath)
	if err != nil {
		return fmt.Errorf("error in uploadoutput: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in uploading commands output")
	}

	log.Info().Str("Command:", commands).Msg("Successfully ran and uploaded commands output.")

	return nil
}

// zipAndUploadFolder zips the folder at srcDir and uploads it to the specified endpoint.
// It also deletes the zip file after a successful upload.
func zipAndUploadFolder(srcDir, destZipPath, endPoint string) error {
	// Step 1: Zip the folder
	if err := zipDir(srcDir, destZipPath); err != nil {
		return fmt.Errorf("error in zipping %s folder: %w", srcDir, err)
	}

	// Step 2: Prepare the endpoint and upload the zip file
	responseBody, err := createAndExecuteFileUploadRequest(endPoint, destZipPath)
	if err != nil {
		return fmt.Errorf("failed to execute upload request for %s: %w", srcDir, err)
	}

	// Step 3: Handle the response
	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload agent logs for %s: %w", srcDir, err)
	}

	// Step 4: Delete the zip file after the successful upload
	if err := os.Remove(destZipPath); err != nil {
		return fmt.Errorf("failed to delete %s zip file: %w", destZipPath, err)
	}

	// Step 5: Delete the folder after the successful upload
	if err := os.RemoveAll(srcDir); err != nil {
		return fmt.Errorf("failed to delete %s folder: %w", srcDir, err)
	}

	log.Info().Msgf("Successfully zipped and uploaded folder %s.", srcDir)

	return nil
}

func runRMMCommand(commands string, commandID int) (string, error) {
	fileName := fmt.Sprintf("exec-command%d.ps1", commandID)
	// commandOutput, err := createAndRunPS1FileWithOutputForExecCommand(fileName, commands)
	commandOutput, err := createAndRunPS1FileWithOutput(fileName, commands)
	if err != nil {
		return "", fmt.Errorf("error in creating and running bash file with output: %w", err)
	}

	return string(commandOutput), nil
}

type ApiGeneralResponse struct {
	Status  *bool  `json:"status"`
	Message string `json:"message"`
}

func readGeneralReponseBody(responseBody bytes.Buffer) error {
	var apiResponse ApiGeneralResponse

	if err := json.Unmarshal(responseBody.Bytes(), &apiResponse); err != nil {
		return fmt.Errorf("error in unmarshalling general response body: %w", err)
	}

	if apiResponse.Status != nil && !*apiResponse.Status {
		return fmt.Errorf("status is not true, and the message is: %s", apiResponse.Message)
	}

	return nil
}

// func createCommandOutputPayload(commandID string, commandOutputRaw []byte) ([]byte, error) {
// 	commandOutputPayload := CommandOutputPayload{
// 		CommandID: commandID,
// 		Output:    b64.StdEncoding.EncodeToString(commandOutputRaw),
// 	}

// 	jsonPayload, err := json.Marshal(commandOutputPayload)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to marshel CommandOutputPayload: %w", err)
// 	}

// 	return jsonPayload, nil

// }

func createCommandOutputPayload(commandID int, commandOutputRaw string) ([]byte, error) {
	// Convert CommandId to string
	commandIDString := strconv.Itoa(commandID)
	// Convert CommandOutputRaw to []byte and encode it to base64
	commandOutput := b64.StdEncoding.EncodeToString([]byte(commandOutputRaw))

	type CommandOutputPayload struct {
		CommandID string `json:"commandID"`
		Output    string `json:"output"`
	}

	commandOutputPayload := CommandOutputPayload{
		CommandID: commandIDString,
		Output:    commandOutput,
	}

	jsonPayload, err := json.Marshal(commandOutputPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshel CommandOutputPayload: %w", err)
	}

	return jsonPayload, nil

}

//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------

// getAndCompressAndUploadListTaskMangerV2 gets the task list and
// saves it to a CSV file. It then compresses the CSV file into a zip file
// and uploads it to the server.
func getAndCompressAndUploadListTaskMangerV2() error {
	log.Info().Msg("Starting the process of compressing and uploading list of task manager...")

	if err := getTaskListAndCompressItIntoZipFile(); err != nil {
		return fmt.Errorf("failed to create tasklist zip folder: %w", err)
	}

	zipFileName := fmt.Sprintf("tasklist_%s_uploadtasklist.zip", id)
	ZipFilePath := filepath.Join(CymetricxPath, "Compressed Files", zipFileName)

	responseBody, err := createAndExecuteFileUploadRequest("task_list_win/"+id, ZipFilePath)
	if err != nil {
		return err
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("error in uploading list task manager: %w", err)
	}

	log.Info().Msg("Successfully compressed and uploaded list of task manager.")

	return nil
}

//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------
//$ ----------------------------------------------------------------------------------------------------------------------------------------------------

// getAndCompressAndUploadWindowsInstallerApplicationsV2 gets all the installed
// applications using the Windows installer only (does not include the ones installed
// using the Windows Store nor the ones installed using 3rd party installers) and saves
// them to a CSV file. It then  compresses the CSV file into a zip file and uploads
// it to the server.
func getAndCompressAndUploadWindowsInstallerApplicationsV2() error {
	log.Info().Msg("Starting the process of compressing and uploading app manager...")

	if err := getAndCompressWindowsInstallerApplicationsIntoZipFile(); err != nil {
		return err
	}

	zipFileName := fmt.Sprintf("appmanager_%s_uploadappmanager.zip", id)
	zipFilePath := filepath.Join(CymetricxPath, "Compressed Files", zipFileName)

	responseBody, err := createAndExecuteFileUploadRequest("app_manager_win/"+id, zipFilePath)
	if err != nil {
		return err
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("failed to upload app manager to server: %w", err)
	}

	log.Info().Msg("Successfully compressed and uploaded app manager.")

	return nil
}

func compressAndUploadWindowsCertificatesV2() error {
	if !certs {
		return nil
	}

	zipFilePath, err := createCertificatesZipFile()
	if err != nil {
		return fmt.Errorf("error in creating certificates zip file: %w", err)
	}

	// sleepForRandomDelayDuration(minimalUploadInterval, maximalUploadInterval)

	responseBody, err := createAndExecuteFileUploadRequest("certs_win/"+id, zipFilePath)
	if err != nil {
		return fmt.Errorf("error in certswin: %w", err)
	}

	if err := readGeneralReponseBody(responseBody); err != nil {
		return fmt.Errorf("couldn't upload windows certificate to server: %w", err)
	}

	return nil
}

// $ ----------------------------------------------------------------------------------------------------------------------------------------------------
// $ ----------------------------------------------------------------------------------------------------------------------------------------------------
// $ ----------------------------------------------------------------------------------------------------------------------------------------------------
// $ ----------------------------------------------------------------------------------------------------------------------------------------------------
// $ ----------------------------------------------------------------------------------------------------------------------------------------------------
// $ ----------------------------------------------------------------------------------------------------------------------------------------------------
// $ ----------------------------------------------------------------------------------------------------------------------------------------------------
// $ ----------------------------------------------------------------------------------------------------------------------------------------------------
// $ ----------------------------------------------------------------------------------------------------------------------------------------------------
// $ ----------------------------------------------------------------------------------------------------------------------------------------------------

// Process variables into a map of string to string where the key is the variable name and the value is the default value
func processVariables(vars map[string]interface{}) map[string]string {
	variables := make(map[string]string)
	for key, v := range vars {
		if varMap, ok := v.(map[string]interface{}); ok {
			if defaultValue, ok := varMap["default"].(string); ok {
				variables[key] = defaultValue
			}
		}
	}
	return variables
}

// Convert controls to a list of string maps
func convertControls(controls []interface{}) []map[string]interface{} {
	// Initialize a slice of maps to store the converted controls
	converted := []map[string]interface{}{}

	for _, control := range controls {
		if controlMap, ok := control.(map[string]interface{}); ok {
			converted = append(converted, controlMap)
		}
	}

	return converted
}

// Process a single condition object
func processCondition(condition map[string]interface{}, variables map[string]string, handlers map[string]func(map[string]string, map[string]string) (map[string]string, error), controlResultList *[]interface{}, automatedValue *string, benchmarkType string) (map[string]interface{}, string, bool) {
	attributes := condition["@attributes"].(map[string]interface{})

	var auto string
	if value, ok := attributes["auto"]; ok {
		auto = value.(string)
	}
	// _ = auto

	conditionType := attributes["type"].(string)
	var returnedMaps []map[string]string

	// Handle custom_item which can be a single object or a list of objects
	var customItems []interface{}
	switch v := condition["custom_item"].(type) {
	case []interface{}:
		customItems = v
	case map[string]interface{}:
		customItems = []interface{}{v}
	default:
		// Handle the case where custom_item is not the expected type
		// fmt.Println("Unexpected type for custom_item")
		// log both the custom item and the type
		log.Error().Msgf("Unexpected type for custom_item that is value is %v and type is %T", condition["custom_item"], v)
		return nil, "", false
	}

	for _, item := range customItems {
		// Assuming custom_item is processed like other controls
		itemMap := item.(map[string]interface{})
		convertedItem := make(map[string]string)

		// Convert all values to strings
		for k, v := range itemMap {
			if strVal, ok := v.(string); ok {
				convertedItem[k] = strVal
			}
		}
		returnedMap := processSingleControl(convertedItem, variables, handlers, benchmarkType)

		// if control has a control_key, it is a control and will be shown as passed or failed
		re := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

		if _, ok := returnedMap["control_key"]; ok && returnedMap["control_key"] != "" && re.MatchString(returnedMap["control_key"]) {
			// append the control to the controlResultList
			*controlResultList = append(*controlResultList, returnedMap)
		}

		// if there is an automatic key and it is set to false, then modify the value of the automaticValue to be false
		if _, ok := returnedMap["automated"]; ok && returnedMap["automated"] == "false" {
			*automatedValue = "false"
		}

		returnedMaps = append(returnedMaps, returnedMap)
	}

	status := "true"
	pass := true
	if conditionType == "AND" {
		var faulsyReturnedMaps []map[string]string
		for _, returnedMap := range returnedMaps {
			if returnedMap["status"] == "false" {
				faulsyReturnedMaps = append(faulsyReturnedMaps, returnedMap)
			}
		}

		if len(faulsyReturnedMaps) > 0 {
			status = "false"
			pass = false
		}

	} else if conditionType == "OR" {
		status = "false"
		pass = false
		for _, returnedMap := range returnedMaps {
			if returnedMap["status"] == "true" {
				status = "true"
				pass = true
				break
			}
		}

		// if status == "false" {
		// 	faulsyReturnedMaps = returnedMaps
		// }
	}

	result := map[string]interface{}{
		"@attributes": map[string]interface{}{
			"type":   conditionType,
			"status": status,
		},
		"custom_item": returnedMaps,
	}

	return result, auto, pass
}
func checkIfReturnedMapIsControl(control map[string]string, controlResultList []interface{}) bool {

	// if control has a control_key, it is a control and will be shown as passed or failed
	if _, ok := control["control_key"]; ok && control["control_key"] != "" {

		// append the control to the controlResultList
		controlResultList = append(controlResultList, control)
	}
	return false
}

func processControls(control map[string]interface{}, handlers map[string]func(map[string]string, map[string]string) (map[string]string, error), variables map[string]string, benchmarkType string) []interface{} {
	var combinedList []interface{}
	var controlResultList []interface{}
	automatedValue := "true"
	if controlType, ok := control["item_type"]; ok && controlType == "condition" {
		conditionControlMap := make(map[string]interface{})

		// Process the condition block
		condition := control["condition"].(map[string]interface{})
		condtionKeyMap, autoKeyValue, ifPassed := processCondition(condition, variables, handlers, &controlResultList, &automatedValue, benchmarkType)
		conditionControlMap["condition"] = condtionKeyMap

		if ifPassed {
			thenMapList, ifReport := processThen(control["then"].(map[string]interface{}), variables, handlers, &controlResultList, true, &automatedValue, autoKeyValue, benchmarkType)
			conditionControlMap["then"] = thenMapList
			if ifReport {
				// read the item block and return it with status true
				// The control passed
				itemMaps := processItem(control, "true")
				conditionControlMap["control_result"] = itemMaps
			} else {
				conditionControlMap["then"] = thenMapList
			}
		} else if elseControl, ok := control["else"]; ok {
			// else block has the same logic as the "then" block
			thenMapList, ifReport := processThen(elseControl.(map[string]interface{}), variables, handlers, &controlResultList, false, &automatedValue, autoKeyValue, benchmarkType)
			if ifReport {
				// read the item block and return it with status true
				// The control passed
				itemMaps := processItem(control, "true")
				conditionControlMap["control_result"] = itemMaps
			} else {
				conditionControlMap["else"] = thenMapList
			}
		} else if !ifPassed {
			// if no else, then go back to then and you'll find the report block which you give false status
			if _, ok := control["then"]; ok {
				thenMapList, ifReport := processThen(control["then"].(map[string]interface{}), variables, handlers, &controlResultList, false, &automatedValue, autoKeyValue, benchmarkType)
				conditionControlMap["then"] = thenMapList
				if ifReport {
					// read the item block and return it with status true
					// The control passed
					itemMaps := processItem(control, "true")
					conditionControlMap["control_result"] = itemMaps
				} else {
					conditionControlMap["then"] = thenMapList
				}
				// Case where the condition is false and there is no else block
				// read the item block and return it with status false
				// returnedMap := processSingleControl(convertedItem, variables, handlers)
				itemMaps := processItem(control, "false")
				conditionControlMap["item"] = itemMaps
			}
		}

		conditionControlMap["item_type"] = "condition"
		conditionControlMap["item"] = control["item"]
		// add controlResultMap to be a value to a key "control_result"
		var controlResultMap = map[string]interface{}{
			"control_result": controlResultList,
		}

		// go over object in controlResultList and add "automated" key to each object
		for _, controlResult := range controlResultList {
			controlResultMap := controlResult.(map[string]string)
			controlResultMap["automated"] = automatedValue
		}

		combinedList = append(combinedList, controlResultMap)
	} else {
		var returnedMaps []map[string]string

		// Normal control processing
		strMap := make(map[string]string)
		for key, value := range control {
			if strVal, ok := value.(string); ok {
				strMap[key] = strVal
			}
		}
		returnedMap := processSingleControl(strMap, variables, handlers, benchmarkType)
		if returnedMap != nil {
			returnedMaps = append(returnedMaps, returnedMap)
		}

		// Append the returned map to the combined list
		for _, returnedMap := range returnedMaps {
			combinedList = append(combinedList, returnedMap)
		}
	}

	return combinedList
}

func processItem(control map[string]interface{}, status string) []map[string]string {
	var itemMaps []map[string]string

	// Handle item which can be a single object or a list of objects
	var items []interface{}
	switch v := control["item"].(type) {
	case []interface{}:
		items = v
	case map[string]interface{}:
		items = []interface{}{v}
	default:
		// Handle the case where item is not the expected type
		log.Error().Msgf("Unexpected type for item that is value is %v and type is %T", control["item"], v)
		return nil
	}

	for _, item := range items {
		itemMap := item.(map[string]interface{})
		convertedItem := make(map[string]string)
		for k, v := range itemMap {
			if strVal, ok := v.(string); ok {
				convertedItem[k] = strVal
			}
		}
		convertedItem["status"] = status

		itemMaps = append(itemMaps, convertedItem)
	}
	return itemMaps
}

// Process "then" block
// Return true if report is seen. False otherwise
func processThen(thenBlock map[string]interface{}, variables map[string]string, handlers map[string]func(map[string]string, map[string]string) (map[string]string, error), controlResultList *[]interface{}, passed bool, automatedValue *string, autoKeyValue string, benchmarkType string) (map[string]interface{}, bool) {
	// Check if "report" block exists
	if report, ok := thenBlock["report"]; ok {
		reportBlock := map[string]interface{}{
			"report": report,
		}
		_ = reportBlock

		switch v := report.(type) {
		case []interface{}:
			for _, item := range v {
				itemMap := item.(map[string]interface{})
				convertedItem := make(map[string]string)
				for k, v := range itemMap {
					if strVal, ok := v.(string); ok {
						convertedItem[k] = strVal
					}
				}

				var result string
				// If passed, then we default to true
				if passed {
					result = "true"

					// It didn't pass, it means we are now in either then or else blocks.
				} else {
					// In the case of "auto" existing, that means that there is no "else" block and i need to rely on the auto value to decide the status
					if autoKeyValue != "" {
						if autoKeyValue == "FAILED" || autoKeyValue == "WARNING" {
							result = "false"
						} else if autoKeyValue == "PASSED" {
							result = "true"
						}

						// In the case of "auto" not existing, that means that there is an "else" block and i need to rely on the "attribute_type" value to decide the status
					} else {
						attibuteType, attributeTypeExists := convertedItem["attribute_type"]
						if attributeTypeExists {
							if attibuteType == "PASSED" {
								result = "true"
							} else if attibuteType == "FAILED" || attibuteType == "WARNING" {
								result = "false"
							}
						}
					}
				}
				convertedItem["status"] = result

				// if !passed && (autoKeyValue == "FAILED" || autoKeyValue == "WARNING") {
				// 	convertedItem["status"] = "false"
				// } else if !passed && autoKeyValue == "PASSED" {
				// 	convertedItem["status"] = "true"
				// }

				*controlResultList = append(*controlResultList, convertedItem)
			}
		case map[string]interface{}:
			convertedItem := make(map[string]string)
			for k, v := range v {
				if strVal, ok := v.(string); ok {
					convertedItem[k] = strVal
				}
			}

			var result string
			// If passed, then we default to true
			if passed {
				result = "true"

				// It didn't pass, it means we are now in either then or else blocks.
			} else {
				// In the case of "auto" existing, that means that there is no "else" block and i need to rely on the auto value to decide the status
				if autoKeyValue != "" {
					if autoKeyValue == "FAILED" || autoKeyValue == "WARNING" {
						result = "false"
					} else if autoKeyValue == "PASSED" {
						result = "true"
					}

					// In the case of "auto" not existing, that means that there is an "else" block and i need to rely on the "attribute_type" value to decide the status
				} else {
					attibuteType, attributeTypeExists := convertedItem["attribute_type"]
					if attributeTypeExists {
						if attibuteType == "PASSED" {
							result = "true"
						} else if attibuteType == "FAILED" || attibuteType == "WARNING" {
							result = "false"
						}
					}
				}
			}
			convertedItem["status"] = result

			// if !passed && (autoKeyValue == "FAILED" || autoKeyValue == "WARNING") {
			// 	convertedItem["status"] = "false"
			// } else if !passed && autoKeyValue == "PASSED" {
			// 	convertedItem["status"] = "true"
			// }

			*controlResultList = append(*controlResultList, convertedItem)
		}

		// return reportBlock, true
	}

	// Check if "custom_item" block exists
	if customItems, ok := thenBlock["custom_item"]; ok {

		var items []interface{}

		// Handle custom_item which can be a single object or a list of objects
		switch v := customItems.(type) {
		case []interface{}:
			items = v
		case map[string]interface{}:
			items = []interface{}{v}
		default:
			// Handle the case where custom_item is not the expected type
			log.Error().Msgf("Unexpected type for custom_item that is value is %v and type is %T", customItems, v)
			return nil, false
		}

		var returnedMapList []map[string]string
		for _, item := range items {
			itemMap := item.(map[string]interface{})
			convertedItem := make(map[string]string)
			for k, v := range itemMap {
				if strVal, ok := v.(string); ok {
					convertedItem[k] = strVal
				}
			}
			returnedMap := processSingleControl(convertedItem, variables, handlers, benchmarkType)
			// if control has a control_key, it is a control and will be shown as passed or failed
			// Regular expression to match the desired format

			if _, ok := returnedMap["control_key"]; ok && returnedMap["control_key"] != "" {
				// append the control to the controlResultList
				*controlResultList = append(*controlResultList, returnedMap)
			}

			// if there is an automatic key and it is set to false, then modify the value of the automaticValue to be false
			if _, ok := returnedMap["automated"]; ok && returnedMap["automated"] == "false" {
				*automatedValue = "false"
			}

			returnedMapList = append(returnedMapList, returnedMap)
		}

		customItemBlock := map[string]interface{}{
			"custom_item": returnedMapList,
		}
		return customItemBlock, false
	}

	// Check if "if" block exists and process it
	if ifBlock, ok := thenBlock["if"]; ok {
		ifBlockResult, ifReport := processIfBlock(ifBlock, variables, handlers, controlResultList, automatedValue, benchmarkType)
		thenBlock["if"] = ifBlockResult
		return thenBlock, ifReport
	}

	// Return nil and false if no "report" or "custom_item" blocks are found
	return nil, false
}

func processIfBlock(ifBlock interface{}, variables map[string]string, handlers map[string]func(map[string]string, map[string]string) (map[string]string, error), controlResultList *[]interface{}, automatedValue *string, benchmarkType string) ([]map[string]interface{}, bool) {
	// The value of ifBLock can be a single object or a list of objects
	var ifBlockList []map[string]interface{}
	switch v := ifBlock.(type) {
	case map[string]interface{}:
		ifBlockList = []map[string]interface{}{v}
	case []interface{}:
		for _, item := range v {
			ifBlockList = append(ifBlockList, item.(map[string]interface{}))
		}
	default:
		log.Error().Msgf("Unexpected type for ifBlock: value=%v, type=%T", ifBlock, v)
		return nil, false
	}

	// Process each ifBlock
	var processedBlocks []map[string]interface{}
	var finalThenReport bool
	for _, ifBlock := range ifBlockList {
		processedBlock, thenReport := processSingleIfBlock(ifBlock, variables, handlers, controlResultList, automatedValue, benchmarkType)
		if processedBlock != nil {
			processedBlocks = append(processedBlocks, processedBlock)
			finalThenReport = finalThenReport || thenReport
		}
	}

	return processedBlocks, finalThenReport
}

func processSingleIfBlock(ifBlock map[string]interface{}, variables map[string]string, handlers map[string]func(map[string]string, map[string]string) (map[string]string, error), controlResultList *[]interface{}, automatedValue *string, benchmarkType string) (map[string]interface{}, bool) {
	condition := ifBlock["condition"].(map[string]interface{})
	conditionResult, autoKeyValue, pass := processCondition(condition, variables, handlers, controlResultList, automatedValue, benchmarkType)
	ifBlock["condition"] = conditionResult

	if pass {
		thenBlockResult, thenReport := processThen(ifBlock["then"].(map[string]interface{}), variables, handlers, controlResultList, true, automatedValue, autoKeyValue, benchmarkType)
		ifBlock["then"] = thenBlockResult
		return ifBlock, thenReport
	} else if elseBlock, ok := ifBlock["else"]; ok {
		elseBlockResult, elseReport := processThen(elseBlock.(map[string]interface{}), variables, handlers, controlResultList, false, automatedValue, autoKeyValue, benchmarkType)
		ifBlock["else"] = elseBlockResult
		return ifBlock, elseReport
	} else if _, ok := ifBlock["then"]; ok {
		thenBlockResult, thenReport := processThen(ifBlock["then"].(map[string]interface{}), variables, handlers, controlResultList, false, automatedValue, autoKeyValue, benchmarkType)
		ifBlock["then"] = thenBlockResult
		return ifBlock, thenReport
	}

	return nil, false
}

// Process a single control using handlers
func processSingleControl(control map[string]string, variables map[string]string, handlers map[string]func(map[string]string, map[string]string) (map[string]string, error), benchmarkType string) map[string]string {
	if objType, ok := control["type"]; ok {
		if handler, exists := handlers[objType]; exists {
			controlKey, ok := control["control_key"]
			if !ok {
				controlKey = ""
			}
			log.Debug().Msgf("Starting to process control for %s with key %s and type %s", benchmarkType, controlKey, objType)

			returnedMap, err := handler(control, variables)
			if err != nil {
				returnedMap["Exception"] = err.Error()
				returnedMap["automated"] = "true"
				return returnedMap
			}
			returnedMap["Exception"] = ""
			returnedMap["automated"] = "true"

			log.Debug().Msgf("Successfully processed control for %s with key %s and type %s", benchmarkType, controlKey, objType)
			return returnedMap
		} else {
			log.Warn().Msg("No handler for type: " + objType)
			return map[string]string{
				"automated":   "false",
				"status":      "false",
				"control_key": control["control_key"],
			}
		}
	} else {
		log.Warn().Msgf("No type for control: %v", control)
		return map[string]string{
			"automated":   "false",
			"status":      "false",
			"control_key": control["control_key"],
		}
	}
}

// ControlsOutput is the structure used to marshal the final JSON output.
type ControlsOutput struct {
	ControlOutput          []interface{} `json:"controls"`
	FinishedControlsNumber int           `json:"finish"`
	TotalControlsNumber    int           `json:"total"`
}

// ControlsProgress holds state across invocations.
type ControlsProgress struct {
	StartedProcessingControlsCount int               // controls started
	TotalControlsCount             int               // total controls available
	controlsQueue                  []controlWithVars // controls to process
	ActiveProcessCount             int               // number of controls currently running
	ResultChan                     chan interface{}  // persistent result channel for controls
	FinishedControlsCount          int               // controls finished processing
}

// controlWithVars is a struct that holds a control and its variables.
type controlWithVars struct {
	control   map[string]interface{}
	variables map[string]string
}

// processControlsData processes controls for up to `timeout`
// duration, launching up to 3 controls concurrently. If a control was started before
// the timeout and hasn't finished, it is left running; meanwhile, additional controls
// are started until 3 are running.
func processControlsData(jsonData, benchmarkType string, progress *ControlsProgress, timeout time.Duration) ([]byte, *ControlsProgress, error) {
	// Initialize the controls queue (if not already done).
	if err := initializeControlsQueue(jsonData, progress); err != nil {
		return nil, progress, err
	}

	// Process controls within the given timeout.
	finishedResults, err := processControlsWithinTimeout(benchmarkType, progress, timeout)
	if err != nil {
		return nil, progress, err
	}

	// Build the output JSON.
	jsonOutput, err := buildControlsOutput(progress, finishedResults)
	if err != nil {
		return nil, progress, err
	}

	return jsonOutput, progress, nil
}

func initializeControlsQueue(jsonData string, progress *ControlsProgress) error {
	if progress.controlsQueue != nil {
		// Already initialized.
		return nil
	}
	levels, err := parseLevels(jsonData)
	if err != nil {
		return fmt.Errorf("error unmarshalling JSON data: %w", err)
	}
	progress.TotalControlsCount = computeTotalControls(levels)
	progress.controlsQueue = make([]controlWithVars, 0, progress.TotalControlsCount)
	progress.ResultChan = make(chan interface{}, 50) // buffered channel

	// Loop through levels and build the queue.
	for _, level := range levels {
		variables, err := extractVariables(level)
		if err != nil {
			return fmt.Errorf("failed to extract variables: %w", err)
		}
		controlsSlice, err := extractControls(level)
		if err != nil {
			return fmt.Errorf("failed to extract controls: %w", err)
		}
		convertedControls := convertControls(controlsSlice)
		for _, ctrl := range convertedControls {
			// Assuming ctrl is of type map[string]interface{}.
			progress.controlsQueue = append(progress.controlsQueue, controlWithVars{
				control:   ctrl,
				variables: variables,
			})
		}
	}
	return nil
}

func processControlsWithinTimeout(benchmarkType string, progress *ControlsProgress, timeout time.Duration) ([]interface{}, error) {
	var finishedResults []interface{}
	deadline := time.Now().Add(timeout)
	resultChan := progress.ResultChan
	errorChan := make(chan error, 1) // Buffered to avoid blocking

deadlineLoop:
	for time.Now().Before(deadline) {
		// Start new controls if there's room.
		for progress.ActiveProcessCount < 3 && len(progress.controlsQueue) > 0 {
			next := progress.controlsQueue[0]
			progress.controlsQueue = progress.controlsQueue[1:]
			progress.StartedProcessingControlsCount++
			progress.ActiveProcessCount++

			// Lfaunch the control in its own goroutine.
			go func(ctrl controlWithVars) {
				// The recover() call must be placed directly inside this deferred function
				// to catch any panic that occurs in this goroutine. Nesting it inside another
				// function will prevent it from catching the panic.
				defer func() {
					if r := recover(); r != nil {
						stackTrace := make([]byte, 1024)
						for {
							n := runtime.Stack(stackTrace, false)
							if n < len(stackTrace) {
								stackTrace = stackTrace[:n]
								break
							}
							stackTrace = make([]byte, len(stackTrace)*2)
						}
						err := fmt.Errorf("%v\nStack Trace:\n%s", r, stackTrace)
						errorChan <- err // Send the error to the error channel.
					}
				}()
				// processControls2 returns a slice; here we take the first element.
				res := processControls(ctrl.control, getControlHandlers(), ctrl.variables, benchmarkType)
				resultChan <- res[0]
			}(next)
		}

		// Drain any available results before waiting.
		for {
			select {
			case res := <-resultChan:
				finishedResults = append(finishedResults, res)
				progress.ActiveProcessCount--
			default:
				// No more results available right now.
				break
			}
			// If resultChan is empty, break the inner loop.
			if len(resultChan) == 0 {
				break
			}
		}

		// Check if everything has been processed.
		if len(progress.controlsQueue) == 0 && progress.ActiveProcessCount == 0 {
			break deadlineLoop
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break deadlineLoop
		}

		// Wait for either a result or until the remaining time expires.
		select {
		case res := <-resultChan:
			finishedResults = append(finishedResults, res)
			progress.ActiveProcessCount--
		case err := <-errorChan:
			return nil, err
		case <-time.After(remaining):
			break deadlineLoop
		}
	}
	return finishedResults, nil
}

func buildControlsOutput(progress *ControlsProgress, finishedResults []interface{}) ([]byte, error) {
	progress.FinishedControlsCount = len(finishedResults)

	outputStruct := ControlsOutput{
		ControlOutput:          finishedResults,
		FinishedControlsNumber: progress.StartedProcessingControlsCount - progress.ActiveProcessCount,
		TotalControlsNumber:    progress.TotalControlsCount,
	}

	jsonOutput, err := json.Marshal(outputStruct)
	if err != nil {
		return nil, fmt.Errorf("error marshalling JSON output for controls: %w", err)
	}
	return jsonOutput, nil
}

// parseLevels unmarshals the JSON string into a slice of levels.
func parseLevels(jsonData string) ([]map[string]interface{}, error) {
	var levels []map[string]interface{}
	err := json.Unmarshal([]byte(jsonData), &levels)
	if err != nil {
		return nil, err
	}
	return levels, nil
}

// getControlHandlers returns a map of control handler functions.
func getControlHandlers() map[string]func(map[string]string, map[string]string) (map[string]string, error) {
	return map[string]func(map[string]string, map[string]string) (map[string]string, error){
		"PASSWORD_POLICY":          controls.GetPasswordPolicy,
		"REGISTRY_SETTING":         controls.GetRegistrySetting,
		"LOCKOUT_POLICY":           controls.GetLockouPolicy,
		"AUDIT_POLICY_SUBCATEGORY": controls.GetAuditPolicySubcategory,
		"REG_CHECK":                controls.GetRegCheck,
		"USER_RIGHTS_POLICY":       controls.GetUserRightsPolicy,
		"CHECK_ACCOUNT":            controls.GetCheckAccount,
		"BANNER_CHECK":             controls.GetBannerCheck,
		"AUDIT_POWERSHELL":         controls.GetAuditPowershell,
		"GUID_REGISTRY_SETTING":    controls.GetGuidRegistrySetting,
		"FILE_CONTENT_CHECK":       controls.GetFileContentCheck,
		"FILE_CHECK":               controls.GetFileCheck,
	}
}

// computeTotalControls calculates the total number of controls across all levels and updates metaData.
func computeTotalControls(levels []map[string]interface{}) int {
	total := 0
	for _, level := range levels {
		if ctrls, ok := level["controls"].([]interface{}); ok {
			total += len(ctrls)
		}
	}
	return total
}

// extractVariables converts the "variables" field from a level into a map[string]string.
func extractVariables(level map[string]interface{}) (map[string]string, error) {
	vars, ok := level["variables"].(map[string]interface{})
	if !ok {
		// If no variables, return empty map.
		return make(map[string]string), nil
		// return nil, fmt.Errorf("failed to assert variables as a map: %v", level["variables"])
	}

	return processVariables(vars), nil
}

// extractControls asserts that the "controls" field from a level is a slice.
func extractControls(level map[string]interface{}) ([]interface{}, error) {
	controlsInterface, ok := level["controls"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to assert controls as a slice: %v", level["controls"])
	}

	return controlsInterface, nil
}
