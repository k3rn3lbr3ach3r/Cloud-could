package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// -----------------------------------------------
//   AUTO-SETUP: DEPENDENCY MANAGEMENT
// -----------------------------------------------

type ToolDep struct {
	Name        string
	Binary      string
	Cloud       string
	CheckArgs   []string            // args to get version
	InstallCmds map[string][]string // os -> shell commands
	InstallHint string
	Required    bool
	NeedsSudo   bool // whether install commands require sudo
}

type SetupConfig struct {
	FirstRunDone bool              `json:"first_run_done"`
	ToolVersions map[string]string `json:"tool_versions"`
	Platform     string            `json:"platform"`
	Arch         string            `json:"arch"`
	SkipSetup    bool              `json:"skip_setup"`
}

var cloudCouldDir = filepath.Join(homeDir(), ".cloud-could")
var setupConfigFile = filepath.Join(cloudCouldDir, "config.json")

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return os.Getenv("HOME")
	}
	return h
}

func getAllToolDeps() []ToolDep {
	return []ToolDep{
		{
			Name:      "AWS CLI",
			Binary:    "aws",
			Cloud:     "aws",
			CheckArgs: []string{"--version"},
			Required:  false,
			NeedsSudo: true,
			InstallCmds: map[string][]string{
				"linux": {
					"curl -fsSL \"https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip\" -o /tmp/awscliv2.zip",
					"cd /tmp && unzip -qo awscliv2.zip",
					"sudo /tmp/aws/install --update 2>/dev/null || /tmp/aws/install --install-dir $HOME/.local/aws-cli --bin-dir $HOME/.local/bin --update",
				},
				"darwin": {
					"curl -fsSL \"https://awscli.amazonaws.com/AWSCLIV2.pkg\" -o /tmp/AWSCLIV2.pkg",
					"sudo installer -pkg /tmp/AWSCLIV2.pkg -target /",
				},
			},
			InstallHint: "pip install awscli  OR  https://aws.amazon.com/cli/",
		},
		{
			Name:      "S3Scanner",
			Binary:    "s3scanner",
			Cloud:     "aws,gcp",
			CheckArgs: []string{"-h"},
			Required:  false,
			NeedsSudo: false,
			InstallCmds: map[string][]string{
				"linux": {
					"go install github.com/sa7mon/S3Scanner@latest",
				},
				"darwin": {
					"go install github.com/sa7mon/S3Scanner@latest",
				},
			},
			InstallHint: "go install github.com/sa7mon/S3Scanner@latest",
		},
		{
			// GCP deep-scan itself uses the native cloud.google.com/go/storage
			// SDK (no gsutil dependency), but the `gcloud` CLI is still the
			// easiest way to obtain Application Default Credentials via
			// `gcloud auth application-default login` for authenticated checks.
			Name:      "Google Cloud SDK (gcloud)",
			Binary:    "gcloud",
			Cloud:     "gcp",
			CheckArgs: []string{"version"},
			Required:  false,
			NeedsSudo: false,
			InstallCmds: map[string][]string{
				"linux": {
					"curl -fsSL https://sdk.cloud.google.com | bash -s -- --disable-prompts --install-dir=$HOME",
				},
				"darwin": {
					"curl -fsSL https://sdk.cloud.google.com | bash -s -- --disable-prompts --install-dir=$HOME",
				},
			},
			InstallHint: "https://cloud.google.com/sdk/docs/install, then run: gcloud auth application-default login",
		},
		{
			Name:      "Azure CLI",
			Binary:    "az",
			Cloud:     "azure",
			CheckArgs: []string{"version", "--output", "tsv"},
			Required:  false,
			NeedsSudo: true,
			InstallCmds: map[string][]string{
				"linux": {
					"curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash || curl -sL https://aka.ms/InstallAzureCLIDeb | sudo DIST_CODE=bookworm bash",
				},
				"darwin": {
					"brew install azure-cli 2>/dev/null || pip3 install azure-cli",
				},
			},
			InstallHint: "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash",
		},
		{
			Name:      "Alibaba Cloud CLI",
			Binary:    "aliyun",
			Cloud:     "alibaba",
			CheckArgs: []string{"version"},
			Required:  false,
			NeedsSudo: true,
			InstallCmds: map[string][]string{
				"linux": {
					"curl -fsSL https://aliyuncli.alicdn.com/aliyun-cli-linux-latest-amd64.tgz -o /tmp/aliyun-cli.tgz",
					"tar -xzf /tmp/aliyun-cli.tgz -C /tmp/",
					"sudo mv /tmp/aliyun /usr/local/bin/aliyun",
				},
				"darwin": {
					"brew install aliyun-cli 2>/dev/null || (curl -fsSL https://aliyuncli.alicdn.com/aliyun-cli-darwin-latest-amd64.tgz -o /tmp/aliyun-cli.tgz && tar -xzf /tmp/aliyun-cli.tgz -C /usr/local/bin/)",
				},
			},
			InstallHint: "https://github.com/aliyun/aliyun-cli#installation",
		},
		{
			Name:      "Go Compiler",
			Binary:    "go",
			Cloud:     "core",
			CheckArgs: []string{"version"},
			Required:  false,
			NeedsSudo: false,
			InstallCmds: map[string][]string{
				"linux": {
					"echo 'Install Go from https://go.dev/dl/'",
				},
			},
			InstallHint: "https://go.dev/dl/",
		},
		{
			Name:      "curl",
			Binary:    "curl",
			Cloud:     "core",
			CheckArgs: []string{"--version"},
			Required:  true,
			NeedsSudo: true,
			InstallCmds: map[string][]string{
				"linux": {
					"sudo apt-get install -y curl 2>/dev/null || sudo yum install -y curl 2>/dev/null || sudo pacman -S curl --noconfirm 2>/dev/null",
				},
			},
			InstallHint: "sudo apt-get install curl",
		},
		{
			Name:      "dig (DNS utils)",
			Binary:    "dig",
			Cloud:     "core",
			CheckArgs: []string{"-v"},
			Required:  false,
			NeedsSudo: true,
			InstallCmds: map[string][]string{
				"linux": {
					"sudo apt-get install -y dnsutils 2>/dev/null || sudo yum install -y bind-utils 2>/dev/null",
				},
			},
			InstallHint: "sudo apt-get install dnsutils",
		},
	}
}

// -----------------------------------------------
//   FIRST-RUN CHECK
// -----------------------------------------------

func isFirstRun() bool {
	cfg := loadSetupConfig()
	return !cfg.FirstRunDone
}

func loadSetupConfig() SetupConfig {
	cfg := SetupConfig{
		ToolVersions: make(map[string]string),
	}
	data, err := os.ReadFile(setupConfigFile)
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		logWarn("Setup config at %s is corrupt, resetting: %v", setupConfigFile, err)
		cfg = SetupConfig{ToolVersions: make(map[string]string)}
	}
	if cfg.ToolVersions == nil {
		cfg.ToolVersions = make(map[string]string)
	}
	return cfg
}

func saveSetupConfig(cfg SetupConfig) {
	if err := os.MkdirAll(cloudCouldDir, 0755); err != nil {
		logWarn("Failed to create config dir %s: %v", cloudCouldDir, err)
		return
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		logWarn("Failed to marshal setup config: %v", err)
		return
	}
	if err := os.WriteFile(setupConfigFile, data, 0644); err != nil {
		logWarn("Failed to save setup config to %s: %v", setupConfigFile, err)
	}
}

// -----------------------------------------------
//   TOOL VERSION DETECTION
// -----------------------------------------------

func getToolVersion(binary string, args []string) (bool, string) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return false, ""
	}

	cmd := exec.Command(path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Tool exists but version check failed -- still found
		return true, "installed"
	}

	version := strings.TrimSpace(string(out))
	// Extract first line only
	if idx := strings.IndexByte(version, '\n'); idx > 0 {
		version = version[:idx]
	}
	// Truncate long version strings
	if len(version) > 80 {
		version = version[:80] + "..."
	}
	return true, version
}

// -----------------------------------------------
//   SUDO PRIMING
// -----------------------------------------------

// primeSudo runs a harmless sudo command to cache the password so
// subsequent sudo calls within the install steps don't re-prompt.
func primeSudo() bool {
	fmt.Printf("\n  %sSome tools require sudo to install.%s\n", Yellow, Reset)
	fmt.Printf("  %sYou may be prompted for your password below.%s\n\n", Gray, Reset)

	cmd := exec.Command("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		logError("sudo authentication failed: %v", err)
		return false
	}
	logSuccess("sudo credentials cached")
	return true
}

// -----------------------------------------------
//   AUTO-SETUP RUNNER
// -----------------------------------------------

func runAutoSetup(interactive bool) {
	logSection("System Requirements Check")

	platform := runtime.GOOS
	arch := runtime.GOARCH
	logInfo("Platform: %s%s/%s%s", Cyan, platform, arch, Reset)

	deps := getAllToolDeps()
	var missing []ToolDep
	var found []ToolDep

	cfg := loadSetupConfig()
	cfg.Platform = platform
	cfg.Arch = arch

	fmt.Println()
	fmt.Printf("  %s%-25s %-10s %-50s%s\n", Bold, "TOOL", "STATUS", "VERSION / INFO", Reset)
	fmt.Printf("  %s%s%s\n", Gray, strings.Repeat("-", 85), Reset)

	for _, dep := range deps {
		exists, version := getToolVersion(dep.Binary, dep.CheckArgs)
		if exists {
			found = append(found, dep)
			cfg.ToolVersions[dep.Binary] = version
			fmt.Printf("  %-25s %s%-10s%s %s%s%s\n",
				dep.Name, Green, "FOUND", Reset, Gray, version, Reset)
		} else {
			missing = append(missing, dep)
			status := "MISSING"
			statusColor := Yellow
			if dep.Required {
				status = "REQUIRED"
				statusColor = Red
			}
			fmt.Printf("  %-25s %s%-10s%s %s%s%s\n",
				dep.Name, statusColor, status, Reset, Gray, dep.InstallHint, Reset)
		}
	}
	fmt.Println()

	logInfo("Found: %s%d/%d%s tools", Green, len(found), len(deps), Reset)

	if len(missing) == 0 {
		logSuccess("All tools available -- system is ready!")
		cfg.FirstRunDone = true
		saveSetupConfig(cfg)
		return
	}

	logWarn("%d tool(s) not found", len(missing))

	// On first run (not explicit -setup), auto-prompt if tools are missing
	if !interactive {
		fmt.Printf("\n  %s%sMissing tools detected on first run.%s\n", Bold, Yellow, Reset)
		fmt.Printf("  %sWould you like to install them now? [Y/n]:%s ", Bold, Reset)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		if answer == "n" || answer == "no" {
			logInfo("Skipping auto-install. Run with %s-setup%s anytime to install later.", Cyan, Reset)
			cfg.FirstRunDone = true
			cfg.SkipSetup = true
			saveSetupConfig(cfg)
			return
		}
		// User said yes (or just pressed enter) -- fall through to install
	} else {
		// Explicit -setup mode: also ask
		fmt.Printf("\n  %sWould you like to install missing tools? [Y/n]:%s ", Bold, Reset)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		if answer == "n" || answer == "no" {
			logInfo("Skipping auto-install. You can install manually later.")
			cfg.FirstRunDone = true
			cfg.SkipSetup = true
			saveSetupConfig(cfg)
			return
		}
	}

	// Check if any missing tool needs sudo
	needsSudo := false
	for _, dep := range missing {
		if dep.NeedsSudo {
			needsSudo = true
			break
		}
	}

	// Prime sudo credentials once so install steps don't keep asking
	if needsSudo {
		if !primeSudo() {
			logWarn("Cannot proceed without sudo. Install tools manually or retry.")
			logInfo("Run with %s-setup%s to try again.", Cyan, Reset)
			cfg.FirstRunDone = true
			saveSetupConfig(cfg)
			return
		}
	}

	// Install each missing tool
	installCount := 0
	for _, dep := range missing {
		cmds, ok := dep.InstallCmds[platform]
		if !ok {
			logWarn("No auto-install commands for %s on %s", dep.Name, platform)
			logInfo("  Manual install: %s", dep.InstallHint)
			continue
		}

		fmt.Println()
		logInfo("Installing %s%s%s ...", Cyan, dep.Name, Reset)
		if dep.NeedsSudo {
			logInfo("  %s(requires sudo)%s", Gray, Reset)
		}

		success := true
		for _, shellCmd := range cmds {
			logInfo("  Running: %s%s%s", Gray, shellCmd, Reset)
			cmd := exec.Command("bash", "-c", shellCmd)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				logError("  Command failed: %v", err)
				success = false
				break
			}
		}

		if success {
			// Verify installation
			exists, version := getToolVersion(dep.Binary, dep.CheckArgs)
			if exists {
				logSuccess("%s installed successfully (%s)", dep.Name, version)
				cfg.ToolVersions[dep.Binary] = version
				installCount++
			} else {
				logWarn("%s install commands ran but binary not found in PATH", dep.Name)
				logInfo("  You may need to restart your shell or add to PATH")
			}
		} else {
			logWarn("Failed to install %s -- install manually: %s", dep.Name, dep.InstallHint)
		}
	}

	fmt.Println()
	if installCount > 0 {
		logSuccess("Installed %d new tool(s)", installCount)
	}

	cfg.FirstRunDone = true
	saveSetupConfig(cfg)
}

// -----------------------------------------------
//   ENHANCED TOOL CHECK (replaces old checkTools)
// -----------------------------------------------

func checkToolsEnhanced(clouds []string) {
	logSection("Tool Availability Check")

	cloudSet := make(map[string]bool)
	for _, c := range clouds {
		cloudSet[strings.ToLower(strings.TrimSpace(c))] = true
	}

	type toolEntry struct {
		name   string
		binary string
		cloud  string
		hint   string
	}

	// GCP no longer shells out to gsutil -- it uses the native
	// cloud.google.com/go/storage SDK (gcloud.go), so there is no CLI
	// binary to check. It needs Application Default Credentials instead,
	// which resolveAuthContexts() reports on directly (run
	// `gcloud auth application-default login` or set
	// GOOGLE_APPLICATION_CREDENTIALS for authenticated checks).
	tools := []toolEntry{
		{"AWS CLI", "aws", "aws", "pip install awscli | https://aws.amazon.com/cli/"},
		{"S3Scanner", "s3scanner", "aws", "go install github.com/sa7mon/S3Scanner@latest"},
		{"Azure CLI", "az", "azure", "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"},
		{"Alibaba CLI", "aliyun", "alibaba", "https://github.com/aliyun/aliyun-cli"},
		{"curl", "curl", "core", "apt install curl"},
	}

	for _, t := range tools {
		// Skip tools for clouds we're not scanning
		if t.cloud != "core" && !cloudSet[t.cloud] {
			continue
		}

		if _, err := exec.LookPath(t.binary); err == nil {
			logSuccess("%-15s found", t.name)
		} else {
			logWarn("%-15s NOT FOUND  ->  %s", t.name, t.hint)
		}
	}

	if cloudSet["gcp"] {
		logInfo("%-15s uses native Go SDK -- run 'gcloud auth application-default login' for authenticated GCS checks", "GCP")
	}
}
