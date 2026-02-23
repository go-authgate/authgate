package version

import (
	"fmt"
	"os"
)

var (
	App       = "AuthGate"
	Version   string
	GitCommit string
	BuildTime string
	GoVersion string
	BuildOS   string
	BuildArch string
)

// PrintVersion prints the version information
func PrintVersion() {
	fmt.Fprintf(os.Stdout, "%s version %s\n", App, getVersion())
	if GitCommit != "" {
		fmt.Fprintf(os.Stdout, "Git commit: %s\n", getShortCommit())
	}
	if BuildTime != "" {
		fmt.Fprintf(os.Stdout, "Build time: %s\n", BuildTime)
	}
	if GoVersion != "" {
		fmt.Fprintf(os.Stdout, "Go version: %s\n", GoVersion)
	}
	if BuildOS != "" && BuildArch != "" {
		fmt.Fprintf(os.Stdout, "Built for: %s/%s\n", BuildOS, BuildArch)
	}
}

func getShortCommit() string {
	if len(GitCommit) > 7 {
		return GitCommit[:7]
	}
	return GitCommit
}

func getVersion() string {
	if Version != "" {
		return Version
	}
	return "dev"
}
