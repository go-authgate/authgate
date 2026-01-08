package version

import "fmt"

var (
	App       string = "AuthGate"
	Version   string
	GitCommit string
	BuildTime string
	GoVersion string
	BuildOS   string
	BuildArch string
)

// PrintVersion prints the version information
func PrintVersion() {
	fmt.Printf("%s version %s\n", App, getVersion())
	if GitCommit != "" {
		fmt.Printf("Git commit: %s\n", getShortCommit())
	}
	if BuildTime != "" {
		fmt.Printf("Build time: %s\n", BuildTime)
	}
	if GoVersion != "" {
		fmt.Printf("Go version: %s\n", GoVersion)
	}
	if BuildOS != "" && BuildArch != "" {
		fmt.Printf("Built for: %s/%s\n", BuildOS, BuildArch)
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
