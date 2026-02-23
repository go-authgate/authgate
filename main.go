//	@title			AuthGate API
//	@version		1.0
//	@description	OAuth 2.0 Device Authorization Grant (RFC 8628) server
//	@termsOfService	http://swagger.io/terms/

//	@contact.name	API Support
//	@contact.url	https://github.com/go-authgate/authgate
//	@contact.email	appleboy.tw@gmail.com

//	@license.name	MIT
//	@license.url	https://github.com/go-authgate/authgate/blob/main/LICENSE

//	@host		localhost:8080
//	@BasePath	/

//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Type "Bearer" followed by a space and JWT token.

//	@securityDefinitions.apikey	SessionAuth
//	@in							cookie
//	@name						oauth_session
//	@description				Session cookie for authenticated users

package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/go-authgate/authgate/internal/bootstrap"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/version"

	_ "github.com/go-authgate/authgate/api" // swagger docs
)

//go:embed internal/templates/*
var templatesFS embed.FS

func main() {
	// Define flags
	showVersion := flag.Bool("version", false, "Show version information")
	flag.BoolVar(showVersion, "v", false, "Show version information (shorthand)")
	flag.Usage = printUsage
	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		version.PrintVersion()
		os.Exit(0)
	}

	// Check if command is provided
	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	// Handle subcommands
	switch args[0] {
	case "server":
		runServer()
	default:
		fmt.Fprintf(os.Stdout, "Unknown command: %s\n\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stdout, "Usage: %s [OPTIONS] COMMAND\n\n", os.Args[0])
	fmt.Fprintln(os.Stdout, "OAuth 2.0 Device Authorization Grant server")
	fmt.Fprintln(os.Stdout, "\nCommands:")
	fmt.Fprintln(os.Stdout, "  server    Start the OAuth server")
	fmt.Fprintln(os.Stdout, "\nOptions:")
	fmt.Fprintln(os.Stdout, "  -v, --version    Show version information")
	fmt.Fprintln(os.Stdout, "  -h, --help       Show this help message")
}

func runServer() {
	cfg := config.Load()

	if err := bootstrap.Run(cfg, templatesFS); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
