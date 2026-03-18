package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/fosrl/newt/internal/app"
	"github.com/fosrl/newt/internal/authdaemon"
)

func handleSubcommand(args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) < 1 {
		return false, nil
	}

	switch args[0] {
	case "auth-daemon":
		if len(args) >= 2 && args[1] == "principals" {
			return true, runPrincipalsCmd(args[2:], stdout, stderr)
		}
		return true, fmt.Errorf("auth-daemon subcommand requires 'principals'")
	default:
		return false, nil
	}
}

func runPrincipalsCmd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("auth-daemon principals", flag.ContinueOnError)
	fs.SetOutput(stderr)

	principalsFile := fs.String("principals-file", app.DefaultConfig().AuthDaemonPrincipals, "Path to the principals file")
	username := fs.String("username", "", "Username to look up")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("username is required")
	}

	list, err := authdaemon.GetPrincipals(*principalsFile, *username)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		_, err = fmt.Fprintln(stdout)
		return err
	}
	for _, principal := range list {
		if _, err := fmt.Fprintln(stdout, principal); err != nil {
			return err
		}
	}
	return nil
}
