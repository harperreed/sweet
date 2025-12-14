// ABOUTME: init.go provides the init command to create or recreate sweet configuration.
// ABOUTME: Generates new seed phrase and device ID, creates config file.
package main

import (
	"flag"
	"fmt"
)

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite existing config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if ConfigExists() && !*force {
		return fmt.Errorf("config already exists at %s (use --force to overwrite)", ConfigPath())
	}

	cfg, err := InitConfig()
	if err != nil {
		return err
	}

	fmt.Printf("Device ID: %s\n", cfg.DeviceID)
	fmt.Println("\nConfiguration initialized successfully!")
	fmt.Println("You can now use 'sweet kv' commands.")

	return nil
}
