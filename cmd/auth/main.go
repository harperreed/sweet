package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"suitesync/vault"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "register":
		registerCmd()
	case "login":
		loginCmd()
	default:
		usage()
	}
}

func registerCmd() {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "", "sync server base URL")
	user := fs.String("user", "", "user id (derived from vault keys)")
	keyPath := fs.String("key", vault.DefaultSSHKeyPath(), "SSH private key path")
	passphrase := fs.String("passphrase", "", "optional key passphrase")
	mustParse(fs)

	require(*server != "", "-server is required")
	require(*user != "", "-user is required")

	ctx := context.Background()
	client := vault.NewAuthClient(*server)
	if err := client.RegisterWithKeyFile(ctx, *user, *keyPath, []byte(*passphrase)); err != nil {
		log.Fatalf("register: %v", err)
	}
	fmt.Println("registration updated")
}

func loginCmd() {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "sync server base URL")
	user := fs.String("user", "", "user id (derived from vault keys)")
	keyPath := fs.String("key", vault.DefaultSSHKeyPath(), "SSH private key path")
	passphrase := fs.String("passphrase", "", "optional key passphrase")
	autoReg := fs.Bool("register", false, "register key before login")
	outFile := fs.String("out", "", "optional file to write bearer token")
	mustParse(fs)

	require(*server != "", "-server is required")
	require(*user != "", "-user is required")

	ctx := context.Background()
	client := vault.NewAuthClient(*server)
	tok, err := client.LoginWithKeyFile(ctx, *user, *keyPath, []byte(*passphrase), *autoReg)
	if err != nil {
		log.Fatalf("login: %v", err)
	}

	fmt.Println(tok.Token)
	fmt.Fprintf(os.Stderr, "token expires %s\n", tok.Expires.Format(time.RFC3339))
	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(tok.Token+"\n"), 0o600); err != nil {
			log.Fatalf("write token: %v", err)
		}
	}
}

func mustParse(fs *flag.FlagSet) {
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
}

func require(ok bool, msg string) {
	if !ok {
		log.Fatalf("%s", msg)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: auth register|login")
}
