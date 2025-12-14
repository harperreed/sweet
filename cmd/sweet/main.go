package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"suitesync/cmd/sweet/internal/inspect"
	"suitesync/vault"
)

const defaultAppDBPath = "./suite-sync.db"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "summary":
		summaryCmd()
	case "list":
		listCmd()
	case "register":
		registerCmd()
	case "old-login":
		oldLoginCmd()
	case "login":
		if err := cmdLogin(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "logout":
		if err := cmdLogout(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "status":
		if err := cmdStatus(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "rotate-seed":
		if err := cmdRotateSeed(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "init":
		if err := cmdInit(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "kv":
		if err := cmdKV(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
	}
}

func summaryCmd() {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	appDB := fs.String("app-db", defaultAppDBPath, "path to app SQLite db")
	mustParse(fs)

	if err := withInspector(*appDB, func(ctx context.Context, insp *inspect.Inspector) error {
		rows, err := insp.Summary(ctx)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("no records found")
			return nil
		}
		for _, row := range rows {
			fmt.Printf("%s\t%d\n", row.Entity, row.Count)
		}
		return nil
	}); err != nil {
		log.Fatal(err)
	}
}

func listCmd() {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	appDB := fs.String("app-db", defaultAppDBPath, "path to app SQLite db")
	entity := fs.String("entity", "", "entity name to inspect (todo, note, log)")
	limit := fs.Int("limit", 25, "maximum rows to display")
	mustParse(fs)

	if err := withInspector(*appDB, func(ctx context.Context, insp *inspect.Inspector) error {
		records, err := insp.List(ctx, *entity, *limit)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			fmt.Println("no records found")
			return nil
		}
		for _, rec := range records {
			fmt.Printf("%s (%s) op=%s updated=%s\n", rec.EntityID, rec.Entity, rec.Op, time.Unix(rec.Updated, 0).UTC().Format(time.RFC3339))
			fmt.Println(indentJSON(rec.Payload))
			fmt.Println()
		}
		return nil
	}); err != nil {
		log.Fatal(err)
	}
}

func withInspector(path string, fn func(context.Context, *inspect.Inspector) error) error {
	insp, err := inspect.Open(path)
	if err != nil {
		return err
	}
	var closeErr error
	defer func() {
		if cerr := insp.Close(); cerr != nil && closeErr == nil {
			closeErr = cerr
		}
	}()
	if err := fn(context.Background(), insp); err != nil {
		return err
	}
	return closeErr
}

func indentJSON(raw string) string {
	if raw == "" {
		return "<empty>"
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(raw), "", "  "); err != nil {
		return raw
	}
	return buf.String()
}

func mustParse(fs *flag.FlagSet) {
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "sweet commands: summary | list | register | old-login | login | logout | status | rotate-seed | init | kv\n")
}

func registerCmd() {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	pbURL := fs.String("pb-url", "", "PocketBase base URL (https://example.com)")
	server := fs.String("server", "", "sync server base URL")
	username := fs.String("username", "", "account username")
	password := fs.String("password", "", "account password")
	email := fs.String("email", "", "account email (optional)")
	keyPath := fs.String("key", vault.DefaultSSHKeyPath(), "SSH private key path to register")
	keyPass := fs.String("key-passphrase", "", "optional SSH key passphrase")
	mustParse(fs)

	require(*pbURL != "", "-pb-url required")
	require(*server != "", "-server required")
	require(*username != "", "-username required")
	require(*password != "", "-password required")

	pbClient, err := newPocketBaseClient(*pbURL)
	if err != nil {
		log.Fatal(err)
	}

	seed, phrase, err := vault.NewSeedPhrase()
	if err != nil {
		log.Fatalf("generate seed: %v", err)
	}
	keys, err := vault.DeriveKeys(seed, "", vault.DefaultKDFParams())
	if err != nil {
		log.Fatalf("derive keys: %v", err)
	}

	mail := strings.TrimSpace(*email)
	if mail == "" {
		mail = fmt.Sprintf("%s@example.invalid", *username)
	}

	ctx := context.Background()
	if err := pbClient.Register(ctx, *username, mail, *password, keys.UserID()); err != nil {
		log.Fatalf("pocketbase register: %v", err)
	}

	authClient := vault.NewAuthClient(*server)
	if err := authClient.RegisterWithKeyFile(ctx, keys.UserID(), *keyPath, []byte(*keyPass)); err != nil {
		log.Fatalf("register ssh key: %v", err)
	}

	fmt.Println("Registration successful!")
	fmt.Println("Seed phrase (store securely):")
	fmt.Println(phrase)
}

func oldLoginCmd() {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	pbURL := fs.String("pb-url", "", "PocketBase base URL")
	server := fs.String("server", "", "sync server base URL")
	username := fs.String("username", "", "account username")
	password := fs.String("password", "", "account password")
	seedPhrase := fs.String("seed", "", "seed phrase (hex)")
	keyPath := fs.String("key", vault.DefaultSSHKeyPath(), "SSH private key path")
	keyPass := fs.String("key-passphrase", "", "optional SSH key passphrase")
	autoRegister := fs.Bool("register-key", false, "register SSH key before login")
	mustParse(fs)

	require(*pbURL != "", "-pb-url required")
	require(*server != "", "-server required")
	require(*username != "", "-username required")
	require(*password != "", "-password required")
	require(*seedPhrase != "", "-seed required")

	pbClient, err := newPocketBaseClient(*pbURL)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	if err := pbClient.Login(ctx, *username, *password); err != nil {
		log.Fatalf("pocketbase login: %v", err)
	}

	seed, err := vault.ParseSeedPhrase(*seedPhrase)
	if err != nil {
		log.Fatalf("parse seed: %v", err)
	}
	keys, err := vault.DeriveKeys(seed, "", vault.DefaultKDFParams())
	if err != nil {
		log.Fatalf("derive keys: %v", err)
	}

	authClient := vault.NewAuthClient(*server)
	token, err := authClient.LoginWithKeyFile(ctx, keys.UserID(), *keyPath, []byte(*keyPass), *autoRegister)
	if err != nil {
		log.Fatalf("login via ssh key: %v", err)
	}

	fmt.Println(token.Token)
	fmt.Fprintf(os.Stderr, "token expires %s\n", token.Expires.Format(time.RFC3339))
}

func require(cond bool, msg string) {
	if !cond {
		log.Fatal(msg)
	}
}
