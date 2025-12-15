package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"suitesync/cmd/sweet/internal/inspect"
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
		if err := cmdRegister(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
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
	case "whoami":
		if err := cmdWhoami(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "init":
		if err := cmdInit(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "reset":
		if err := cmdReset(os.Args[2:]); err != nil {
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
	mustParse(os.Args[2:], fs)

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
	mustParse(os.Args[2:], fs)

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

func mustParse(args []string, fs *flag.FlagSet) {
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "sweet commands: summary | list | register | login | logout | status | whoami | init | reset | kv\n")
}
