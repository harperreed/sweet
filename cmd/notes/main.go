package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"suitesync/cmd/internal/appcli"
	"suitesync/vault"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		return
	}

	switch os.Args[1] {
	case "seed":
		phrase()
	case "upsert":
		upsert()
	case "delete":
		deleteCmd()
	case "list":
		list()
	case "sync":
		syncCmd()
	default:
		usage()
	}
}

func phrase() {
	_, s, err := vault.NewSeedPhrase()
	if err != nil {
		log.Fatalf("generate seed: %v", err)
	}
	fmt.Println(s)
}

func upsert() {
	fs := flag.NewFlagSet("upsert", flag.ExitOnError)
	var cfg appcli.RuntimeConfig
	cfg.BindFlags(fs)
	id := fs.String("id", "", "note id")
	title := fs.String("title", "", "note title")
	body := fs.String("body", "", "note body")
	mustParse(os.Args[2:], fs)

	if err := runApp(cfg, func(ctx context.Context, app *appcli.App) error {
		payload := map[string]any{
			"title": *title,
			"body":  *body,
		}
		return app.Upsert(ctx, *id, payload)
	}); err != nil {
		log.Fatal(err)
	}
}

func deleteCmd() {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	var cfg appcli.RuntimeConfig
	cfg.BindFlags(fs)
	id := fs.String("id", "", "note id")
	mustParse(os.Args[2:], fs)

	if err := runApp(cfg, func(ctx context.Context, app *appcli.App) error {
		return app.Delete(ctx, *id)
	}); err != nil {
		log.Fatal(err)
	}
}

func list() {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var cfg appcli.RuntimeConfig
	cfg.BindFlags(fs)
	mustParse(os.Args[2:], fs)

	if err := runApp(cfg, func(ctx context.Context, app *appcli.App) error {
		items, err := app.DumpRecords(ctx)
		if err != nil {
			return err
		}
		for _, item := range items {
			fmt.Printf("%s: %v (op=%v updated=%v)\n", item["entity_id"], item["payload"], item["op"], time.Unix(item["updated_at"].(int64), 0).UTC())
		}
		return nil
	}); err != nil {
		log.Fatal(err)
	}
}

func syncCmd() {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	var cfg appcli.RuntimeConfig
	cfg.BindFlags(fs)
	mustParse(os.Args[2:], fs)

	if err := runApp(cfg, func(ctx context.Context, app *appcli.App) error {
		return app.Sync(ctx)
	}); err != nil {
		log.Fatal(err)
	}
}

const (
	noteEntity = "note"
	// Unique AppID for notes CLI - ensures namespace isolation from other apps
	notesAppID = "ad431033-a18b-44d7-9ec0-b6493843ce3f"
)

func runApp(cfg appcli.RuntimeConfig, fn func(context.Context, *appcli.App) error) (err error) {
	ctx := context.Background()
	app, err := appcli.NewApp(cfg.Options(notesAppID, noteEntity))
	if err != nil {
		return fmt.Errorf("init app: %w", err)
	}
	defer func() {
		if cerr := app.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if err := fn(ctx, app); err != nil {
		return fmt.Errorf("%s: %w", noteEntity, err)
	}
	return nil
}

func mustParse(args []string, fs *flag.FlagSet) {
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "notes commands: seed | upsert | delete | list | sync\n")
}
