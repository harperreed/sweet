package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/harperreed/sweet/cmd/internal/appcli"
	"github.com/harperreed/sweet/vault"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "seed":
		phrase()
	case "upsert":
		upsert()
	case "delete":
		deleteCmd()
	case "sync":
		syncCmd()
	case "list":
		list()
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
	id := fs.String("id", "", "todo id")
	text := fs.String("text", "", "todo text")
	done := fs.Bool("done", false, "mark complete")
	mustParse(os.Args[2:], fs)

	if err := runApp(cfg, func(ctx context.Context, app *appcli.App) error {
		payload := map[string]any{
			"text": *text,
			"done": *done,
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
	id := fs.String("id", "", "todo id")
	mustParse(os.Args[2:], fs)

	if err := runApp(cfg, func(ctx context.Context, app *appcli.App) error {
		return app.Delete(ctx, *id)
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

const (
	todoEntity = "todo"
	// Unique AppID for todo CLI - ensures namespace isolation from other apps
	todoAppID = "bddfd5a4-e494-4f65-9057-42b672eded2c"
)

func runApp(cfg appcli.RuntimeConfig, fn func(context.Context, *appcli.App) error) (err error) {
	ctx := context.Background()
	app, err := appcli.NewApp(cfg.Options(todoAppID, todoEntity))
	if err != nil {
		return fmt.Errorf("init app: %w", err)
	}
	defer func() {
		if cerr := app.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if err := fn(ctx, app); err != nil {
		return fmt.Errorf("%s: %w", todoEntity, err)
	}
	return nil
}

func mustParse(args []string, fs *flag.FlagSet) {
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "todo commands: seed | upsert | delete | sync | list\n")
}
