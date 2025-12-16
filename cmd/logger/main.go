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

	switch os.Args[1] {
	case "seed":
		phrase()
	case "append":
		appendCmd()
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

func appendCmd() {
	fs := flag.NewFlagSet("append", flag.ExitOnError)
	var cfg appcli.RuntimeConfig
	cfg.BindFlags(fs)
	message := fs.String("message", "", "log message")
	level := fs.String("level", "info", "log level")
	mustParse(os.Args[2:], fs)

	if err := runApp(cfg, func(ctx context.Context, app *appcli.App) error {
		payload := map[string]any{
			"message": *message,
			"level":   *level,
		}
		_, err := app.Append(ctx, payload)
		return err
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
	logEntity = "log"
	// Unique AppID for logger CLI - ensures namespace isolation from other apps
	loggerAppID = "0365fb65-26e1-4a22-9760-d5e1cb75c740"
)

func runApp(cfg appcli.RuntimeConfig, fn func(context.Context, *appcli.App) error) (err error) {
	ctx := context.Background()
	app, err := appcli.NewApp(cfg.Options(loggerAppID, logEntity))
	if err != nil {
		return fmt.Errorf("init app: %w", err)
	}
	defer func() {
		if cerr := app.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if err := fn(ctx, app); err != nil {
		return fmt.Errorf("%s: %w", logEntity, err)
	}
	return nil
}

func mustParse(args []string, fs *flag.FlagSet) {
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "logger commands: seed | append | list | sync\n")
}
