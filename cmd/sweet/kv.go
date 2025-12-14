// ABOUTME: kv.go implements a simple key/value CLI interface using vault library.
// ABOUTME: Provides set, get, list, delete, and sync commands for encrypted K/V storage.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"suitesync/cmd/internal/appcli"
)

const kvEntity = "kv"

type parsedConfig struct {
	runtime appcli.RuntimeConfig
	flagSet *flag.FlagSet
}

func loadRuntimeConfig(args []string) (*parsedConfig, error) {
	// Load config from file (with env overrides)
	fileCfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// Create runtime config with defaults from file
	rtCfg := appcli.RuntimeConfig{
		SeedPhrase: fileCfg.Seed,
		VaultPath:  fileCfg.VaultDB,
		AppDBPath:  fileCfg.AppDB,
		DeviceID:   fileCfg.DeviceID,
		ServerURL:  fileCfg.Server,
		AuthToken:  fileCfg.Token,
	}

	// Parse flags (flags override config)
	fs := flag.NewFlagSet("kv", flag.ExitOnError)
	rtCfg.BindFlags(fs)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return &parsedConfig{
		runtime: rtCfg,
		flagSet: fs,
	}, nil
}

func cmdKV(args []string) error {
	// Auto-initialize config if it doesn't exist
	if !ConfigExists() {
		fmt.Fprintf(os.Stderr, "No config found. Initializing sweet...\n")
		if _, err := InitConfig(); err != nil {
			return fmt.Errorf("auto-init config: %w", err)
		}
		fmt.Fprintln(os.Stderr)
	}

	if len(args) < 1 {
		return fmt.Errorf("kv requires a subcommand: set | get | list | delete | sync")
	}

	switch args[0] {
	case "set":
		return kvSet(args[1:])
	case "get":
		return kvGet(args[1:])
	case "list":
		return kvList(args[1:])
	case "delete":
		return kvDelete(args[1:])
	case "sync":
		return kvSync(args[1:])
	default:
		return fmt.Errorf("unknown kv subcommand: %s", args[0])
	}
}

func kvSet(args []string) error {
	cfg, err := loadRuntimeConfig(args)
	if err != nil {
		return err
	}

	fs := cfg.flagSet
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: kv set <key> <value>")
	}

	key := fs.Arg(0)
	value := fs.Arg(1)

	return runKVApp(cfg.runtime, func(ctx context.Context, app *appcli.App) error {
		payload := map[string]any{
			"value": value,
		}
		if err := app.Upsert(ctx, key, payload); err != nil {
			return err
		}
		fmt.Printf("Set: %s = %s\n", key, value)
		return nil
	})
}

func kvGet(args []string) error {
	cfg, err := loadRuntimeConfig(args)
	if err != nil {
		return err
	}

	fs := cfg.flagSet
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: kv get <key>")
	}

	key := fs.Arg(0)

	return runKVApp(cfg.runtime, func(ctx context.Context, app *appcli.App) error {
		records, err := app.DumpRecords(ctx)
		if err != nil {
			return err
		}

		for _, rec := range records {
			if rec["entity_id"] == key {
				payloadMap, ok := rec["payload"].(map[string]any)
				if !ok {
					return fmt.Errorf("invalid payload format")
				}
				value, exists := payloadMap["value"]
				if !exists {
					return fmt.Errorf("key not found: %s", key)
				}
				fmt.Println(value)
				return nil
			}
		}
		return fmt.Errorf("key not found: %s", key)
	})
}

func kvList(args []string) error {
	cfg, err := loadRuntimeConfig(args)
	if err != nil {
		return err
	}

	return runKVApp(cfg.runtime, func(ctx context.Context, app *appcli.App) error {
		records, err := app.DumpRecords(ctx)
		if err != nil {
			return err
		}

		if len(records) == 0 {
			fmt.Println("no key/value pairs found")
			return nil
		}

		for _, rec := range records {
			key := rec["entity_id"]
			payloadMap, ok := rec["payload"].(map[string]any)
			if !ok {
				continue
			}
			value := payloadMap["value"]
			updatedAt := time.Unix(rec["updated_at"].(int64), 0).UTC().Format(time.RFC3339)
			fmt.Printf("%s = %v (updated: %s)\n", key, value, updatedAt)
		}
		return nil
	})
}

func kvDelete(args []string) error {
	cfg, err := loadRuntimeConfig(args)
	if err != nil {
		return err
	}

	fs := cfg.flagSet
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: kv delete <key>")
	}

	key := fs.Arg(0)

	return runKVApp(cfg.runtime, func(ctx context.Context, app *appcli.App) error {
		if err := app.Delete(ctx, key); err != nil {
			return err
		}
		fmt.Printf("Deleted: %s\n", key)
		return nil
	})
}

func kvSync(args []string) error {
	cfg, err := loadRuntimeConfig(args)
	if err != nil {
		return err
	}

	return runKVApp(cfg.runtime, func(ctx context.Context, app *appcli.App) error {
		if err := app.Sync(ctx); err != nil {
			return err
		}
		fmt.Println("Sync complete")
		return nil
	})
}

func runKVApp(cfg appcli.RuntimeConfig, fn func(context.Context, *appcli.App) error) (err error) {
	ctx := context.Background()
	app, err := appcli.NewApp(cfg.Options(kvEntity))
	if err != nil {
		return fmt.Errorf("init app: %w", err)
	}
	defer func() {
		if cerr := app.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if err := fn(ctx, app); err != nil {
		return fmt.Errorf("%s: %w", kvEntity, err)
	}
	return nil
}
