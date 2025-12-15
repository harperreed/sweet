package appcli

import "flag"

// RuntimeConfig captures CLI flag inputs shared across binaries.
type RuntimeConfig struct {
	SeedPhrase string
	Passphrase string
	VaultPath  string
	AppDBPath  string
	DeviceID   string
	ServerURL  string
	AuthToken  string
}

// BindFlags attaches shared flags to provided FlagSet.
func (rc *RuntimeConfig) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&rc.SeedPhrase, "seed", rc.SeedPhrase, "seed phrase (mnemonic or hex)")
	fs.StringVar(&rc.Passphrase, "passphrase", rc.Passphrase, "optional passphrase")
	fs.StringVar(&rc.VaultPath, "vault-db", rc.VaultPath, "path to vault SQLite store")
	fs.StringVar(&rc.AppDBPath, "app-db", rc.AppDBPath, "path to local entity SQLite db")
	fs.StringVar(&rc.DeviceID, "device", rc.DeviceID, "stable device identifier")
	fs.StringVar(&rc.ServerURL, "server", rc.ServerURL, "sync server base URL")
	fs.StringVar(&rc.AuthToken, "token", rc.AuthToken, "bearer token")
}

// Options converts runtime config into app Options for entity.
func (rc RuntimeConfig) Options(entity string) Options {
	return Options{
		Entity:     entity,
		SeedPhrase: rc.SeedPhrase,
		Passphrase: rc.Passphrase,
		VaultPath:  rc.VaultPath,
		AppDBPath:  rc.AppDBPath,
		DeviceID:   rc.DeviceID,
		ServerURL:  rc.ServerURL,
		AuthToken:  rc.AuthToken,
	}
}
