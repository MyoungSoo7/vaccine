package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds all runtime settings, loaded from (in order of precedence):
//  1. Environment variables (highest)
//  2. ~/.vaccine/config.json
//  3. Defaults
type Config struct {
	VTAPIKey       string   `json:"vt_api_key,omitempty"`
	CacheDir       string   `json:"cache_dir,omitempty"`
	CacheTTLHours  int      `json:"cache_ttl_hours,omitempty"`
	BlocklistPaths []string `json:"blocklist_paths,omitempty"`
	WhitelistPaths []string `json:"whitelist_paths,omitempty"`
	TelegramBotToken string `json:"telegram_bot_token,omitempty"`
	TelegramChatID   string `json:"telegram_chat_id,omitempty"`
	URLhausFeedURL   string `json:"urlhaus_feed_url,omitempty"`
	WatchIntervalMin int    `json:"watch_interval_min,omitempty"`
	MaxFileMB        int    `json:"max_file_mb,omitempty"`
	VTRateSeconds    int    `json:"vt_rate_seconds,omitempty"`
}

// Default cache and feed locations.
const (
	defaultCacheTTL    = 24
	defaultURLhausFeed = "https://urlhaus.abuse.ch/downloads/csv_recent/"
	defaultWatchMin    = 60
	defaultMaxFileMB   = 100
	defaultVTRate      = 16
)

// Load merges defaults + file + environment.
// If the file is missing it is silently ignored.
// Returns ErrNoVTKey when VT key is empty AND the caller needs it
// (callers that don't need VT may ignore that specific error).
var ErrNoVTKey = errors.New("VACCINE_VT_API_KEY not set (get one at https://www.virustotal.com/gui/my-apikey)")

func Load() (*Config, error) {
	c := defaults()

	if cfgPath, err := defaultConfigPath(); err == nil {
		if data, err := os.ReadFile(cfgPath); err == nil {
			var fromFile Config
			if err := json.Unmarshal(data, &fromFile); err != nil {
				return nil, fmt.Errorf("parse %s: %w", cfgPath, err)
			}
			c.mergeFromFile(&fromFile)
		}
	}

	c.applyEnv()

	if err := os.MkdirAll(c.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("cache dir %s: %w", c.CacheDir, err)
	}

	if c.VTAPIKey == "" {
		return c, ErrNoVTKey
	}
	return c, nil
}

func defaults() *Config {
	home, _ := os.UserHomeDir()
	cache := filepath.Join(home, ".vaccine", "cache")
	return &Config{
		CacheDir:         cache,
		CacheTTLHours:    defaultCacheTTL,
		URLhausFeedURL:   defaultURLhausFeed,
		WatchIntervalMin: defaultWatchMin,
		MaxFileMB:        defaultMaxFileMB,
		VTRateSeconds:    defaultVTRate,
	}
}

func defaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".vaccine", "config.json"), nil
}

func (c *Config) mergeFromFile(f *Config) {
	if f.VTAPIKey != "" {
		c.VTAPIKey = f.VTAPIKey
	}
	if f.CacheDir != "" {
		c.CacheDir = f.CacheDir
	}
	if f.CacheTTLHours > 0 {
		c.CacheTTLHours = f.CacheTTLHours
	}
	if len(f.BlocklistPaths) > 0 {
		c.BlocklistPaths = append(c.BlocklistPaths, f.BlocklistPaths...)
	}
	if len(f.WhitelistPaths) > 0 {
		c.WhitelistPaths = append(c.WhitelistPaths, f.WhitelistPaths...)
	}
	if f.TelegramBotToken != "" {
		c.TelegramBotToken = f.TelegramBotToken
	}
	if f.TelegramChatID != "" {
		c.TelegramChatID = f.TelegramChatID
	}
	if f.URLhausFeedURL != "" {
		c.URLhausFeedURL = f.URLhausFeedURL
	}
	if f.WatchIntervalMin > 0 {
		c.WatchIntervalMin = f.WatchIntervalMin
	}
	if f.MaxFileMB > 0 {
		c.MaxFileMB = f.MaxFileMB
	}
	if f.VTRateSeconds > 0 {
		c.VTRateSeconds = f.VTRateSeconds
	}
}

func (c *Config) applyEnv() {
	if v := os.Getenv("VACCINE_VT_API_KEY"); v != "" {
		c.VTAPIKey = v
	}
	if v := os.Getenv("VACCINE_CACHE_DIR"); v != "" {
		c.CacheDir = v
	}
	if v := os.Getenv("VACCINE_TELEGRAM_BOT_TOKEN"); v != "" {
		c.TelegramBotToken = v
	}
	if v := os.Getenv("VACCINE_TELEGRAM_CHAT_ID"); v != "" {
		c.TelegramChatID = v
	}
}
