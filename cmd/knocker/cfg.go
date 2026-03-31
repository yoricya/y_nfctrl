package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
)

type Config struct {
	Addr string `json:"addr"`
	Key  string `json:"key"`
}

func getConfigPath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "nfctrl_knocker_cfg.json")
}

func loadConfig() (*Config, error) {
	data, err := os.ReadFile(getConfigPath())
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	err = json.Unmarshal(data, cfg)
	return cfg, err
}

func saveConfig(cfg Config) error {
	_, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return err
	}

	data, _ := json.Marshal(cfg)
	_ = os.WriteFile(getConfigPath(), data, 0644)

	return nil
}
