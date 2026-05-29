package config

import (
	"errors"
	"os"
)

type Config struct {
	VTAPIKey string
}

func Load() (*Config, error) {
	c := &Config{
		VTAPIKey: os.Getenv("VACCINE_VT_API_KEY"),
	}
	if c.VTAPIKey == "" {
		return c, errors.New("VACCINE_VT_API_KEY not set (get one at https://www.virustotal.com/gui/my-apikey)")
	}
	return c, nil
}
