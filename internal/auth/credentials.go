package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

type Credential struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
}

type CredentialsConfig struct {
	Credentials []Credential `json:"credentials"`
}

type CredentialStore struct {
	creds map[string]Credential
}

func LoadCredentials(path string) (*CredentialStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}

	var cfg CredentialsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}

	if len(cfg.Credentials) == 0 {
		return nil, fmt.Errorf("no credentials configured")
	}

	store := &CredentialStore{
		creds: make(map[string]Credential),
	}
	for _, c := range cfg.Credentials {
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return nil, fmt.Errorf("credential missing accessKeyId or secretAccessKey")
		}
		store.creds[c.AccessKeyID] = c
	}
	return store, nil
}

func (s *CredentialStore) Lookup(accessKeyID string) (Credential, bool) {
	c, ok := s.creds[accessKeyID]
	return c, ok
}
