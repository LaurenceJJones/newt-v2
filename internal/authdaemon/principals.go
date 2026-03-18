package authdaemon

import (
	"encoding/json"
	"fmt"
	"os"
)

// GetPrincipals returns the principals configured for a username.
func GetPrincipals(path, username string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("principals file path is required")
	}
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read principals file: %w", err)
	}

	data := make(map[string][]string)
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("decode principals file: %w", err)
	}

	return data[username], nil
}
