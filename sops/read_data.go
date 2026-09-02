package sops

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/keyservice"
	"gopkg.in/yaml.v3"

	"github.com/carlpett/terraform-provider-sops/sops/internal/dotenv"
	"github.com/carlpett/terraform-provider-sops/sops/internal/ini"
)

func readData(content []byte, format string, svc keyservice.KeyServiceClient) (map[string]string, string, error) {
	cleartext, err := decryptData(content, format, svc)
	if err != nil {
		// sops reports why each individual key failed through UserError, while
		// Error only says how many key groups succeeded. Without the former, an
		// authentication failure is indistinguishable from a missing key.
		var userErr sops.UserError
		if errors.As(err, &userErr) {
			err = errors.New(userErr.UserError())
		}
		return nil, "", fmt.Errorf("Error decrypting sops file: %w", err)
	}

	var data map[string]interface{}
	switch format {
	case "json":
		err = json.Unmarshal(cleartext, &data)
	case "yaml":
		err = yaml.Unmarshal(cleartext, &data)
	case "dotenv":
		err = dotenv.Unmarshal(cleartext, &data)
	case "ini":
		err = ini.Unmarshal(cleartext, &data)
	}
	if err != nil {
		return nil, "", fmt.Errorf("Error parsing decrypted data: %w", err)
	}

	return flatten(data), string(cleartext), nil
}
