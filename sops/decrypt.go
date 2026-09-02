package sops

import (
	"fmt"
	"time"

	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
)

// decryptData mirrors decrypt.DataWithFormat from the sops library, differing
// only in that the caller chooses the key service used to recover the data
// key. The decrypt package exposes no way to do that: decrypt.Data takes no
// options and hardcodes keyservice.NewLocalClient.
func decryptData(data []byte, format string, svc keyservice.KeyServiceClient) ([]byte, error) {
	store := common.StoreForFormat(formats.FormatFromString(format), config.NewStoresConfig())

	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return nil, err
	}

	key, err := tree.Metadata.GetDataKeyWithKeyServices([]keyservice.KeyServiceClient{svc}, nil)
	if err != nil {
		return nil, err
	}

	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return nil, err
	}

	// Compare the MAC of the decrypted tree against the one stored in the
	// document, confirming integrity was preserved.
	originalMac, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		key,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt original mac: %w", err)
	}
	if originalMac != mac {
		return nil, fmt.Errorf("Failed to verify data integrity. expected mac %q, got %q", originalMac, mac)
	}

	return store.EmitPlainFile(tree.Branches)
}
