package sops

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/keyservice"
)

// keyServiceServer decrypts sops data keys, delegating to the stock sops
// implementation for every key type except Azure Key Vault.
//
// sops flattens each master key to a protobuf message before handing it to a
// key service, which discards any credential configured on the key itself. A
// custom key service is therefore the supported way to supply one: azkv's
// MasterKey documents its tokenCredential field as injectable "by a (local)
// keyservice.KeyServiceServer using TokenCredential.ApplyToMasterKey".
type keyServiceServer struct {
	keyservice.Server

	// azureCredential is applied to Azure Key Vault keys. When nil, requests
	// are delegated unchanged and sops builds its own default credential.
	azureCredential azcore.TokenCredential
}

// newKeyServiceClient returns a key service that uses cred for Azure Key Vault
// keys. A nil cred yields the stock sops key service.
func newKeyServiceClient(cred azcore.TokenCredential) keyservice.KeyServiceClient {
	if cred == nil {
		return keyservice.NewLocalClient()
	}
	return keyservice.NewCustomLocalClient(keyServiceServer{azureCredential: cred})
}

func (s keyServiceServer) Decrypt(ctx context.Context, req *keyservice.DecryptRequest) (*keyservice.DecryptResponse, error) {
	key, ok := req.Key.GetKeyType().(*keyservice.Key_AzureKeyvaultKey)
	if !ok || s.azureCredential == nil {
		return s.Server.Decrypt(ctx, req)
	}

	masterKey := azkv.MasterKey{
		VaultURL:     key.AzureKeyvaultKey.GetVaultUrl(),
		Name:         key.AzureKeyvaultKey.GetName(),
		Version:      key.AzureKeyvaultKey.GetVersion(),
		EncryptedKey: string(req.GetCiphertext()),
	}
	azkv.NewTokenCredential(s.azureCredential).ApplyToMasterKey(&masterKey)

	plaintext, err := masterKey.Decrypt()
	if err != nil {
		return nil, err
	}
	return &keyservice.DecryptResponse{Plaintext: []byte(plaintext)}, nil
}
