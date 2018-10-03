package storage

import (
	"github.com/Azure/azure-sdk-for-go/storage"
)

// DeleteBlobOptions includes the options for a delete blob operation
type DeleteBlobOptions storage.DeleteBlobOptions

// CreateContainerOptions includes the options for a create container operation
type CreateContainerOptions storage.CreateContainerOptions

// PutBlobOptions includes the options any put blob operation
// (page, block, append)
type PutBlobOptions storage.PutBlobOptions
