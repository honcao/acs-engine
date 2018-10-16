package azurestack

import (
	"github.com/Azure/azure-sdk-for-go/services/preview/msi/mgmt/2015-08-31-preview/msi"
	"github.com/pkg/errors"
)

//CreateUserAssignedID - Creates a user assigned msi.
func (az *AzureClient) CreateUserAssignedID(location string, resourceGroup string, userAssignedID string) (id *msi.Identity, err error) {
	return nil, errors.New("Azure Stack did not support MSI yet")
}
