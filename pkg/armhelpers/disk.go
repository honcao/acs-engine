package armhelpers

import (
	"context"
)

// DeleteManagedDisk deletes a managed disk.
func (az *AzureClient) DeleteManagedDisk(ctx context.Context, resourceGroupName string, diskName string) error {
	future, err := az.disksClient.Delete(ctx, resourceGroupName, diskName)
	if err != nil {
		return err
	}

	if err = future.WaitForCompletionRef(ctx, az.disksClient.Client); err != nil {
		return err
	}

	_, err = future.Result(az.disksClient)
	return err
}

// ListManagedDisksByResourceGroup lists managed disks in a resource group.
func (az *AzureClient) ListManagedDisksByResourceGroup(ctx context.Context, resourceGroupName string) (result DiskListPage, err error) {
	page, err := az.disksClient.ListByResourceGroup(ctx, resourceGroupName)
	return &page, err
}
