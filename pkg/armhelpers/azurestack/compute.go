package azurestack

import (
	"context"

	"github.com/Azure/acs-engine/pkg/armhelpers"
	"github.com/Azure/acs-engine/pkg/armhelpers/azurestack/converter"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2017-03-30/compute"
	azcompute "github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-04-01/compute"
)

//VirtualMachineListResultPageClient Virtual Machine List Result Page Client
type VirtualMachineListResultPageClient struct {
	vmlrp compute.VirtualMachineListResultPage
	err   error
}

// Next advances to the next page of values.  If there was an error making
// the request the page does not advance and the error is returned.
func (page *VirtualMachineListResultPageClient) Next() error {
	return page.vmlrp.Next()
}

// NotDone returns true if the page enumeration should be started or is not yet complete.
func (page VirtualMachineListResultPageClient) NotDone() bool {
	return page.vmlrp.NotDone()
}

// Response returns the raw server response from the last page request.
func (page VirtualMachineListResultPageClient) Response() azcompute.VirtualMachineListResult {
	return converter.ConvertVirtualMachineListResult(page.vmlrp.Response())
}

// Values returns the slice of values for the current page or nil if there are no values.
func (page VirtualMachineListResultPageClient) Values() []azcompute.VirtualMachine {
	return converter.ConvertVirtualMachineSlice(page.vmlrp.Values())
}

// ListVirtualMachines returns (the first page of) the machines in the specified resource group.
func (az *AzureClient) ListVirtualMachines(ctx context.Context, resourceGroup string) (armhelpers.VirtualMachineListResultPage, error) {
	page, err := az.virtualMachinesClient.List(ctx, resourceGroup)

	c := VirtualMachineListResultPageClient{
		vmlrp: page,
		err:   err,
	}
	return &c, err
}

// GetVirtualMachine returns the specified machine in the specified resource group.
func (az *AzureClient) GetVirtualMachine(ctx context.Context, resourceGroup, name string) (azcompute.VirtualMachine, error) {
	r, err := az.virtualMachinesClient.Get(ctx, resourceGroup, name, "")
	return converter.ConvertVirtualMachine(r), err
}

// DeleteVirtualMachine handles deletion of a CRP/VMAS VM (aka, not a VMSS VM).
func (az *AzureClient) DeleteVirtualMachine(ctx context.Context, resourceGroup, name string) error {
	future, err := az.virtualMachinesClient.Delete(ctx, resourceGroup, name)
	if err != nil {
		return err
	}

	if err = future.WaitForCompletionRef(ctx, az.virtualMachinesClient.Client); err != nil {
		return err
	}

	_, err = future.Result(az.virtualMachinesClient)
	return err
}

// VirtualMachineScaleSetListResultPageClient Virtual Machine Scale Set List Result Page Client
type VirtualMachineScaleSetListResultPageClient struct {
	vmsslrp compute.VirtualMachineScaleSetListResultPage
	err     error
}

// Next advances to the next page of values.  If there was an error making
// the request the page does not advance and the error is returned.
func (page *VirtualMachineScaleSetListResultPageClient) Next() error {
	return page.vmsslrp.Next()
}

// NotDone returns true if the page enumeration should be started or is not yet complete.
func (page VirtualMachineScaleSetListResultPageClient) NotDone() bool {
	return page.vmsslrp.NotDone()
}

// Response returns the raw server response from the last page request.
func (page VirtualMachineScaleSetListResultPageClient) Response() azcompute.VirtualMachineScaleSetListResult {
	return converter.ConvertVirtualMachineScaleSetListResult(page.vmsslrp.Response())
}

// Values returns the slice of values for the current page or nil if there are no values.
func (page VirtualMachineScaleSetListResultPageClient) Values() []azcompute.VirtualMachineScaleSet {
	return converter.ConvertVirtualMachineScaleSetSliceValue(page.vmsslrp.Values())
}

// ListVirtualMachineScaleSets returns (the first page of) the vmss resources in the specified resource group.
func (az *AzureClient) ListVirtualMachineScaleSets(ctx context.Context, resourceGroup string) (armhelpers.VirtualMachineScaleSetListResultPage, error) {
	page, err := az.virtualMachineScaleSetsClient.List(ctx, resourceGroup)
	c := VirtualMachineScaleSetListResultPageClient{
		vmsslrp: page,
		err:     err,
	}
	return &c, err
}

// VirtualMachineScaleSetVMListResultPageClient Virtual Machine Scale Set VM List Result Page Client
type VirtualMachineScaleSetVMListResultPageClient struct {
	vmssvlrp compute.VirtualMachineScaleSetVMListResultPage
	err      error
}

// Next advances to the next page of values.  If there was an error making
// the request the page does not advance and the error is returned.
func (page *VirtualMachineScaleSetVMListResultPageClient) Next() error {
	return page.vmssvlrp.Next()
}

// NotDone returns true if the page enumeration should be started or is not yet complete.
func (page VirtualMachineScaleSetVMListResultPageClient) NotDone() bool {
	return page.vmssvlrp.NotDone()
}

// Response returns the raw server response from the last page request.
func (page VirtualMachineScaleSetVMListResultPageClient) Response() azcompute.VirtualMachineScaleSetVMListResult {
	return converter.ConvertVirtualMachineScaleSetVMListResult(page.vmssvlrp.Response())
}

// Values returns the slice of values for the current page or nil if there are no values.
func (page VirtualMachineScaleSetVMListResultPageClient) Values() []azcompute.VirtualMachineScaleSetVM {
	return converter.ConvertVirtualMachineScaleSetVMSliceValue(page.vmssvlrp.Values())
}

// ListVirtualMachineScaleSetVMs returns the list of VMs per VMSS
func (az *AzureClient) ListVirtualMachineScaleSetVMs(ctx context.Context, resourceGroup, virtualMachineScaleSet string) (armhelpers.VirtualMachineScaleSetVMListResultPage, error) {
	page, err := az.virtualMachineScaleSetVMsClient.List(ctx, resourceGroup, virtualMachineScaleSet, "", "", "")
	c := VirtualMachineScaleSetVMListResultPageClient{
		vmssvlrp: page,
		err:      err,
	}
	return &c, err
}

// DeleteVirtualMachineScaleSetVM deletes a VM in a VMSS
func (az *AzureClient) DeleteVirtualMachineScaleSetVM(ctx context.Context, resourceGroup, virtualMachineScaleSet, instanceID string) error {
	future, err := az.virtualMachineScaleSetVMsClient.Delete(ctx, resourceGroup, virtualMachineScaleSet, instanceID)
	if err != nil {
		return err
	}

	if err = future.WaitForCompletionRef(ctx, az.virtualMachineScaleSetVMsClient.Client); err != nil {
		return err
	}

	_, err = future.Result(az.virtualMachineScaleSetVMsClient)
	return err
}

// SetVirtualMachineScaleSetCapacity sets the VMSS capacity
func (az *AzureClient) SetVirtualMachineScaleSetCapacity(ctx context.Context, resourceGroup, virtualMachineScaleSet string, sku azcompute.Sku, location string) error {
	future, err := az.virtualMachineScaleSetsClient.CreateOrUpdate(
		ctx,
		resourceGroup,
		virtualMachineScaleSet,
		compute.VirtualMachineScaleSet{
			Location: &location,
			Sku:      converter.ConvertFromSku(&sku),
		})
	if err != nil {
		return err
	}

	if err = future.WaitForCompletionRef(ctx, az.virtualMachineScaleSetsClient.Client); err != nil {
		return err
	}

	_, err = future.Result(az.virtualMachineScaleSetsClient)
	return err
}
