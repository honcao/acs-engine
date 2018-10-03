package compute

import (
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-04-01/compute"
)

// VirtualMachineListResult the List Virtual Machine operation response.
type VirtualMachineListResult compute.VirtualMachineListResult

// VirtualMachine describes a Virtual Machine.
type VirtualMachine compute.VirtualMachine

// Sku describes a virtual machine scale set sku.
type Sku compute.Sku

// VirtualMachineScaleSetListResultPage contains a page of VirtualMachineScaleSet values.
type VirtualMachineScaleSetListResultPage compute.VirtualMachineScaleSetListResultPage

// VirtualMachineScaleSetVMListResultPage contains a page of VirtualMachineScaleSetVM values.
type VirtualMachineScaleSetVMListResultPage compute.VirtualMachineScaleSetVMListResultPage
