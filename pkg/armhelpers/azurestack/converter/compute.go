package converter

import (
	azscompute "github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2017-03-30/compute"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-04-01/compute"
	"github.com/Azure/go-autorest/autorest/to"
)

// ConvertVirtualMachine20170330To20180401 converts resources.DeploymentExtended from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachine20170330To20180401(azsvm azscompute.VirtualMachine) compute.VirtualMachine {
	vm := compute.VirtualMachine{
		Response: azsvm.Response,
		Zones:    azsvm.Zones,
		ID:       azsvm.ID,
		Name:     azsvm.Name,
		Type:     azsvm.Type,
		Location: azsvm.Location,
		Tags:     azsvm.Tags,
	}

	if azsvm.Plan != nil {
		vm.Plan = &compute.Plan{
			Name:          azsvm.Plan.Name,
			Publisher:     azsvm.Plan.Publisher,
			Product:       azsvm.Plan.Product,
			PromotionCode: azsvm.Plan.PromotionCode,
		}
	}

	if azsvm.VirtualMachineProperties != nil {
		hw := compute.HardwareProfile{}
		if azsvm.HardwareProfile != nil {
			hw.VMSize = compute.VirtualMachineSizeTypes(string(azsvm.HardwareProfile.VMSize))
		}

		sp := compute.StorageProfile{}
		if azsvm.StorageProfile != nil {
			if azsvm.StorageProfile.ImageReference != nil {
				sp.ImageReference = &compute.ImageReference{
					Publisher: azsvm.StorageProfile.ImageReference.Publisher,
					Offer:     azsvm.StorageProfile.ImageReference.Offer,
					Sku:       azsvm.StorageProfile.ImageReference.Sku,
					Version:   azsvm.StorageProfile.ImageReference.Version,
					ID:        azsvm.StorageProfile.ImageReference.ID,
				}
			}

			if azsvm.StorageProfile.OsDisk != nil {
				od := compute.OSDisk{
					OsType:                  compute.OperatingSystemTypes(string(azsvm.StorageProfile.OsDisk.OsType)),
					Name:                    azsvm.StorageProfile.OsDisk.Name,
					Caching:                 compute.CachingTypes(string(azsvm.StorageProfile.OsDisk.Caching)),
					WriteAcceleratorEnabled: to.BoolPtr(false),
					CreateOption:            compute.DiskCreateOptionTypes(string(azsvm.StorageProfile.OsDisk.CreateOption)),
					DiskSizeGB:              azsvm.StorageProfile.OsDisk.DiskSizeGB,
				}
				if azsvm.StorageProfile.OsDisk.EncryptionSettings != nil {
					odes := compute.DiskEncryptionSettings{}
					od.EncryptionSettings = &odes
				}
				if azsvm.StorageProfile.OsDisk.Vhd != nil {
					odvhd := compute.VirtualHardDisk{
						URI: azsvm.StorageProfile.OsDisk.Vhd.URI,
					}
					od.Vhd = &odvhd
				}
				if azsvm.StorageProfile.OsDisk.Image != nil {
					odi := compute.VirtualHardDisk{
						URI: azsvm.StorageProfile.OsDisk.Image.URI,
					}
					od.Image = &odi
				}
				if azsvm.StorageProfile.OsDisk.ManagedDisk != nil {
					odm := compute.ManagedDiskParameters{
						ID:                 azsvm.StorageProfile.OsDisk.ManagedDisk.ID,
						StorageAccountType: compute.StorageAccountTypes(string(azsvm.StorageProfile.OsDisk.ManagedDisk.StorageAccountType)),
					}
					od.ManagedDisk = &odm
				}
			}
		}
		op := compute.OSProfile{
			ComputerName:  azsvm.OsProfile.ComputerName,
			AdminUsername: azsvm.OsProfile.AdminUsername,
			AdminPassword: azsvm.OsProfile.AdminPassword,
			CustomData:    azsvm.OsProfile.CustomData,
		}

		if azsvm.OsProfile.WindowsConfiguration != nil {
			opwc := compute.WindowsConfiguration{
				ProvisionVMAgent:       azsvm.OsProfile.WindowsConfiguration.ProvisionVMAgent,
				EnableAutomaticUpdates: azsvm.OsProfile.WindowsConfiguration.EnableAutomaticUpdates,
				TimeZone:               azsvm.OsProfile.WindowsConfiguration.TimeZone,
			}
			if azsvm.OsProfile.WindowsConfiguration.AdditionalUnattendContent != nil {
				sauc := []compute.AdditionalUnattendContent{}
				for _, vauc := range *azsvm.OsProfile.WindowsConfiguration.AdditionalUnattendContent {
					auc := compute.AdditionalUnattendContent{
						Content:       vauc.Content,
						PassName:      compute.PassNames(string(vauc.PassName)),
						ComponentName: compute.ComponentNames(string(vauc.ComponentName)),
						SettingName:   compute.SettingNames(string(vauc.SettingName)),
					}
					sauc = append(sauc, auc)
				}
				op.WindowsConfiguration.AdditionalUnattendContent = &sauc
			}
			op.WindowsConfiguration = &opwc
		}

		if azsvm.OsProfile.LinuxConfiguration != nil {
			oplc := compute.LinuxConfiguration{
				DisablePasswordAuthentication: azsvm.OsProfile.LinuxConfiguration.DisablePasswordAuthentication,
			}
			if azsvm.OsProfile.LinuxConfiguration.SSH != nil {
				opls := compute.SSHConfiguration{}
				if azsvm.OsProfile.LinuxConfiguration.SSH.PublicKeys != nil {
					soplsk := []compute.SSHPublicKey{}
					for _, vsoplsk := range *azsvm.OsProfile.LinuxConfiguration.SSH.PublicKeys {
						oplsk := compute.SSHPublicKey{
							Path:    vsoplsk.Path,
							KeyData: vsoplsk.KeyData,
						}
						soplsk = append(soplsk, oplsk)
					}
					opls.PublicKeys = &soplsk
				}

				op.LinuxConfiguration.SSH = &opls
			}
			op.LinuxConfiguration = &oplc
		}

		if azsvm.OsProfile.Secrets != nil {
			ops := []compute.VaultSecretGroup{}
			op.Secrets = &ops
		}
		vm.VirtualMachineProperties = &compute.VirtualMachineProperties{
			HardwareProfile: &hw,
			StorageProfile:  &sp,
			OsProfile:       &op,
		}
	}
	vm.VirtualMachineProperties = azsvm.VirtualMachineProperties
	vm.Resources = azsvm.Resources
	vm.Identity = azsvm.Identity

	return vm
}
