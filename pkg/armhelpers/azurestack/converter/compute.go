package converter

import (
	azscompute "github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2017-03-30/compute"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-04-01/compute"
	"github.com/Azure/go-autorest/autorest/to"
)

// ConvertVirtualMachine20170330To20180401 converts compute.VirtualMachine from version 2017-03-30 to 2018-04-01
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

	vm.Plan = ConvertPlan20170330To20180401(azsvm.Plan)

	if azsvm.VirtualMachineProperties != nil {
		hw := compute.HardwareProfile{}
		if azsvm.HardwareProfile != nil {
			hw.VMSize = compute.VirtualMachineSizeTypes(string(azsvm.HardwareProfile.VMSize))
		}

		sp := compute.StorageProfile{}
		if azsvm.StorageProfile != nil {
			sp.ImageReference = ConvertImageReference20170330To20180401(azsvm.StorageProfile.ImageReference)
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

		op.WindowsConfiguration = ConvertWindowsConfiguration20170330To20180401(azsvm.OsProfile.WindowsConfiguration)
		op.LinuxConfiguration = ConvertLinuxConfiguration20170330To20180401(azsvm.OsProfile.LinuxConfiguration)
		op.Secrets = ConvertVaultSecretGroup20170330To20180401(azsvm.OsProfile.Secrets)

		np := compute.NetworkProfile{}
		if azsvm.NetworkProfile != nil {
			snpn := []compute.NetworkInterfaceReference{}
			for _, vsnpn := range *azsvm.NetworkProfile.NetworkInterfaces {
				npn := compute.NetworkInterfaceReference{
					ID: vsnpn.ID,
				}

				if vsnpn.NetworkInterfaceReferenceProperties != nil {
					npn.NetworkInterfaceReferenceProperties = &compute.NetworkInterfaceReferenceProperties{
						Primary: vsnpn.NetworkInterfaceReferenceProperties.Primary,
					}
				}

				snpn = append(snpn, npn)
			}
			np.NetworkInterfaces = &snpn
		}

		as := compute.SubResource{}
		if azsvm.AvailabilitySet != nil {
			as.ID = azsvm.AvailabilitySet.ID
		}

		iw := compute.VirtualMachineInstanceView{}
		if azsvm.InstanceView != nil {
			iw.Response = azsvm.InstanceView.Response

			iw.PlatformUpdateDomain = azsvm.InstanceView.PlatformUpdateDomain
			iw.PlatformFaultDomain = azsvm.InstanceView.PlatformFaultDomain
			iw.ComputerName = nil //Empty in azsvm.InstanceView.ComputerName
			iw.OsName = nil       //Empty in azsvm.InstanceView.OsName
			iw.OsVersion = nil    //Empty in azsvm.InstanceView.OsVersion
			iw.RdpThumbPrint = azsvm.InstanceView.RdpThumbPrint

			if azsvm.InstanceView.VMAgent != nil {
				va := compute.VirtualMachineAgentInstanceView{
					VMAgentVersion: azsvm.InstanceView.VMAgent.VMAgentVersion,
				}

				if azsvm.InstanceView.VMAgent.ExtensionHandlers != nil {
					sehi := []compute.VirtualMachineExtensionHandlerInstanceView{}
					for _, vehi := range *azsvm.InstanceView.VMAgent.ExtensionHandlers {
						ehi := compute.VirtualMachineExtensionHandlerInstanceView{
							Type:               vehi.Type,
							TypeHandlerVersion: vehi.TypeHandlerVersion,
						}

						if vehi.Status != nil {
							ehi.Status = &compute.InstanceViewStatus{
								Code:          vehi.Status.Code,
								Level:         compute.StatusLevelTypes(string(vehi.Status.Level)),
								DisplayStatus: vehi.Status.DisplayStatus,
								Message:       vehi.Status.Message,
								Time:          vehi.Status.Time,
							}
						}

						sehi = append(sehi, ehi)
					}
					iw.VMAgent.ExtensionHandlers = &sehi
				}

				if azsvm.InstanceView.VMAgent.Statuses != nil {
					svms := []compute.InstanceViewStatus{}
					for _, vsvms := range *azsvm.InstanceView.VMAgent.Statuses {
						vms := compute.InstanceViewStatus{
							Code:          vsvms.Code,
							Level:         compute.StatusLevelTypes(string(vsvms.Level)),
							DisplayStatus: vsvms.DisplayStatus,
							Message:       vsvms.Message,
							Time:          vsvms.Time,
						}
						svms = append(svms, vms)
					}
					iw.VMAgent.Statuses = &svms
				}

				iw.VMAgent = &va

			}

			if azsvm.InstanceView.MaintenanceRedeployStatus != nil {
				mrs := compute.MaintenanceRedeployStatus{
					IsCustomerInitiatedMaintenanceAllowed: azsvm.InstanceView.MaintenanceRedeployStatus.IsCustomerInitiatedMaintenanceAllowed,
					PreMaintenanceWindowStartTime:         azsvm.InstanceView.MaintenanceRedeployStatus.PreMaintenanceWindowStartTime,
					PreMaintenanceWindowEndTime:           azsvm.InstanceView.MaintenanceRedeployStatus.PreMaintenanceWindowEndTime,
					MaintenanceWindowStartTime:            azsvm.InstanceView.MaintenanceRedeployStatus.MaintenanceWindowStartTime,
					MaintenanceWindowEndTime:              azsvm.InstanceView.MaintenanceRedeployStatus.MaintenanceWindowEndTime,
					LastOperationResultCode:               compute.MaintenanceOperationResultCodeTypes(string(azsvm.InstanceView.MaintenanceRedeployStatus.LastOperationResultCode)),
					LastOperationMessage:                  azsvm.InstanceView.MaintenanceRedeployStatus.LastOperationMessage,
				}
				iw.MaintenanceRedeployStatus = &mrs
			}

			if azsvm.InstanceView.Disks != nil {
				svmid := []compute.DiskInstanceView{}
				for _, vsvmid := range *azsvm.InstanceView.Disks {
					vmid := compute.DiskInstanceView{
						Name: vsvmid.Name,
					}
					if vsvmid.EncryptionSettings != nil {
						ses := []compute.DiskEncryptionSettings{}
						for _, vses := range *vsvmid.EncryptionSettings {
							es := compute.DiskEncryptionSettings{
								Enabled: vses.Enabled,
							}
							if vses.DiskEncryptionKey != nil {
								es.DiskEncryptionKey = &compute.KeyVaultSecretReference{
									SecretURL: vses.DiskEncryptionKey.SecretURL,
								}
								if vses.DiskEncryptionKey.SourceVault != nil {
									es.DiskEncryptionKey.SourceVault = &compute.SubResource{
										ID: vses.DiskEncryptionKey.SourceVault.ID,
									}
								}
							}
							ses = append(ses, es)
						}
						vmid.EncryptionSettings = &ses
					}

					svmid = append(svmid, vmid)
				}
				iw.Disks = &svmid
			}
			iw.Extensions = ConvertVirtualMachineExtensionInstanceViewSlice20170330To20180401(azsvm.InstanceView.Extensions)

			if azsvm.InstanceView.BootDiagnostics != nil {
				iw.BootDiagnostics = &compute.BootDiagnosticsInstanceView{
					ConsoleScreenshotBlobURI: azsvm.InstanceView.BootDiagnostics.ConsoleScreenshotBlobURI,
					SerialConsoleLogBlobURI:  azsvm.InstanceView.BootDiagnostics.SerialConsoleLogBlobURI,
				}
			}
			if azsvm.InstanceView.Statuses != nil {
				svmss1 := []compute.InstanceViewStatus{}
				for _, vsvmss1 := range *azsvm.InstanceView.Statuses {
					vmss1 := compute.InstanceViewStatus{
						Code:          vsvmss1.Code,
						Level:         compute.StatusLevelTypes(string(vsvmss1.Level)),
						DisplayStatus: vsvmss1.DisplayStatus,
						Message:       vsvmss1.Message,
						Time:          vsvmss1.Time,
					}
					svmss1 = append(svmss1, vmss1)
				}
				iw.Statuses = &svmss1
			}
		}

		vm.VirtualMachineProperties = &compute.VirtualMachineProperties{
			HardwareProfile:    &hw,
			StorageProfile:     &sp,
			OsProfile:          &op,
			NetworkProfile:     &np,
			DiagnosticsProfile: ConvertDiagnosticsProfile20170330To20180401(azsvm.DiagnosticsProfile),
			AvailabilitySet:    &as,
			ProvisioningState:  azsvm.ProvisioningState,
			InstanceView:       &iw,
			LicenseType:        azsvm.LicenseType,
			VMID:               azsvm.VMID,
		}
	}

	if azsvm.Resources != nil {
		svmr := []compute.VirtualMachineExtension{}
		for _, vsvmr := range *azsvm.Resources {
			vmr := compute.VirtualMachineExtension{
				Response: vsvmr.Response,
				ID:       vsvmr.ID,
				Name:     vsvmr.Name,
				Type:     vsvmr.Type,
				Location: vsvmr.Location,
				Tags:     vsvmr.Tags,
			}
			vmr.ForceUpdateTag = vsvmr.ForceUpdateTag
			vmr.Publisher = vsvmr.Publisher
			vmr.Type = vsvmr.Type
			vmr.TypeHandlerVersion = vsvmr.TypeHandlerVersion
			vmr.AutoUpgradeMinorVersion = vsvmr.AutoUpgradeMinorVersion
			vmr.Settings = vsvmr.Settings
			vmr.ProvisioningState = vsvmr.ProvisioningState
			vmr.InstanceView = ConvertVirtualMachineExtensionInstanceView20170330To20180401(vsvmr.InstanceView)
			svmr = append(svmr, vmr)
		}
		vm.Resources = &svmr
	}

	if azsvm.Identity != nil {
		vmi := compute.VirtualMachineIdentity{
			PrincipalID: azsvm.Identity.PrincipalID,
			TenantID:    azsvm.Identity.TenantID,
			Type:        compute.ResourceIdentityType(string(azsvm.Identity.Type)),
			IdentityIds: nil, // Empty in azsvm.Identity.IdentityIds,
		}
		vm.Identity = &vmi
	}

	return vm
}

// ConvertVirtualMachineScaleSetSlice20170330To20180401 converts *[]compute.VirtualMachine from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetSlice20170330To20180401(azsvmss *[]azscompute.VirtualMachineScaleSet) *[]compute.VirtualMachineScaleSet {
	if azsvmss == nil {
		return nil
	}

	svmss := []compute.VirtualMachineScaleSet{}
	for _, vvmss := range *azsvmss {
		svmss = append(svmss, ConvertVirtualMachineScaleSet20170330To20180401(vvmss))
	}
	return &svmss
}

// ConvertVirtualMachineScaleSet20170330To20180401 converts compute.VirtualMachine from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSet20170330To20180401(azsvmss azscompute.VirtualMachineScaleSet) compute.VirtualMachineScaleSet {
	vmss := compute.VirtualMachineScaleSet{
		Response: azsvmss.Response,
		Sku:      ConvertSku20170330To20180401(azsvmss.Sku),
		Plan:     ConvertPlan20170330To20180401(azsvmss.Plan),
		Identity: ConvertVirtualMachineScaleSetIdentity20170330To20180401(azsvmss.Identity),
		Zones:    azsvmss.Zones,
		ID:       azsvmss.ID,
		Name:     azsvmss.Name,
		Type:     azsvmss.Type,
		Location: azsvmss.Location,
		Tags:     azsvmss.Tags,
	}

	vmss.UpgradePolicy = ConvertUpgradePolicy20170330To20180401(azsvmss.UpgradePolicy)
	vmss.ProvisioningState = azsvmss.ProvisioningState
	vmss.Overprovision = azsvmss.Overprovision
	vmss.UniqueID = azsvmss.UniqueID
	vmss.SinglePlacementGroup = azsvmss.SinglePlacementGroup
	vmss.ZoneBalance = nil              // empty in azsvmss.ZoneBalance
	vmss.PlatformFaultDomainCount = nil // empty in  azsvmss.PlatformFaultDomainCount
	vmss.VirtualMachineProfile = ConvertVirtualMachineScaleSetVMProfile20170330To20180401(azsvmss.VirtualMachineProfile)
	return vmss
}

//ConvertVirtualMachineListResult20170330To20180401 converts *[]compute.VirtualMachineListResult from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineListResult20170330To20180401(azsvmlr azscompute.VirtualMachineListResult) compute.VirtualMachineListResult {
	vmlr := compute.VirtualMachineListResult{
		Response: azsvmlr.Response,
		NextLink: azsvmlr.NextLink,
	}
	if azsvmlr.Value != nil {
		svm := []compute.VirtualMachine{}
		for _, vvm := range *azsvmlr.Value {
			vm := ConvertVirtualMachine20170330To20180401(vvm)
			svm = append(svm, vm)
		}
		vmlr.Value = &svm
	}
	return vmlr
}

//ConvertVirtualMachineExtensionInstanceView20170330To20180401 converts *[]compute.VirtualMachineExtensionInstanceView from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineExtensionInstanceView20170330To20180401(azsvmei *azscompute.VirtualMachineExtensionInstanceView) *compute.VirtualMachineExtensionInstanceView {
	if azsvmei == nil {
		return nil
	}
	vme := compute.VirtualMachineExtensionInstanceView{
		Name:               azsvmei.Name,
		Type:               azsvmei.Type,
		TypeHandlerVersion: azsvmei.TypeHandlerVersion,
	}

	if azsvmei.Substatuses != nil {
		svmss := []compute.InstanceViewStatus{}
		for _, vsvmss := range *azsvmei.Substatuses {
			vmss := compute.InstanceViewStatus{
				Code:          vsvmss.Code,
				Level:         compute.StatusLevelTypes(string(vsvmss.Level)),
				DisplayStatus: vsvmss.DisplayStatus,
				Message:       vsvmss.Message,
				Time:          vsvmss.Time,
			}
			svmss = append(svmss, vmss)
		}
	}

	if azsvmei.Statuses != nil {
		svmss1 := []compute.InstanceViewStatus{}
		for _, vsvmss1 := range *azsvmei.Statuses {
			vmss1 := compute.InstanceViewStatus{
				Code:          vsvmss1.Code,
				Level:         compute.StatusLevelTypes(string(vsvmss1.Level)),
				DisplayStatus: vsvmss1.DisplayStatus,
				Message:       vsvmss1.Message,
				Time:          vsvmss1.Time,
			}
			svmss1 = append(svmss1, vmss1)
		}
	}

	return &vme
}

//ConvertVirtualMachineExtensionInstanceViewSlice20170330To20180401 converts *compute.VirtualMachineExtensionInstanceView from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineExtensionInstanceViewSlice20170330To20180401(sazsvmei *[]azscompute.VirtualMachineExtensionInstanceView) *[]compute.VirtualMachineExtensionInstanceView {
	if sazsvmei == nil {
		return nil
	}
	svme := []compute.VirtualMachineExtensionInstanceView{}
	for _, vsvme := range *sazsvmei {
		vme := compute.VirtualMachineExtensionInstanceView{
			Name:               vsvme.Name,
			Type:               vsvme.Type,
			TypeHandlerVersion: vsvme.TypeHandlerVersion,
		}

		if vsvme.Substatuses != nil {
			svmss := []compute.InstanceViewStatus{}
			for _, vsvmss := range *vsvme.Substatuses {
				vmss := compute.InstanceViewStatus{
					Code:          vsvmss.Code,
					Level:         compute.StatusLevelTypes(string(vsvmss.Level)),
					DisplayStatus: vsvmss.DisplayStatus,
					Message:       vsvmss.Message,
					Time:          vsvmss.Time,
				}
				svmss = append(svmss, vmss)
			}
		}

		if vsvme.Statuses != nil {
			svmss1 := []compute.InstanceViewStatus{}
			for _, vsvmss1 := range *vsvme.Statuses {
				vmss1 := compute.InstanceViewStatus{
					Code:          vsvmss1.Code,
					Level:         compute.StatusLevelTypes(string(vsvmss1.Level)),
					DisplayStatus: vsvmss1.DisplayStatus,
					Message:       vsvmss1.Message,
					Time:          vsvmss1.Time,
				}
				svmss1 = append(svmss1, vmss1)
			}
		}

		svme = append(svme, vme)
	}
	return &svme
}

//ConvertPlan20170330To20180401 converts *compute.Plan from version 2017-03-30 to 2018-04-01
func ConvertPlan20170330To20180401(azsp *azscompute.Plan) *compute.Plan {
	if azsp == nil {
		return nil
	}
	return &compute.Plan{
		Name:          azsp.Name,
		Publisher:     azsp.Publisher,
		Product:       azsp.Product,
		PromotionCode: azsp.PromotionCode,
	}
}

//ConvertSku20170330To20180401 converts *compute.Sku from version 2017-03-30 to 2018-04-01
func ConvertSku20170330To20180401(azss *azscompute.Sku) *compute.Sku {
	if azss == nil {
		return nil
	}
	return &compute.Sku{
		Name:     azss.Name,
		Tier:     azss.Tier,
		Capacity: azss.Capacity,
	}
}

//ConvertVirtualMachineScaleSetIdentity20170330To20180401 converts *compute.VirtualMachineScaleSetIdentity from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetIdentity20170330To20180401(azsi *azscompute.VirtualMachineScaleSetIdentity) *compute.VirtualMachineScaleSetIdentity {
	if azsi == nil {
		return nil
	}
	return &compute.VirtualMachineScaleSetIdentity{
		PrincipalID: azsi.PrincipalID,
		TenantID:    azsi.TenantID,
		Type:        compute.ResourceIdentityType(string(azsi.Type)),
		IdentityIds: nil, // empty in azsi.IdentityIds,
	}
}

//ConvertUpgradePolicy20170330To20180401 converts *compute.UpgradePolicy from version 2017-03-30 to 2018-04-01
func ConvertUpgradePolicy20170330To20180401(azs *azscompute.UpgradePolicy) *compute.UpgradePolicy {
	if azs == nil {
		return nil
	}
	up := &compute.UpgradePolicy{
		Mode:               compute.UpgradeMode(string(azs.Mode)),
		AutomaticOSUpgrade: azs.AutomaticOSUpgrade,
	}

	if azs.RollingUpgradePolicy != nil {
		up.RollingUpgradePolicy = &compute.RollingUpgradePolicy{
			MaxBatchInstancePercent:             azs.RollingUpgradePolicy.MaxBatchInstancePercent,
			MaxUnhealthyInstancePercent:         azs.RollingUpgradePolicy.MaxUnhealthyInstancePercent,
			MaxUnhealthyUpgradedInstancePercent: azs.RollingUpgradePolicy.MaxUnhealthyUpgradedInstancePercent,
			PauseTimeBetweenBatches:             azs.RollingUpgradePolicy.PauseTimeBetweenBatches,
		}
	}

	up.AutoOSUpgradePolicy = &compute.AutoOSUpgradePolicy{
		DisableAutoRollback: to.BoolPtr(false), // empty in azure stack
	}

	return up
}

//ConvertVirtualMachineScaleSetVMProfile20170330To20180401 converts *compute.VirtualMachineScaleSetVMProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetVMProfile20170330To20180401(azs *azscompute.VirtualMachineScaleSetVMProfile) *compute.VirtualMachineScaleSetVMProfile {
	if azs == nil {
		return nil
	}
	vmp := compute.VirtualMachineScaleSetVMProfile{
		OsProfile:          ConvertVirtualMachineScaleSetOSProfile20170330To20180401(azs.OsProfile),
		StorageProfile:     ConvertVirtualMachineScaleSetStorageProfile20170330To20180401(azs.StorageProfile),
		NetworkProfile:     ConvertVirtualMachineScaleSetNetworkProfile20170330To20180401(azs.NetworkProfile),
		DiagnosticsProfile: ConvertDiagnosticsProfile20170330To20180401(azs.DiagnosticsProfile),
		ExtensionProfile:   ConvertVirtualMachineScaleSetExtensionProfile20170330To20180401(azs.ExtensionProfile),
		LicenseType:        azs.LicenseType,
		Priority:           "", // empty in azure stack
		EvictionPolicy:     "", // empty in azure stack
	}
	return &vmp
}

//ConvertVirtualMachineScaleSetOSProfile20170330To20180401 converts *compute.VirtualMachineScaleSetOSProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetOSProfile20170330To20180401(azs *azscompute.VirtualMachineScaleSetOSProfile) *compute.VirtualMachineScaleSetOSProfile {
	if azs == nil {
		return nil
	}
	op := compute.VirtualMachineScaleSetOSProfile{
		ComputerNamePrefix:   azs.ComputerNamePrefix,
		AdminUsername:        azs.AdminUsername,
		AdminPassword:        azs.AdminPassword,
		CustomData:           azs.CustomData,
		WindowsConfiguration: ConvertWindowsConfiguration20170330To20180401(azs.WindowsConfiguration),
		LinuxConfiguration:   ConvertLinuxConfiguration20170330To20180401(azs.LinuxConfiguration),
		Secrets:              ConvertVaultSecretGroup20170330To20180401(azs.Secrets),
	}
	return &op
}

//ConvertWindowsConfiguration20170330To20180401 converts *compute.WindowsConfiguration from version 2017-03-30 to 2018-04-01
func ConvertWindowsConfiguration20170330To20180401(azs *azscompute.WindowsConfiguration) *compute.WindowsConfiguration {
	if azs == nil {
		return nil
	}

	opwc := compute.WindowsConfiguration{
		ProvisionVMAgent:       azs.ProvisionVMAgent,
		EnableAutomaticUpdates: azs.EnableAutomaticUpdates,
		TimeZone:               azs.TimeZone,
	}
	if azs.AdditionalUnattendContent != nil {
		sauc := []compute.AdditionalUnattendContent{}
		for _, vauc := range *azs.AdditionalUnattendContent {
			auc := compute.AdditionalUnattendContent{
				Content:       vauc.Content,
				PassName:      compute.PassNames(string(vauc.PassName)),
				ComponentName: compute.ComponentNames(string(vauc.ComponentName)),
				SettingName:   compute.SettingNames(string(vauc.SettingName)),
			}
			sauc = append(sauc, auc)
		}
		opwc.AdditionalUnattendContent = &sauc
	}
	return &opwc
}

//ConvertLinuxConfiguration20170330To20180401 converts *compute.LinuxConfiguration from version 2017-03-30 to 2018-04-01
func ConvertLinuxConfiguration20170330To20180401(azs *azscompute.LinuxConfiguration) *compute.LinuxConfiguration {
	if azs == nil {
		return nil
	}

	oplc := compute.LinuxConfiguration{
		DisablePasswordAuthentication: azs.DisablePasswordAuthentication,
	}
	if azs.SSH != nil {
		opls := compute.SSHConfiguration{}
		if azs.SSH.PublicKeys != nil {
			soplsk := []compute.SSHPublicKey{}
			for _, vsoplsk := range *azs.SSH.PublicKeys {
				oplsk := compute.SSHPublicKey{
					Path:    vsoplsk.Path,
					KeyData: vsoplsk.KeyData,
				}
				soplsk = append(soplsk, oplsk)
			}
			opls.PublicKeys = &soplsk
		}

		oplc.SSH = &opls
	}
	return &oplc
}

//ConvertVaultSecretGroup20170330To20180401 converts *[]compute.VaultSecretGroup from version 2017-03-30 to 2018-04-01
func ConvertVaultSecretGroup20170330To20180401(azs *[]azscompute.VaultSecretGroup) *[]compute.VaultSecretGroup {
	if azs == nil {
		return nil
	}

	sops := []compute.VaultSecretGroup{}
	for _, vsops := range *azs {
		ops := compute.VaultSecretGroup{}
		if vsops.SourceVault != nil {
			ops.SourceVault = &compute.SubResource{
				ID: vsops.SourceVault.ID,
			}
		}
		if vsops.VaultCertificates != nil {
			sopsvc := []compute.VaultCertificate{}
			for _, vsopsvc := range *vsops.VaultCertificates {
				opsvc := compute.VaultCertificate{
					CertificateURL:   vsopsvc.CertificateURL,
					CertificateStore: vsopsvc.CertificateStore,
				}
				sopsvc = append(sopsvc, opsvc)
			}
			ops.VaultCertificates = &sopsvc
		}

		sops = append(sops, ops)

	}
	return &sops
}

//ConvertImageReference20170330To20180401 converts *compute.ImageReference from version 2017-03-30 to 2018-04-01
func ConvertImageReference20170330To20180401(azs *azscompute.ImageReference) *compute.ImageReference {
	if azs == nil {
		return nil
	}

	return &compute.ImageReference{
		Publisher: azs.Publisher,
		Offer:     azs.Offer,
		Sku:       azs.Sku,
		Version:   azs.Version,
		ID:        azs.ID,
	}
}

//ConvertVirtualMachineScaleSetOSDisk20170330To20180401 converts *compute.VirtualMachineScaleSetOSDisk from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetOSDisk20170330To20180401(azs *azscompute.VirtualMachineScaleSetOSDisk) *compute.VirtualMachineScaleSetOSDisk {
	if azs == nil {
		return nil
	}

	od := compute.VirtualMachineScaleSetOSDisk{
		Name:                    azs.Name,
		Caching:                 compute.CachingTypes(string(azs.Caching)),
		WriteAcceleratorEnabled: to.BoolPtr(false), // empty in azurestack
		CreateOption:            compute.DiskCreateOptionTypes(string(azs.CreateOption)),
		DiskSizeGB:              nil, // empty in azs.DiskSizeGB,
		OsType:                  compute.OperatingSystemTypes(string(azs.OsType)),
		Image:                   ConvertVirtualHardDisk20170330To20180401(azs.Image),
		VhdContainers:           azs.VhdContainers,
	}

	if azs.ManagedDisk != nil {
		od.ManagedDisk = &compute.VirtualMachineScaleSetManagedDiskParameters{
			StorageAccountType: compute.StorageAccountTypes(string(azs.ManagedDisk.StorageAccountType)),
		}
	}
	return &od
}

//ConvertVirtualMachineScaleSetDataDisk20170330To20180401 converts *[]compute.VirtualMachineScaleSetDataDisk from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetDataDisk20170330To20180401(azs *[]azscompute.VirtualMachineScaleSetDataDisk) *[]compute.VirtualMachineScaleSetDataDisk {
	if azs == nil {
		return nil
	}
	sod := []compute.VirtualMachineScaleSetDataDisk{}
	for _, vsod := range *azs {
		od := compute.VirtualMachineScaleSetDataDisk{
			Name:                    vsod.Name,
			Lun:                     vsod.Lun,
			Caching:                 compute.CachingTypes(string(vsod.Caching)),
			WriteAcceleratorEnabled: to.BoolPtr(false), // empty in azurestack
			CreateOption:            compute.DiskCreateOptionTypes(string(vsod.CreateOption)),
			DiskSizeGB:              nil, // empty in azs.DiskSizeGB,
		}

		if vsod.ManagedDisk != nil {
			od.ManagedDisk = &compute.VirtualMachineScaleSetManagedDiskParameters{
				StorageAccountType: compute.StorageAccountTypes(string(vsod.ManagedDisk.StorageAccountType)),
			}
		}
		sod = append(sod, od)
	}

	return &sod
}

//ConvertVirtualHardDisk20170330To20180401 converts *compute.VirtualHardDisk from version 2017-03-30 to 2018-04-01
func ConvertVirtualHardDisk20170330To20180401(azs *azscompute.VirtualHardDisk) *compute.VirtualHardDisk {
	if azs == nil {
		return nil
	}
	return &compute.VirtualHardDisk{
		URI: azs.URI,
	}
}

//ConvertVirtualMachineScaleSetStorageProfile20170330To20180401 converts *compute.VirtualMachineScaleSetStorageProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetStorageProfile20170330To20180401(azs *azscompute.VirtualMachineScaleSetStorageProfile) *compute.VirtualMachineScaleSetStorageProfile {
	if azs == nil {
		return nil
	}
	return &compute.VirtualMachineScaleSetStorageProfile{
		ImageReference: ConvertImageReference20170330To20180401(azs.ImageReference),
		OsDisk:         ConvertVirtualMachineScaleSetOSDisk20170330To20180401(azs.OsDisk),
		DataDisks:      ConvertVirtualMachineScaleSetDataDisk20170330To20180401(azs.DataDisks),
	}
}

//ConvertVirtualMachineScaleSetNetworkProfile20170330To20180401 converts *compute.VirtualMachineScaleSetNetworkProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetNetworkProfile20170330To20180401(azs *azscompute.VirtualMachineScaleSetNetworkProfile) *compute.VirtualMachineScaleSetNetworkProfile {
	if azs == nil {
		return nil
	}
	np := compute.VirtualMachineScaleSetNetworkProfile{}
	if azs.HealthProbe != nil {
		np.HealthProbe = &compute.APIEntityReference{
			ID: azs.HealthProbe.ID,
		}
	}

	if azs.NetworkInterfaceConfigurations != nil {
		snc := []compute.VirtualMachineScaleSetNetworkConfiguration{}
		for _, vsnc := range *azs.NetworkInterfaceConfigurations {
			nc := compute.VirtualMachineScaleSetNetworkConfiguration{
				Name: vsnc.Name,
				ID:   vsnc.ID,
			}
			nc.Primary = vsnc.Primary
			nc.EnableAcceleratedNetworking = vsnc.EnableAcceleratedNetworking
			if vsnc.NetworkSecurityGroup != nil {
				nc.NetworkSecurityGroup = &compute.SubResource{
					ID: vsnc.NetworkSecurityGroup.ID,
				}
			}
			if vsnc.DNSSettings != nil {
				nc.DNSSettings = &compute.VirtualMachineScaleSetNetworkConfigurationDNSSettings{
					DNSServers: vsnc.DNSSettings.DNSServers,
				}
			}
			if vsnc.IPConfigurations != nil {
				sipc := []compute.VirtualMachineScaleSetIPConfiguration{}
				for _, vsipc := range *vsnc.IPConfigurations {
					ipc := compute.VirtualMachineScaleSetIPConfiguration{
						Name: vsipc.Name,
						ID:   vsipc.ID,
					}

					if vsipc.Subnet != nil {
						ipc.Subnet = &compute.APIEntityReference{
							ID: vsipc.Subnet.ID,
						}
					}

					ipc.Primary = vsipc.Primary

					if vsipc.PublicIPAddressConfiguration != nil {
						ipc.PublicIPAddressConfiguration = &compute.VirtualMachineScaleSetPublicIPAddressConfiguration{
							Name: vsipc.PublicIPAddressConfiguration.Name,
						}
						ipc.PublicIPAddressConfiguration.IdleTimeoutInMinutes = vsipc.PublicIPAddressConfiguration.IdleTimeoutInMinutes
						if vsipc.PublicIPAddressConfiguration.DNSSettings != nil {
							ipc.PublicIPAddressConfiguration.DNSSettings = &compute.VirtualMachineScaleSetPublicIPAddressConfigurationDNSSettings{
								DomainNameLabel: vsipc.PublicIPAddressConfiguration.DNSSettings.DomainNameLabel,
							}
						}
						// empty in vsipc.PublicIPAddressConfiguration.VirtualMachineScaleSetIPTag != nil
					}

					ipc.PrivateIPAddressVersion = compute.IPVersion(string(vsipc.PrivateIPAddressVersion))
					ipc.ApplicationGatewayBackendAddressPools = ConvertSubResource20170330To20180401(vsipc.ApplicationGatewayBackendAddressPools)
					ipc.LoadBalancerBackendAddressPools = ConvertSubResource20170330To20180401(vsipc.LoadBalancerBackendAddressPools)
					ipc.LoadBalancerInboundNatPools = ConvertSubResource20170330To20180401(vsipc.LoadBalancerInboundNatPools)
					sipc = append(sipc, ipc)
				}
				nc.IPConfigurations = &sipc

			}
			nc.EnableIPForwarding = nil // empty in vsnc.EnableIPForwarding

			snc = append(snc, nc)
		}
		np.NetworkInterfaceConfigurations = &snc
	}
	return &np
}

//ConvertSubResource20170330To20180401 converts *[]compute.SubResource from version 2017-03-30 to 2018-04-01
func ConvertSubResource20170330To20180401(azs *[]azscompute.SubResource) *[]compute.SubResource {

	if azs == nil {
		return nil
	}

	ssr := []compute.SubResource{}
	for _, vssr := range *azs {
		sr := compute.SubResource{
			ID: vssr.ID,
		}
		ssr = append(ssr, sr)
	}
	return &ssr
}

//ConvertDiagnosticsProfile20170330To20180401 converts *compute.DiagnosticsProfile from version 2017-03-30 to 2018-04-01
func ConvertDiagnosticsProfile20170330To20180401(azs *azscompute.DiagnosticsProfile) *compute.DiagnosticsProfile {
	if azs == nil {
		return nil
	}

	dp := compute.DiagnosticsProfile{}
	dp.BootDiagnostics = ConvertBootDiagnostics20170330To20180401(azs.BootDiagnostics)
	return &dp
}

//ConvertBootDiagnostics20170330To20180401 converts *compute.BootDiagnostics from version 2017-03-30 to 2018-04-01
func ConvertBootDiagnostics20170330To20180401(azs *azscompute.BootDiagnostics) *compute.BootDiagnostics {
	if azs == nil {
		return nil
	}

	return &compute.BootDiagnostics{
		Enabled:    azs.Enabled,
		StorageURI: azs.StorageURI,
	}
}

//ConvertVirtualMachineScaleSetExtensionProfile20170330To20180401 converts *compute.DiagnosticsProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetExtensionProfile20170330To20180401(azs *azscompute.VirtualMachineScaleSetExtensionProfile) *compute.VirtualMachineScaleSetExtensionProfile {
	if azs == nil {
		return nil
	}

	ep := compute.VirtualMachineScaleSetExtensionProfile{}
	if azs.Extensions != nil {
		svmsse := []compute.VirtualMachineScaleSetExtension{}
		for _, vsvmsse := range *azs.Extensions {
			vmsse := compute.VirtualMachineScaleSetExtension{
				Name:     vsvmsse.Name,
				ID:       vsvmsse.ID,
				Response: vsvmsse.Response,
			}
			vmsse.ForceUpdateTag = vsvmsse.ForceUpdateTag
			vmsse.Publisher = vsvmsse.Publisher
			vmsse.Type = vsvmsse.Type
			vmsse.TypeHandlerVersion = vsvmsse.TypeHandlerVersion
			vmsse.AutoUpgradeMinorVersion = vsvmsse.AutoUpgradeMinorVersion
			vmsse.Settings = vsvmsse.Settings
			vmsse.ProtectedSettings = vsvmsse.ProtectedSettings
			vmsse.ProvisioningState = vsvmsse.ProvisioningState

			svmsse = append(svmsse, vmsse)
		}
		ep.Extensions = &svmsse
	}
	return &ep
}

//ConvertVirtualMachineScaleSetListResult20170330To20180401 converts *compute.VirtualMachineScaleSetListResult from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetListResult20170330To20180401(azs *azscompute.VirtualMachineScaleSetListResult) *compute.VirtualMachineScaleSetListResult {
	if azs == nil {
		return nil
	}

	return &compute.VirtualMachineScaleSetListResult{
		Response: azs.Response,
		NextLink: azs.NextLink,
		Value:    ConvertVirtualMachineScaleSetSlice20170330To20180401(azs.Value),
	}
}

//ConvertVirtualMachineScaleSetListResultPage20170330To20180401 converts compute.VirtualMachineScaleSetListResult from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetListResultPage20170330To20180401(azs azscompute.VirtualMachineScaleSetListResultPage) compute.VirtualMachineScaleSetListResultPage {
	if azs == nil {
		return nil
	}

	return &compute.VirtualMachineScaleSetListResultPage{
		Response: azs.Response,
		NextLink: azs.NextLink,
		Value:    ConvertVirtualMachineScaleSetListResult20170330To20180401(),
	}
}
