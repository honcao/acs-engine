package converter

import (
	azscompute "github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2017-03-30/compute"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-04-01/compute"
	"github.com/Azure/go-autorest/autorest/to"
)

// ConvertVirtualMachine converts compute.VirtualMachine from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachine(azsvm azscompute.VirtualMachine) compute.VirtualMachine {
	vm := compute.VirtualMachine{
		Response: azsvm.Response,
		Zones:    azsvm.Zones,
		ID:       azsvm.ID,
		Name:     azsvm.Name,
		Type:     azsvm.Type,
		Location: azsvm.Location,
		Tags:     azsvm.Tags,
	}

	vm.Plan = ConvertPlan(azsvm.Plan)

	if azsvm.VirtualMachineProperties != nil {

		op := compute.OSProfile{
			ComputerName:  azsvm.OsProfile.ComputerName,
			AdminUsername: azsvm.OsProfile.AdminUsername,
			AdminPassword: azsvm.OsProfile.AdminPassword,
			CustomData:    azsvm.OsProfile.CustomData,
		}

		op.WindowsConfiguration = ConvertWindowsConfiguration(azsvm.OsProfile.WindowsConfiguration)
		op.LinuxConfiguration = ConvertLinuxConfiguration(azsvm.OsProfile.LinuxConfiguration)
		op.Secrets = ConvertVaultSecretGroup(azsvm.OsProfile.Secrets)

		iw := compute.VirtualMachineInstanceView{}
		if azsvm.InstanceView != nil {
			iw.Response = azsvm.InstanceView.Response
			iw.PlatformUpdateDomain = azsvm.InstanceView.PlatformUpdateDomain
			iw.PlatformFaultDomain = azsvm.InstanceView.PlatformFaultDomain
			iw.ComputerName = nil //Empty in azsvm.InstanceView.ComputerName
			iw.OsName = nil       //Empty in azsvm.InstanceView.OsName
			iw.OsVersion = nil    //Empty in azsvm.InstanceView.OsVersion
			iw.RdpThumbPrint = azsvm.InstanceView.RdpThumbPrint
			iw.VMAgent = ConvertVirtualMachineAgentInstanceView(azsvm.InstanceView.VMAgent)
			iw.MaintenanceRedeployStatus = ConvertMaintenanceRedeployStatus(azsvm.InstanceView.MaintenanceRedeployStatus)
			iw.Disks = ConvertDiskInstanceViewSlice(azsvm.InstanceView.Disks)
			iw.Extensions = ConvertVirtualMachineExtensionInstanceViewSlice(azsvm.InstanceView.Extensions)
			iw.BootDiagnostics = ConvertBootDiagnosticsInstanceView(azsvm.InstanceView.BootDiagnostics)
			iw.Statuses = ConvertInstanceViewStatusSlice(azsvm.InstanceView.Statuses)

		}

		vm.VirtualMachineProperties = &compute.VirtualMachineProperties{
			HardwareProfile:    ConvertHardwareProfile(azsvm.HardwareProfile),
			StorageProfile:     ConvertStorageProfile(azsvm.StorageProfile),
			OsProfile:          &op,
			NetworkProfile:     ConvertNetworkProfile(azsvm.NetworkProfile),
			DiagnosticsProfile: ConvertDiagnosticsProfile(azsvm.DiagnosticsProfile),
			AvailabilitySet:    ConvertSubResource(azsvm.AvailabilitySet),
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
			vmr.InstanceView = ConvertVirtualMachineExtensionInstanceView(vsvmr.InstanceView)
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

// ConvertVirtualMachineSlice converts *[]compute.VirtualMachine from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineSlice(azs []azscompute.VirtualMachine) []compute.VirtualMachine {

	sp := []compute.VirtualMachine{}
	for _, vsp := range azs {
		sp = append(sp, ConvertVirtualMachine(vsp))
	}

	return sp
}

// ConvertVirtualMachineScaleSetSlice converts *[]compute.VirtualMachine from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetSlice(azsvmss *[]azscompute.VirtualMachineScaleSet) *[]compute.VirtualMachineScaleSet {

	if azsvmss == nil {
		return nil
	}

	svmss := []compute.VirtualMachineScaleSet{}
	for _, vvmss := range *azsvmss {
		svmss = append(svmss, ConvertVirtualMachineScaleSet(vvmss))
	}
	return &svmss
}

// ConvertVirtualMachineScaleSetSliceValue converts []compute.VirtualMachine from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetSliceValue(azsvmss []azscompute.VirtualMachineScaleSet) []compute.VirtualMachineScaleSet {

	svmss := []compute.VirtualMachineScaleSet{}
	for _, vvmss := range azsvmss {
		svmss = append(svmss, ConvertVirtualMachineScaleSet(vvmss))
	}
	return svmss
}

// ConvertVirtualMachineScaleSet converts compute.VirtualMachine from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSet(azsvmss azscompute.VirtualMachineScaleSet) compute.VirtualMachineScaleSet {
	vmss := compute.VirtualMachineScaleSet{
		Response: azsvmss.Response,
		Sku:      ConvertSku(azsvmss.Sku),
		Plan:     ConvertPlan(azsvmss.Plan),
		Identity: ConvertVirtualMachineScaleSetIdentity(azsvmss.Identity),
		Zones:    azsvmss.Zones,
		ID:       azsvmss.ID,
		Name:     azsvmss.Name,
		Type:     azsvmss.Type,
		Location: azsvmss.Location,
		Tags:     azsvmss.Tags,
	}

	vmss.UpgradePolicy = ConvertUpgradePolicy(azsvmss.UpgradePolicy)
	vmss.ProvisioningState = azsvmss.ProvisioningState
	vmss.Overprovision = azsvmss.Overprovision
	vmss.UniqueID = azsvmss.UniqueID
	vmss.SinglePlacementGroup = azsvmss.SinglePlacementGroup
	vmss.ZoneBalance = nil              // empty in azsvmss.ZoneBalance
	vmss.PlatformFaultDomainCount = nil // empty in  azsvmss.PlatformFaultDomainCount
	vmss.VirtualMachineProfile = ConvertVirtualMachineScaleSetVMProfile(azsvmss.VirtualMachineProfile)
	return vmss
}

//ConvertVirtualMachineListResult converts *[]compute.VirtualMachineListResult from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineListResult(azsvmlr azscompute.VirtualMachineListResult) compute.VirtualMachineListResult {
	vmlr := compute.VirtualMachineListResult{
		Response: azsvmlr.Response,
		NextLink: azsvmlr.NextLink,
	}
	if azsvmlr.Value != nil {
		svm := []compute.VirtualMachine{}
		for _, vvm := range *azsvmlr.Value {
			vm := ConvertVirtualMachine(vvm)
			svm = append(svm, vm)
		}
		vmlr.Value = &svm
	}
	return vmlr
}

//ConvertVirtualMachineExtensionInstanceView converts *[]compute.VirtualMachineExtensionInstanceView from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineExtensionInstanceView(azsvmei *azscompute.VirtualMachineExtensionInstanceView) *compute.VirtualMachineExtensionInstanceView {
	if azsvmei == nil {
		return nil
	}
	return &compute.VirtualMachineExtensionInstanceView{
		Name:               azsvmei.Name,
		Type:               azsvmei.Type,
		TypeHandlerVersion: azsvmei.TypeHandlerVersion,
		Substatuses:        ConvertInstanceViewStatusSlice(azsvmei.Substatuses),
		Statuses:           ConvertInstanceViewStatusSlice(azsvmei.Statuses),
	}
}

//ConvertVirtualMachineExtensionInstanceViewSlice converts *compute.VirtualMachineExtensionInstanceView from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineExtensionInstanceViewSlice(sazsvmei *[]azscompute.VirtualMachineExtensionInstanceView) *[]compute.VirtualMachineExtensionInstanceView {
	if sazsvmei == nil {
		return nil
	}
	svme := []compute.VirtualMachineExtensionInstanceView{}
	for _, vsvme := range *sazsvmei {
		svme = append(svme, *ConvertVirtualMachineExtensionInstanceView(&vsvme))
	}
	return &svme
}

//ConvertPlan converts *compute.Plan from version 2017-03-30 to 2018-04-01
func ConvertPlan(azsp *azscompute.Plan) *compute.Plan {
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

//ConvertSku converts *compute.Sku from version 2017-03-30 to 2018-04-01
func ConvertSku(azss *azscompute.Sku) *compute.Sku {
	if azss == nil {
		return nil
	}
	return &compute.Sku{
		Name:     azss.Name,
		Tier:     azss.Tier,
		Capacity: azss.Capacity,
	}
}

//ConvertFromSku converts *compute.Sku from version 2018-04-01 to 2017-03-30
func ConvertFromSku(azs *compute.Sku) *azscompute.Sku {
	if azs == nil {
		return nil
	}
	return &azscompute.Sku{
		Name:     azs.Name,
		Tier:     azs.Tier,
		Capacity: azs.Capacity,
	}
}

//ConvertVirtualMachineScaleSetIdentity converts *compute.VirtualMachineScaleSetIdentity from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetIdentity(azsi *azscompute.VirtualMachineScaleSetIdentity) *compute.VirtualMachineScaleSetIdentity {
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

//ConvertUpgradePolicy converts *compute.UpgradePolicy from version 2017-03-30 to 2018-04-01
func ConvertUpgradePolicy(azs *azscompute.UpgradePolicy) *compute.UpgradePolicy {
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

//ConvertVirtualMachineScaleSetVMProfile converts *compute.VirtualMachineScaleSetVMProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetVMProfile(azs *azscompute.VirtualMachineScaleSetVMProfile) *compute.VirtualMachineScaleSetVMProfile {
	if azs == nil {
		return nil
	}
	vmp := compute.VirtualMachineScaleSetVMProfile{
		OsProfile:          ConvertVirtualMachineScaleSetOSProfile(azs.OsProfile),
		StorageProfile:     ConvertVirtualMachineScaleSetStorageProfile(azs.StorageProfile),
		NetworkProfile:     ConvertVirtualMachineScaleSetNetworkProfile(azs.NetworkProfile),
		DiagnosticsProfile: ConvertDiagnosticsProfile(azs.DiagnosticsProfile),
		ExtensionProfile:   ConvertVirtualMachineScaleSetExtensionProfile(azs.ExtensionProfile),
		LicenseType:        azs.LicenseType,
		Priority:           "", // empty in azure stack
		EvictionPolicy:     "", // empty in azure stack
	}
	return &vmp
}

//ConvertVirtualMachineScaleSetOSProfile converts *compute.VirtualMachineScaleSetOSProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetOSProfile(azs *azscompute.VirtualMachineScaleSetOSProfile) *compute.VirtualMachineScaleSetOSProfile {
	if azs == nil {
		return nil
	}
	op := compute.VirtualMachineScaleSetOSProfile{
		ComputerNamePrefix:   azs.ComputerNamePrefix,
		AdminUsername:        azs.AdminUsername,
		AdminPassword:        azs.AdminPassword,
		CustomData:           azs.CustomData,
		WindowsConfiguration: ConvertWindowsConfiguration(azs.WindowsConfiguration),
		LinuxConfiguration:   ConvertLinuxConfiguration(azs.LinuxConfiguration),
		Secrets:              ConvertVaultSecretGroup(azs.Secrets),
	}
	return &op
}

//ConvertWindowsConfiguration converts *compute.WindowsConfiguration from version 2017-03-30 to 2018-04-01
func ConvertWindowsConfiguration(azs *azscompute.WindowsConfiguration) *compute.WindowsConfiguration {
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

//ConvertLinuxConfiguration converts *compute.LinuxConfiguration from version 2017-03-30 to 2018-04-01
func ConvertLinuxConfiguration(azs *azscompute.LinuxConfiguration) *compute.LinuxConfiguration {
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

//ConvertVaultSecretGroup converts *[]compute.VaultSecretGroup from version 2017-03-30 to 2018-04-01
func ConvertVaultSecretGroup(azs *[]azscompute.VaultSecretGroup) *[]compute.VaultSecretGroup {
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

//ConvertImageReference converts *compute.ImageReference from version 2017-03-30 to 2018-04-01
func ConvertImageReference(azs *azscompute.ImageReference) *compute.ImageReference {
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

//ConvertVirtualMachineScaleSetOSDisk converts *compute.VirtualMachineScaleSetOSDisk from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetOSDisk(azs *azscompute.VirtualMachineScaleSetOSDisk) *compute.VirtualMachineScaleSetOSDisk {
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
		Image:                   ConvertVirtualHardDisk(azs.Image),
		VhdContainers:           azs.VhdContainers,
	}

	if azs.ManagedDisk != nil {
		od.ManagedDisk = &compute.VirtualMachineScaleSetManagedDiskParameters{
			StorageAccountType: compute.StorageAccountTypes(string(azs.ManagedDisk.StorageAccountType)),
		}
	}
	return &od
}

//ConvertVirtualMachineScaleSetDataDisk converts *[]compute.VirtualMachineScaleSetDataDisk from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetDataDisk(azs *[]azscompute.VirtualMachineScaleSetDataDisk) *[]compute.VirtualMachineScaleSetDataDisk {
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

//ConvertVirtualHardDisk converts *compute.VirtualHardDisk from version 2017-03-30 to 2018-04-01
func ConvertVirtualHardDisk(azs *azscompute.VirtualHardDisk) *compute.VirtualHardDisk {
	if azs == nil {
		return nil
	}
	return &compute.VirtualHardDisk{
		URI: azs.URI,
	}
}

//ConvertVirtualMachineScaleSetStorageProfile converts *compute.VirtualMachineScaleSetStorageProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetStorageProfile(azs *azscompute.VirtualMachineScaleSetStorageProfile) *compute.VirtualMachineScaleSetStorageProfile {
	if azs == nil {
		return nil
	}
	return &compute.VirtualMachineScaleSetStorageProfile{
		ImageReference: ConvertImageReference(azs.ImageReference),
		OsDisk:         ConvertVirtualMachineScaleSetOSDisk(azs.OsDisk),
		DataDisks:      ConvertVirtualMachineScaleSetDataDisk(azs.DataDisks),
	}
}

//ConvertVirtualMachineScaleSetNetworkProfile converts *compute.VirtualMachineScaleSetNetworkProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetNetworkProfile(azs *azscompute.VirtualMachineScaleSetNetworkProfile) *compute.VirtualMachineScaleSetNetworkProfile {
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
					ipc.ApplicationGatewayBackendAddressPools = ConvertSubResourceSlice(vsipc.ApplicationGatewayBackendAddressPools)
					ipc.LoadBalancerBackendAddressPools = ConvertSubResourceSlice(vsipc.LoadBalancerBackendAddressPools)
					ipc.LoadBalancerInboundNatPools = ConvertSubResourceSlice(vsipc.LoadBalancerInboundNatPools)
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

// ConvertSubResource converts *compute.SubResource from version 2017-03-30 to 2018-04-01
func ConvertSubResource(azs *azscompute.SubResource) *compute.SubResource {

	if azs == nil {
		return nil
	}
	return &compute.SubResource{
		ID: azs.ID,
	}
}

//ConvertSubResourceSlice converts *[]compute.SubResource from version 2017-03-30 to 2018-04-01
func ConvertSubResourceSlice(azs *[]azscompute.SubResource) *[]compute.SubResource {

	if azs == nil {
		return nil
	}

	ssr := []compute.SubResource{}
	for _, vssr := range *azs {
		ssr = append(ssr, *ConvertSubResource(&vssr))
	}
	return &ssr
}

//ConvertDiagnosticsProfile converts *compute.DiagnosticsProfile from version 2017-03-30 to 2018-04-01
func ConvertDiagnosticsProfile(azs *azscompute.DiagnosticsProfile) *compute.DiagnosticsProfile {
	if azs == nil {
		return nil
	}

	dp := compute.DiagnosticsProfile{}
	dp.BootDiagnostics = ConvertBootDiagnostics(azs.BootDiagnostics)
	return &dp
}

//ConvertBootDiagnostics converts *compute.BootDiagnostics from version 2017-03-30 to 2018-04-01
func ConvertBootDiagnostics(azs *azscompute.BootDiagnostics) *compute.BootDiagnostics {
	if azs == nil {
		return nil
	}

	return &compute.BootDiagnostics{
		Enabled:    azs.Enabled,
		StorageURI: azs.StorageURI,
	}
}

//ConvertVirtualMachineScaleSetExtensionProfile converts *compute.DiagnosticsProfile from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetExtensionProfile(azs *azscompute.VirtualMachineScaleSetExtensionProfile) *compute.VirtualMachineScaleSetExtensionProfile {
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

//ConvertVirtualMachineScaleSetListResult converts compute.VirtualMachineScaleSetListResult from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetListResult(azs azscompute.VirtualMachineScaleSetListResult) compute.VirtualMachineScaleSetListResult {
	return compute.VirtualMachineScaleSetListResult{
		Response: azs.Response,
		NextLink: azs.NextLink,
		Value:    ConvertVirtualMachineScaleSetSlice(azs.Value),
	}
}

//ConvertVirtualMachineScaleSetVMListResult converts compute.VirtualMachineScaleSetVMListResult from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetVMListResult(azs azscompute.VirtualMachineScaleSetVMListResult) compute.VirtualMachineScaleSetVMListResult {
	return compute.VirtualMachineScaleSetVMListResult{
		Response: azs.Response,
		NextLink: azs.NextLink,
		Value:    ConvertVirtualMachineScaleSetVMSlice(azs.Value),
	}
}

// ConvertVirtualMachineScaleSetVMSlice converts *[]compute.VirtualMachineScaleSetVM from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetVMSlice(azsvmss *[]azscompute.VirtualMachineScaleSetVM) *[]compute.VirtualMachineScaleSetVM {
	if azsvmss == nil {
		return nil
	}

	svmss := []compute.VirtualMachineScaleSetVM{}
	for _, vvmss := range *azsvmss {
		svmss = append(svmss, ConvertVirtualMachineScaleSetVM(vvmss))
	}
	return &svmss
}

// ConvertVirtualMachineScaleSetVMSliceValue converts []compute.VirtualMachineScaleSetVM from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetVMSliceValue(azsvmss []azscompute.VirtualMachineScaleSetVM) []compute.VirtualMachineScaleSetVM {
	svmss := []compute.VirtualMachineScaleSetVM{}
	for _, vvmss := range azsvmss {
		svmss = append(svmss, ConvertVirtualMachineScaleSetVM(vvmss))
	}
	return svmss
}

// ConvertVirtualMachineScaleSetVM converts compute.VirtualMachine from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetVM(azsvmss azscompute.VirtualMachineScaleSetVM) compute.VirtualMachineScaleSetVM {
	vmss := compute.VirtualMachineScaleSetVM{
		Response:   azsvmss.Response,
		InstanceID: azsvmss.InstanceID,
		Sku:        ConvertSku(azsvmss.Sku),
		Plan:       ConvertPlan(azsvmss.Plan),
		Zones:      nil, //empty in azsvmss.Zones,
		ID:         azsvmss.ID,
		Name:       azsvmss.Name,
		Type:       azsvmss.Type,
		Location:   azsvmss.Location,
		Tags:       azsvmss.Tags,
	}

	vmss.LatestModelApplied = azsvmss.LatestModelApplied
	vmss.VMID = azsvmss.VMID
	vmss.InstanceView = ConvertVirtualMachineScaleSetVMInstanceView(azsvmss.InstanceView)
	vmss.HardwareProfile = ConvertHardwareProfile(azsvmss.HardwareProfile)
	vmss.StorageProfile = ConvertStorageProfile(azsvmss.StorageProfile)
	vmss.NetworkProfile = ConvertNetworkProfile(azsvmss.NetworkProfile)
	vmss.DiagnosticsProfile = ConvertDiagnosticsProfile(azsvmss.DiagnosticsProfile)
	vmss.AvailabilitySet = ConvertSubResource(azsvmss.AvailabilitySet)

	vmss.ProvisioningState = azsvmss.ProvisioningState
	return vmss
}

// ConvertHardwareProfile converts compute.HardwareProfile from version 2017-03-30 to 2018-04-01
func ConvertHardwareProfile(azs *azscompute.HardwareProfile) *compute.HardwareProfile {
	if azs == nil {
		return nil
	}

	return &compute.HardwareProfile{
		VMSize: compute.VirtualMachineSizeTypes(string(azs.VMSize)),
	}
}

// ConvertVirtualMachineScaleSetVMInstanceView converts compute.VirtualMachineScaleSetVMInstanceView from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineScaleSetVMInstanceView(azs *azscompute.VirtualMachineScaleSetVMInstanceView) *compute.VirtualMachineScaleSetVMInstanceView {
	if azs == nil {
		return nil
	}

	iw := compute.VirtualMachineScaleSetVMInstanceView{
		Response:                  azs.Response,
		PlatformUpdateDomain:      azs.PlatformUpdateDomain,
		PlatformFaultDomain:       azs.PlatformFaultDomain,
		RdpThumbPrint:             azs.RdpThumbPrint,
		VMAgent:                   ConvertVirtualMachineAgentInstanceView(azs.VMAgent),
		MaintenanceRedeployStatus: nil, // empty in ConvertMaintenanceRedeployStatus(azs.MaintenanceRedeployStatus)

		Disks:            ConvertDiskInstanceViewSlice(azs.Disks),
		Extensions:       ConvertVirtualMachineExtensionInstanceViewSlice(azs.Extensions),
		BootDiagnostics:  ConvertBootDiagnosticsInstanceView(azs.BootDiagnostics),
		Statuses:         ConvertInstanceViewStatusSlice(azs.Statuses),
		PlacementGroupID: azs.PlacementGroupID,
	}

	return &iw
}

// ConvertVirtualMachineAgentInstanceView converts *compute.VirtualMachineAgentInstanceView from version 2017-03-30 to 2018-04-01
func ConvertVirtualMachineAgentInstanceView(azs *azscompute.VirtualMachineAgentInstanceView) *compute.VirtualMachineAgentInstanceView {
	if azs == nil {
		return nil
	}

	va := compute.VirtualMachineAgentInstanceView{
		VMAgentVersion: azs.VMAgentVersion,
	}

	if azs.ExtensionHandlers != nil {
		sehi := []compute.VirtualMachineExtensionHandlerInstanceView{}
		for _, vehi := range *azs.ExtensionHandlers {
			ehi := compute.VirtualMachineExtensionHandlerInstanceView{
				Type:               vehi.Type,
				TypeHandlerVersion: vehi.TypeHandlerVersion,
			}

			ehi.Status = ConvertInstanceViewStatus(vehi.Status)
			sehi = append(sehi, ehi)
		}
		va.ExtensionHandlers = &sehi
	}

	va.Statuses = ConvertInstanceViewStatusSlice(azs.Statuses)

	return &va

}

// ConvertMaintenanceRedeployStatus converts *compute.MaintenanceRedeployStatus from version 2017-03-30 to 2018-04-01
func ConvertMaintenanceRedeployStatus(azs *azscompute.MaintenanceRedeployStatus) *compute.MaintenanceRedeployStatus {
	if azs == nil {
		return nil
	}
	return &compute.MaintenanceRedeployStatus{
		IsCustomerInitiatedMaintenanceAllowed: azs.IsCustomerInitiatedMaintenanceAllowed,
		PreMaintenanceWindowStartTime:         azs.PreMaintenanceWindowStartTime,
		PreMaintenanceWindowEndTime:           azs.PreMaintenanceWindowEndTime,
		MaintenanceWindowStartTime:            azs.MaintenanceWindowStartTime,
		MaintenanceWindowEndTime:              azs.MaintenanceWindowEndTime,
		LastOperationResultCode:               compute.MaintenanceOperationResultCodeTypes(string(azs.LastOperationResultCode)),
		LastOperationMessage:                  azs.LastOperationMessage,
	}
}

// ConvertBootDiagnosticsInstanceView converts *compute.BootDiagnosticsInstanceView from version 2017-03-30 to 2018-04-01
func ConvertBootDiagnosticsInstanceView(azs *azscompute.BootDiagnosticsInstanceView) *compute.BootDiagnosticsInstanceView {
	if azs == nil {
		return nil
	}

	return &compute.BootDiagnosticsInstanceView{
		ConsoleScreenshotBlobURI: azs.ConsoleScreenshotBlobURI,
		SerialConsoleLogBlobURI:  azs.SerialConsoleLogBlobURI,
	}
}

// ConvertDiskInstanceViewSlice converts *[]compute.DiskInstanceView from version 2017-03-30 to 2018-04-01
func ConvertDiskInstanceViewSlice(azs *[]azscompute.DiskInstanceView) *[]compute.DiskInstanceView {

	if azs == nil {
		return nil
	}
	svmid := []compute.DiskInstanceView{}
	for _, vsvmid := range *azs {
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

	return &svmid
}

// ConvertInstanceViewStatusSlice converts *[]compute.InstanceViewStatus from version 2017-03-30 to 2018-04-01
func ConvertInstanceViewStatusSlice(azs *[]azscompute.InstanceViewStatus) *[]compute.InstanceViewStatus {
	if azs == nil {
		return nil
	}
	svmss1 := []compute.InstanceViewStatus{}
	for _, vsvmss1 := range *azs {
		svmss1 = append(svmss1, *ConvertInstanceViewStatus(&vsvmss1))
	}
	return &svmss1
}

// ConvertInstanceViewStatus converts *compute.InstanceViewStatus from version 2017-03-30 to 2018-04-01
func ConvertInstanceViewStatus(azs *azscompute.InstanceViewStatus) *compute.InstanceViewStatus {
	if azs == nil {
		return nil
	}
	return &compute.InstanceViewStatus{
		Code:          azs.Code,
		Level:         compute.StatusLevelTypes(string(azs.Level)),
		DisplayStatus: azs.DisplayStatus,
		Message:       azs.Message,
		Time:          azs.Time,
	}
}

// ConvertStorageProfile converts *compute.StorageProfile from version 2017-03-30 to 2018-04-01
func ConvertStorageProfile(azs *azscompute.StorageProfile) *compute.StorageProfile {
	if azs == nil {
		return nil
	}
	sp := compute.StorageProfile{}
	sp.ImageReference = ConvertImageReference(azs.ImageReference)
	if azs.OsDisk != nil {
		od := compute.OSDisk{
			OsType:                  compute.OperatingSystemTypes(string(azs.OsDisk.OsType)),
			Name:                    azs.OsDisk.Name,
			Caching:                 compute.CachingTypes(string(azs.OsDisk.Caching)),
			WriteAcceleratorEnabled: to.BoolPtr(false),
			CreateOption:            compute.DiskCreateOptionTypes(string(azs.OsDisk.CreateOption)),
			DiskSizeGB:              azs.OsDisk.DiskSizeGB,
		}
		if azs.OsDisk.EncryptionSettings != nil {
			odes := compute.DiskEncryptionSettings{}
			od.EncryptionSettings = &odes
		}
		if azs.OsDisk.Vhd != nil {
			odvhd := compute.VirtualHardDisk{
				URI: azs.OsDisk.Vhd.URI,
			}
			od.Vhd = &odvhd
		}
		if azs.OsDisk.Image != nil {
			odi := compute.VirtualHardDisk{
				URI: azs.OsDisk.Image.URI,
			}
			od.Image = &odi
		}
		if azs.OsDisk.ManagedDisk != nil {
			odm := compute.ManagedDiskParameters{
				ID:                 azs.OsDisk.ManagedDisk.ID,
				StorageAccountType: compute.StorageAccountTypes(string(azs.OsDisk.ManagedDisk.StorageAccountType)),
			}
			od.ManagedDisk = &odm
		}
	}
	return &sp
}

// ConvertNetworkProfile converts *compute.NetworkProfile from version 2017-03-30 to 2018-04-01
func ConvertNetworkProfile(azs *azscompute.NetworkProfile) *compute.NetworkProfile {

	if azs == nil {
		return nil
	}
	np := compute.NetworkProfile{}
	snpn := []compute.NetworkInterfaceReference{}
	for _, vsnpn := range *azs.NetworkInterfaces {
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
	return &np
}

// ConvertDiskList converts compute.DiskList from version 2017-03-30 to 2018-04-01
func ConvertDiskList(azs azscompute.DiskList) compute.DiskList {

	return compute.DiskList{
		Response: azs.Response,
		Value:    ConvertDiskSlice(azs.Value),
		NextLink: azs.NextLink,
	}

}

// ConvertCreationData converts *compute.CreationData from version 2017-03-30 to 2018-04-01
func ConvertCreationData(azs *azscompute.CreationData) *compute.CreationData {

	if azs == nil {
		return nil
	}
	return &compute.CreationData{}
}

// ConvertKeyVaultAndSecretReference converts *compute.KeyVaultAndSecretReference from version 2017-03-30 to 2018-04-01
func ConvertKeyVaultAndSecretReference(azs *azscompute.KeyVaultAndSecretReference) *compute.KeyVaultAndSecretReference {

	if azs == nil {
		return nil
	}
	r := compute.KeyVaultAndSecretReference{
		SecretURL: azs.SecretURL,
	}
	if azs.SourceVault != nil {
		r.SourceVault = &compute.SourceVault{
			ID: azs.SourceVault.ID,
		}
	}
	return &r
}

// ConvertKeyVaultAndKeyReference converts *compute.KeyVaultAndKeyReference from version 2017-03-30 to 2018-04-01
func ConvertKeyVaultAndKeyReference(azs *azscompute.KeyVaultAndKeyReference) *compute.KeyVaultAndKeyReference {

	if azs == nil {
		return nil
	}
	r := compute.KeyVaultAndKeyReference{
		KeyURL: azs.KeyURL,
	}
	if azs.SourceVault != nil {
		r.SourceVault = &compute.SourceVault{
			ID: azs.SourceVault.ID,
		}
	}
	return &r
}

// ConvertEncryptionSettings converts *compute.EncryptionSettings from version 2017-03-30 to 2018-04-01
func ConvertEncryptionSettings(azs *azscompute.EncryptionSettings) *compute.EncryptionSettings {

	if azs == nil {
		return nil
	}
	return &compute.EncryptionSettings{
		Enabled:           azs.Enabled,
		DiskEncryptionKey: ConvertKeyVaultAndSecretReference(azs.DiskEncryptionKey),
		KeyEncryptionKey:  ConvertKeyVaultAndKeyReference(azs.KeyEncryptionKey),
	}
}

// ConvertDisk converts *compute.Disk from version 2017-03-30 to 2018-04-01
func ConvertDisk(azs *azscompute.Disk) *compute.Disk {

	if azs == nil {
		return nil
	}
	d := compute.Disk{
		Response:  azs.Response,
		ManagedBy: azs.ManagedBy,
		Zones:     azs.Zones,
		ID:        azs.ID,
		Name:      azs.Name,
		Location:  azs.Location,
		Tags:      azs.Tags,
	}

	if azs.Sku != nil {
		d.Sku = &compute.DiskSku{
			Name: compute.StorageAccountTypes(string(azs.Sku.Name)),
			Tier: azs.Sku.Tier,
		}
	}
	d.TimeCreated = azs.TimeCreated
	d.OsType = compute.OperatingSystemTypes(string(azs.OsType))

	d.CreationData = ConvertCreationData(azs.CreationData)
	d.DiskSizeGB = azs.DiskSizeGB
	d.EncryptionSettings = ConvertEncryptionSettings(azs.EncryptionSettings)
	d.ProvisioningState = azs.ProvisioningState

	return &d
}

// ConvertDiskSlice converts *[]compute.NetworkProfile from version 2017-03-30 to 2018-04-01
func ConvertDiskSlice(azs *[]azscompute.Disk) *[]compute.Disk {

	if azs == nil {
		return nil
	}
	snpn := []compute.Disk{}
	for _, vsnpn := range *azs {

		snpn = append(snpn, *ConvertDisk(&vsnpn))
	}
	return &snpn
}

// ConvertDiskSliceValue converts []compute.NetworkProfile from version 2017-03-30 to 2018-04-01
func ConvertDiskSliceValue(azs []azscompute.Disk) []compute.Disk {

	snpn := []compute.Disk{}
	for _, vsnpn := range azs {

		snpn = append(snpn, *ConvertDisk(&vsnpn))
	}
	return snpn
}
