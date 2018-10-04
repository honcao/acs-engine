package converter

import (
	azsresources "github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-02-01/resources"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
	"github.com/Azure/go-autorest/autorest/to"
)

// ConvertDeploymentExtended20180201To20180501 converts resources.DeploymentExtended from version 2018-05-01 to 2018-02-01
func ConvertDeploymentExtended20180201To20180501(azsde azsresources.DeploymentExtended) resources.DeploymentExtended {

	de := resources.DeploymentExtended{}
	de.Response = azsde.Response
	de.ID = azsde.ID
	de.Name = azsde.Name
	// TODO: find out the value
	de.Location = to.StringPtr("")
	if azsde.Properties != nil {
		de.Properties.ProvisioningState = azsde.Properties.ProvisioningState
		de.Properties.CorrelationID = azsde.Properties.CorrelationID
		de.Properties.Timestamp = azsde.Properties.Timestamp
		de.Properties.Outputs = azsde.Properties.Outputs

		sp := []resources.Provider{}

		for _, v := range *azsde.Properties.Providers {
			p := resources.Provider{}
			p.Response = v.Response
			p.ID = v.ID
			p.Namespace = v.Namespace
			p.RegistrationState = v.RegistrationState

			sprt := []resources.ProviderResourceType{}
			for _, vprt := range *v.ResourceTypes {
				prt := resources.ProviderResourceType{}
				prt.Locations = vprt.Locations
				prt.APIVersions = vprt.APIVersions
				prt.Properties = vprt.Properties

				sat := []resources.AliasType{}
				for _, vat := range *vprt.Aliases {
					at := resources.AliasType{}
					at.Name = vat.Name

					satp := []resources.AliasPathType{}
					for _, vatp := range *vat.Paths {
						atp := resources.AliasPathType{}
						atp.Path = vatp.Path
						atp.APIVersions = vatp.APIVersions
						satp = append(satp, atp)
					}
					at.Paths = &satp
					sat = append(sat, at)
				}
				prt.Aliases = &sat
				sprt = append(sprt, prt)
			}
			p.ResourceTypes = &sprt
			sp = append(sp, p)
		}

		de.Properties.Providers = &sp

		sd := []resources.Dependency{}
		for _, vd := range *azsde.Properties.Dependencies {
			d := resources.Dependency{}
			d.ID = vd.ID
			d.ResourceType = vd.ResourceType
			d.ResourceName = vd.ResourceName

			sdd := []resources.BasicDependency{}
			for _, vdd := range *vd.DependsOn {
				dd := resources.BasicDependency{}
				dd.ID = vdd.ID
				dd.ResourceName = vdd.ResourceName
				dd.ResourceType = vdd.ResourceType
				sdd = append(sdd, dd)
			}
			d.DependsOn = &sdd

			sd = append(sd, d)
		}

		de.Properties.Dependencies = &sd

		de.Properties.Template = azsde.Properties.Template
		if azsde.Properties.TemplateLink != nil {
			de.Properties.TemplateLink = &resources.TemplateLink{
				URI:            azsde.Properties.TemplateLink.URI,
				ContentVersion: azsde.Properties.TemplateLink.ContentVersion,
			}
		}

		de.Properties.Parameters = azsde.Properties.Parameters
		if azsde.Properties.ParametersLink != nil {
			de.Properties.ParametersLink = &resources.ParametersLink{
				URI:            azsde.Properties.ParametersLink.URI,
				ContentVersion: azsde.Properties.ParametersLink.ContentVersion,
			}
		}

		if len(azsde.Properties.Mode) > 0 {
			de.Properties.Mode = resources.DeploymentMode(string(azsde.Properties.Mode))
		}
		if azsde.Properties.DebugSetting != nil {
			de.Properties.DebugSetting = &resources.DebugSetting{
				DetailLevel: azsde.Properties.DebugSetting.DetailLevel,
			}
		}
		if azsde.Properties.OnErrorDeployment != nil {
			de.Properties.OnErrorDeployment = &resources.OnErrorDeploymentExtended{
				ProvisioningState: azsde.Properties.OnErrorDeployment.ProvisioningState,
				DeploymentName:    azsde.Properties.OnErrorDeployment.DeploymentName,
				Type:              resources.OnErrorDeploymentType(string(azsde.Properties.OnErrorDeployment.Type)),
			}
		}
	}

	return de
}

// ConvertGroup20180201To20180501 converts resources.DeploymentExtended from version 2018-05-01 to 2018-02-01
func ConvertGroup20180201To20180501(azsg azsresources.Group) resources.Group {
	g := resources.Group{
		Response:  azsg.Response,
		ID:        azsg.ID,
		Name:      azsg.Name,
		ManagedBy: azsg.ManagedBy,
		Tags:      azsg.Tags,
	}

	if azsg.Properties != nil {
		g.Properties = &resources.GroupProperties{
			ProvisioningState: azsg.Properties.ProvisioningState,
		}
	}

	return g
}
