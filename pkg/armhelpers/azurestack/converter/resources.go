package converter

import (
	azsresources "github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-02-01/resources"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
	"github.com/Azure/go-autorest/autorest/to"
)

// ConvertDeploymentExtended converts resources.DeploymentExtended from version 2018-05-01 to 2018-02-01
func ConvertDeploymentExtended(azsde azsresources.DeploymentExtended) resources.DeploymentExtended {

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
			p.ResourceTypes = ConvertProviderResourceTypeSlice(v.ResourceTypes)

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

// ConvertGroup converts resources.DeploymentExtended from version 2018-05-01 to 2018-02-01
func ConvertGroup(azsg azsresources.Group) resources.Group {
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

// ConvertProvider converts resources.ProviderListResult from version 2018-05-01 to 2018-02-01
func ConvertProvider(azs *azsresources.Provider) *resources.Provider {

	if azs == nil {
		return nil
	}

	p := resources.Provider{
		Response:      azs.Response,
		ID:            azs.ID,
		Namespace:     azs.Namespace,
		ResourceTypes: ConvertProviderResourceTypeSlice(azs.ResourceTypes),
	}
	return &p
}

// ConvertProviderResourceType converts resources.ProviderListResult from version 2018-05-01 to 2018-02-01
func ConvertProviderResourceType(azs *azsresources.ProviderResourceType) *resources.ProviderResourceType {
	if azs == nil {
		return nil
	}

	p := resources.ProviderResourceType{
		ResourceType: azs.ResourceType,
		Locations:    azs.Locations,
		Aliases:      ConvertAliasTypeSlice(azs.Aliases),
		APIVersions:  azs.APIVersions,
		Properties:   azs.Properties,
	}
	return &p
}

// ConvertAliasType converts resources.AliasType from version 2018-05-01 to 2018-02-01
func ConvertAliasType(azs *azsresources.AliasType) *resources.AliasType {
	if azs == nil {
		return nil
	}

	at := resources.AliasType{}
	at.Name = azs.Name

	satp := []resources.AliasPathType{}
	for _, vatp := range *azs.Paths {
		atp := resources.AliasPathType{}
		atp.Path = vatp.Path
		atp.APIVersions = vatp.APIVersions
		satp = append(satp, atp)
	}
	at.Paths = &satp
	return &at

}

// ConvertAliasTypeSlice converts *[]resources.AliasType from version 2018-05-01 to 2018-02-01
func ConvertAliasTypeSlice(azs *[]azsresources.AliasType) *[]resources.AliasType {
	if azs == nil {
		return nil
	}

	sp := []resources.AliasType{}
	for _, vsp := range *azs {
		sp = append(sp, *ConvertAliasType(&vsp))
	}

	return &sp
}

// ConvertProviderResourceTypeSlice converts *[]resources.ProviderLiProviderResourceTypestResult from version 2018-05-01 to 2018-02-01
func ConvertProviderResourceTypeSlice(azs *[]azsresources.ProviderResourceType) *[]resources.ProviderResourceType {
	if azs == nil {
		return nil
	}

	sp := []resources.ProviderResourceType{}
	for _, vsp := range *azs {
		sp = append(sp, *ConvertProviderResourceType(&vsp))
	}

	return &sp
}

// ConvertProviderSlice converts *[]resources.Provider from version 2018-05-01 to 2018-02-01
func ConvertProviderSlice(azs *[]azsresources.Provider) *[]resources.Provider {
	if azs == nil {
		return nil
	}

	sp := []resources.Provider{}
	for _, vsp := range *azs {
		sp = append(sp, *ConvertProvider(&vsp))
	}

	return &sp
}

// ConvertProviderSliceValue converts []resources.Provider from version 2018-05-01 to 2018-02-01
func ConvertProviderSliceValue(azs []azsresources.Provider) []resources.Provider {

	sp := []resources.Provider{}
	for _, vsp := range azs {
		sp = append(sp, *ConvertProvider(&vsp))
	}

	return sp
}

// ConvertProviderListResult converts resources.ProviderListResult from version 2018-05-01 to 2018-02-01
func ConvertProviderListResult(azs azsresources.ProviderListResult) resources.ProviderListResult {
	g := resources.ProviderListResult{
		Response: azs.Response,
		Value:    ConvertProviderSlice(azs.Value),
		NextLink: azs.NextLink,
	}

	return g
}

// ConvertDeploymentOperationsListResult converts resources.DeploymentOperationsListResult from version 2018-05-01 to 2018-02-01
func ConvertDeploymentOperationsListResult(azs azsresources.DeploymentOperationsListResult) resources.DeploymentOperationsListResult {
	g := resources.DeploymentOperationsListResult{
		Response: azs.Response,
		Value:    ConvertDeploymentOperationSlice(azs.Value),
		NextLink: azs.NextLink,
	}

	return g
}

// ConvertDeploymentOperationSlice converts *[]resources.DeploymentOperation from version 2018-05-01 to 2018-02-01
func ConvertDeploymentOperationSlice(azs *[]azsresources.DeploymentOperation) *[]resources.DeploymentOperation {
	if azs == nil {
		return nil
	}

	sp := []resources.DeploymentOperation{}
	for _, vsp := range *azs {
		sp = append(sp, *ConvertDeploymentOperation(&vsp))
	}

	return &sp
}

// ConvertDeploymentOperationSliceValue converts []resources.DeploymentOperation from version 2018-05-01 to 2018-02-01
func ConvertDeploymentOperationSliceValue(azs []azsresources.DeploymentOperation) []resources.DeploymentOperation {
	sp := []resources.DeploymentOperation{}
	for _, vsp := range azs {
		sp = append(sp, *ConvertDeploymentOperation(&vsp))
	}

	return sp
}

// ConvertDeploymentOperation converts resources.ProviderListResult from version 2018-05-01 to 2018-02-01
func ConvertDeploymentOperation(azs *azsresources.DeploymentOperation) *resources.DeploymentOperation {

	if azs == nil {
		return nil
	}

	p := resources.DeploymentOperation{
		Response:    azs.Response,
		ID:          azs.ID,
		OperationID: azs.OperationID,
		Properties:  ConvertDeploymentOperationProperties(azs.Properties),
	}
	return &p
}

// ConvertDeploymentOperationProperties converts resources.DeploymentOperationProperties from version 2018-05-01 to 2018-02-01
func ConvertDeploymentOperationProperties(azs *azsresources.DeploymentOperationProperties) *resources.DeploymentOperationProperties {

	if azs == nil {
		return nil
	}

	p := resources.DeploymentOperationProperties{
		ProvisioningState: azs.ProvisioningState,
		Timestamp:         azs.Timestamp,
		ServiceRequestID:  azs.ServiceRequestID,
		StatusCode:        azs.StatusCode,
		TargetResource:    ConvertTargetResource(azs.TargetResource),
		Request:           ConvertHTTPMessage(azs.Request),
		Response:          ConvertHTTPMessage(azs.Response),
	}
	return &p
}

// ConvertTargetResource converts resources.TargetResource from version 2018-05-01 to 2018-02-01
func ConvertTargetResource(azs *azsresources.TargetResource) *resources.TargetResource {

	if azs == nil {
		return nil
	}

	p := resources.TargetResource{
		ID:           azs.ID,
		ResourceName: azs.ResourceName,
		ResourceType: azs.ResourceType,
	}
	return &p
}

// ConvertHTTPMessage converts resources.HTTPMessage from version 2018-05-01 to 2018-02-01
func ConvertHTTPMessage(azs *azsresources.HTTPMessage) *resources.HTTPMessage {

	if azs == nil {
		return nil
	}

	p := resources.HTTPMessage{
		Content: azs.Content,
	}
	return &p
}
