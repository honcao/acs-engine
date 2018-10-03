package converter

import (
	azsresources "github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-02-01/resources"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
)

// Convert20180201To20180501 converts resources.DeploymentExtended from version 2018-05-01 to 2018-02-01
func Convert20180201To20180501(azsde azsresources.DeploymentExtended) resources.DeploymentExtended {

	de := resources.DeploymentExtended{}
	de.Response = azsde.Response

	return de
}
