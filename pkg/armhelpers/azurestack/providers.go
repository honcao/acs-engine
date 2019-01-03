package azurestack

import (
	"context"

	"github.com/Azure/acs-engine/pkg/armhelpers"
	"github.com/Azure/acs-engine/pkg/armhelpers/azurestack/converter"

	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-02-01/resources"
	azresources "github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
	"github.com/Azure/go-autorest/autorest/to"
)

// ProviderListResultPageClient contains a page of Provider values.
type ProviderListResultPageClient struct {
	plrp resources.ProviderListResultPage
	err  error
}

// Next advances to the next page of values.  If there was an error making
// the request the page does not advance and the error is returned.
func (page *ProviderListResultPageClient) Next() error {
	return page.plrp.Next()
}

// NotDone returns true if the page enumeration should be started or is not yet complete.
func (page ProviderListResultPageClient) NotDone() bool {
	return page.plrp.NotDone()
}

// Response returns the raw server response from the last page request.
func (page ProviderListResultPageClient) Response() azresources.ProviderListResult {
	return converter.ConvertProviderListResult(page.plrp.Response())
}

// Values returns the slice of values for the current page or nil if there are no values.
func (page ProviderListResultPageClient) Values() []azresources.Provider {
	return converter.ConvertProviderSliceValue(page.plrp.Values())
}

// ListProviders returns all the providers for a given AzureClient
func (az *AzureClient) ListProviders(ctx context.Context) (armhelpers.ProviderListResultPage, error) {
	azsp, err := az.providersClient.List(ctx, to.Int32Ptr(100), "")
	return &ProviderListResultPageClient{
		plrp: azsp,
		err:  err,
	}, err
}
