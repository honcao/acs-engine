package converter

import (
	azsstorage "github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2016-01-01/storage"
	"github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2018-02-01/storage"
)

// ConvertAccountKeySlice converts *[]azsstorage.AccountKey from version 2016-01-01 to 2018-02-01
func ConvertAccountKeySlice(azs *[]azsstorage.AccountKey) *[]storage.AccountKey {

	if azs == nil {
		return nil
	}

	sp := []storage.AccountKey{}
	for _, vsp := range *azs {
		sp = append(sp, *ConvertAccountKey(&vsp))
	}

	return &sp
}

// ConvertAccountKey converts *azsstorage.AccountKey from version 2016-01-01 to 2018-02-01
func ConvertAccountKey(azs *azsstorage.AccountKey) *storage.AccountKey {

	if azs == nil {
		return nil
	}

	sp := storage.AccountKey{
		KeyName:     azs.KeyName,
		Value:       azs.Value,
		Permissions: storage.KeyPermission(string(azs.Permissions)),
	}
	return &sp
}
