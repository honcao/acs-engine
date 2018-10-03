package armhelpers

import (
	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2015-07-01/authorization"
)

// RoleAssignmentListResult role assignment list operation result.
type RoleAssignmentListResult authorization.RoleAssignmentListResult

// RoleAssignment role Assignments
type RoleAssignment authorization.RoleAssignment

// RoleAssignmentCreateParameters role assignment create parameters.
type RoleAssignmentCreateParameters authorization.RoleAssignmentCreateParameters
