package graphrbac

import (
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
)

// ApplicationCreateParameters request parameters for creating a new application.
type ApplicationCreateParameters graphrbac.ApplicationCreateParameters

// Application active Directory application information.
type Application graphrbac.Application

// ServicePrincipal active Directory service principal information.
type ServicePrincipal graphrbac.ServicePrincipal

// ServicePrincipalCreateParameters request parameters for creating a new service principal.
type ServicePrincipalCreateParameters graphrbac.ServicePrincipalCreateParameters

// RequiredResourceAccess specifies the set of OAuth 2.0 permission scopes and app roles under the specified
// resource that an application requires access to. The specified OAuth 2.0 permission scopes may be requested by
// client applications (through the requiredResourceAccess collection) when calling a resource application. The
// requiredResourceAccess property of the Application entity is a collection of ReqiredResourceAccess.
type RequiredResourceAccess graphrbac.RequiredResourceAccess
