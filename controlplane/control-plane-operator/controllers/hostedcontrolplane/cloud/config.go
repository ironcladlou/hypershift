package cloud

import (
	"github.com/openshift/hypershift/controlplane/control-plane-operator/controllers/hostedcontrolplane/cloud/aws"
)

func ProviderConfigKey(provider string) string {
	switch provider {
	case aws.Provider:
		return aws.ProviderConfigKey
	default:
		return ""
	}
}
