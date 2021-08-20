module github.com/openshift/hypershift/controlplane/hosted-cluster-config-operator

go 1.16

replace github.com/openshift/hypershift/api => ../../api

require (
	github.com/go-logr/logr v0.4.0
	github.com/onsi/gomega v1.11.0 // indirect
	github.com/openshift/api v0.0.0-20201019163320-c6a5ec25f267
	github.com/openshift/client-go v0.0.0-20200929181438-91d71ef2122c
	github.com/openshift/hypershift/api v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.7.0
	honnef.co/go/tools v0.0.1-2020.1.4 // indirect
	k8s.io/api v0.20.2
	k8s.io/apiextensions-apiserver v0.20.2
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v0.20.2
	sigs.k8s.io/controller-runtime v0.8.2
)
