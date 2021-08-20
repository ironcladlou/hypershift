module github.com/openshift/hypershift/operator/ignition-server

go 1.16

replace github.com/openshift/hypershift/api => ../../api

replace github.com/openshift/hypershift/support => ../../support

require (
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/go-logr/logr v0.4.0
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/openshift/hypershift/api v0.0.0-00010101000000-000000000000
	github.com/openshift/hypershift/support v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.1.1
	honnef.co/go/tools v0.0.1-2020.1.4 // indirect
	k8s.io/api v0.20.2
	k8s.io/apimachinery v0.20.2
	k8s.io/utils v0.0.0-20210111153108-fddb29f9d009
	sigs.k8s.io/controller-runtime v0.8.2
)
