package manifests

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func EtcdOperatorStatefulSet(ns string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "etcd",
			Namespace: ns,
		},
	}
}

func EtcdOperatorPeerService(ns string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "etcd-peer",
			Namespace: ns,
		},
	}
}

func EtcdOperatorClientService(ns string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "etcd-client",
			Namespace: ns,
		},
	}
}

func EtcdOperatorConfigMap(ns string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "etcd-operator",
			Namespace: ns,
		},
	}
}

func EtcdServiceMonitor(ns string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("monitoring.coreos.com/v1")
	obj.SetKind("ServiceMonitor")
	obj.SetName("etcd")
	obj.SetNamespace(ns)
	return obj
}
