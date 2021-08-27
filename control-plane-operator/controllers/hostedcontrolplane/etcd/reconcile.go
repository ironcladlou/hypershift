package etcd

import (
	"fmt"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/yaml"

	"github.com/openshift/hypershift/control-plane-operator/controllers/hostedcontrolplane/config"
	"github.com/openshift/hypershift/control-plane-operator/controllers/hostedcontrolplane/manifests"
	"github.com/openshift/hypershift/control-plane-operator/controllers/hostedcontrolplane/util"
)

var etcdOperatorDeploymentLabels = map[string]string{
	"name": "etcd-operator",
}

func etcdOperatorContainer() *corev1.Container {
	return &corev1.Container{
		Name: "etcd-operator",
	}
}

func buildEtcdOperatorContainer(image string, replicas int) func(c *corev1.Container) {
	return func(c *corev1.Container) {
		c.Image = image
		c.ImagePullPolicy = corev1.PullAlways
		c.Command = []string{"/usr/bin/etcd-cloud-operator", "--log-level", "debug", "--config", "/etc/etcd/config/config.yaml"}
		c.VolumeMounts = []corev1.VolumeMount{
			{
				Name:      "data",
				MountPath: "/var/lib",
			},
			{
				Name:      "config",
				MountPath: "/etc/etcd/config",
			},
			{
				Name:      "peer-tls",
				MountPath: "/etc/etcd/tls/peer",
			},
			{
				Name:      "server-tls",
				MountPath: "/etc/etcd/tls/server",
			},
		}
		c.Env = []corev1.EnvVar{
			{
				Name:  "ETCD_API",
				Value: "3",
			},
			{
				Name:  "ETCDCTL_INSECURE_SKIP_TLS_VERIFY",
				Value: "true",
			},
			{
				Name:  "STATEFULSET_SERVICE_NAME",
				Value: "etcd-peer",
			},
			{
				Name:  "STATEFULSET_NAME",
				Value: "etcd",
			},
			{
				Name:  "STATEFULSET_DNS_CLUSTER_SUFFIX",
				Value: "cluster.local",
			},
			{
				Name: "POD_IP",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "status.podIP",
					},
				},
			},
			{
				Name: "STATEFULSET_NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.namespace",
					},
				},
			},
			// TODO: Find a way to avoid encoding this in env
			{
				Name:  "STATEFULSET_REPLICAS",
				Value: strconv.Itoa(replicas),
			},
		}
		c.Ports = []corev1.ContainerPort{
			{
				Name:          "client",
				ContainerPort: 2379,
				Protocol:      corev1.ProtocolTCP,
			},
			{
				Name:          "http",
				ContainerPort: 2378,
				Protocol:      corev1.ProtocolTCP,
			},
			{
				Name:          "peer",
				ContainerPort: 2380,
				Protocol:      corev1.ProtocolTCP,
			},
			{
				Name:          "metrics",
				ContainerPort: 2381,
				Protocol:      corev1.ProtocolTCP,
			},
		}
		c.LivenessProbe = &corev1.Probe{
			Handler: corev1.Handler{
				TCPSocket: &corev1.TCPSocketAction{
					Port: intstr.Parse("client"),
				},
			},
			InitialDelaySeconds: 60,
			PeriodSeconds:       30,
		}
		c.ReadinessProbe = &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/status",
					Port: intstr.Parse("http"),
				},
			},
			InitialDelaySeconds: 60,
			PeriodSeconds:       30,
		}
		//c.StartupProbe = &corev1.Probe{
		//	Handler: corev1.Handler{
		//		Exec: &corev1.ExecAction{
		//			Command: []string{"/bin/sh", "-c", "/usr/bin/etcdctl --endpoints=${HOSTNAME}:2379 endpoint health"},
		//		},
		//	},
		//	FailureThreshold: 30,
		//	PeriodSeconds:    10,
		//}
	}
}

func ReconcileOperatorStatefulSet(sts *appsv1.StatefulSet, ownerRef config.OwnerRef, deploymentConfig config.DeploymentConfig, operatorImage string) error {
	peerSecret := manifests.EtcdPeerSecret(sts.Namespace)
	serverSecret := manifests.EtcdServerSecret(sts.Namespace)
	ecoConfig := manifests.EtcdOperatorConfigMap(sts.Namespace)
	ownerRef.ApplyTo(sts)

	sts.Spec = appsv1.StatefulSetSpec{
		ServiceName: "etcd-peer",
		Selector: &metav1.LabelSelector{
			MatchLabels: etcdOperatorDeploymentLabels,
		},
		PodManagementPolicy: appsv1.ParallelPodManagement,
		VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "data",
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					StorageClassName: pointer.StringPtr("gp2"),
					AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("1Gi"),
						},
					},
				},
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: etcdOperatorDeploymentLabels,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					util.BuildContainer(etcdOperatorContainer(), buildEtcdOperatorContainer(operatorImage, deploymentConfig.Replicas)),
				},
				Volumes: []corev1.Volume{
					{
						Name: "config",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: ecoConfig.Name,
								},
							},
						},
					},
					{
						Name: "peer-tls",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: peerSecret.Name,
							},
						},
					},
					{
						Name: "server-tls",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: serverSecret.Name,
							},
						},
					},
				},
			},
		},
	}
	deploymentConfig.ApplyToStatefulSet(sts)
	return nil
}

func ReconcileOperatorConfig(cm *corev1.ConfigMap, ownerRef config.OwnerRef) error {
	ownerRef.ApplyTo(cm)
	type operatorConfig struct {
		ECO Config `json:"eco"`
	}
	ecoConfig := operatorConfig{
		ECO: Config{
			UnhealthyMemberTTL: 2 * time.Minute,
			Etcd: EtcdConfiguration{
				DataDir:                 "/var/lib/etcd",
				BackendQuota:            2 * 1024 * 1024 * 1024,
				AutoCompactionMode:      "periodic",
				AutoCompactionRetention: "0",
				PeerTransportSecurity: SecurityConfig{
					CertFile:      "/etc/etcd/tls/peer/peer.crt",
					KeyFile:       "/etc/etcd/tls/peer/peer.key",
					CertAuth:      true,
					TrustedCAFile: "/etc/etcd/tls/peer/peer-ca.crt",
					AutoTLS:       false,
				},
				ClientTransportSecurity: SecurityConfig{
					CertFile:      "/etc/etcd/tls/server/server.crt",
					KeyFile:       "/etc/etcd/tls/server/server.key",
					CertAuth:      true,
					TrustedCAFile: "/etc/etcd/tls/server/server-ca.crt",
					AutoTLS:       false,
				},
			},
			ASG: ASGConfig{
				Provider: "sts",
			},
			Snapshot: SnapshotConfig{
				Provider: "file",
				Interval: 5 * time.Minute,
				TTL:      1 * time.Hour,
			},
		},
	}
	configBytes, err := yaml.Marshal(ecoConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal etcd operator config: %w", err)
	}
	cm.Data = map[string]string{
		"config.yaml": string(configBytes),
	}
	return nil
}

func ReconcileOperatorPeerService(service *corev1.Service, ownerRef config.OwnerRef) error {
	ownerRef.ApplyTo(service)
	service.Spec = corev1.ServiceSpec{
		Type:      corev1.ServiceTypeClusterIP,
		ClusterIP: corev1.ClusterIPNone,
		Ports: []corev1.ServicePort{
			{
				Name:       "peer",
				Protocol:   corev1.ProtocolTCP,
				Port:       2380,
				TargetPort: intstr.Parse("peer"),
			},
		},
		Selector:                 etcdOperatorDeploymentLabels,
		PublishNotReadyAddresses: true,
	}
	return nil
}

func ReconcileOperatorClientService(service *corev1.Service, ownerRef config.OwnerRef) error {
	ownerRef.ApplyTo(service)
	service.Labels = map[string]string{
		"name": "etcd-client",
	}
	service.Spec = corev1.ServiceSpec{
		Type:      corev1.ServiceTypeClusterIP,
		ClusterIP: corev1.ClusterIPNone,
		Ports: []corev1.ServicePort{
			{
				Name:       "client",
				Protocol:   corev1.ProtocolTCP,
				Port:       2379,
				TargetPort: intstr.Parse("client"),
			},
			{
				Name:       "http",
				Protocol:   corev1.ProtocolTCP,
				Port:       2378,
				TargetPort: intstr.Parse("http"),
			},
			{
				Name:       "metrics",
				Protocol:   corev1.ProtocolTCP,
				Port:       2381,
				TargetPort: intstr.Parse("metrics"),
			},
		},
		Selector: etcdOperatorDeploymentLabels,
	}
	return nil
}

func ReconcileOperatorServiceMonitor(sm *unstructured.Unstructured, ownerRef config.OwnerRef) error {
	ownerRef.ApplyTo(sm)
	serviceMonitorJSON := `
{
   "apiVersion": "monitoring.coreos.com/v1",
   "kind": "ServiceMonitor",
   "spec": {
      "endpoints": [
         {
            "interval": "30s",
            "port": "metrics"
         }
      ],
      "jobLabel": "component",
      "selector": {
         "matchLabels": {
            "name": "etcd-client"
         }
      }
   }
}
`
	obj, err := runtime.Decode(unstructured.UnstructuredJSONScheme, []byte(serviceMonitorJSON))
	if err != nil {
		return err
	}
	desired := obj.(*unstructured.Unstructured)
	spec, found, err := unstructured.NestedMap(desired.Object, "spec")
	if err != nil {
		return fmt.Errorf("couldn't read spec from servicemonitor object")
	}
	if !found {
		return fmt.Errorf("missing spec in servicemonitor object")
	}
	return unstructured.SetNestedField(sm.Object, spec, "spec")
}
