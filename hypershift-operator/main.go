/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	"k8s.io/client-go/rest"
	capiaws "sigs.k8s.io/cluster-api-provider-aws/api/v1alpha3"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"

	hyperv1 "openshift.io/hypershift/api/v1alpha1"
	"openshift.io/hypershift/hypershift-operator/controllers/externalinfracluster"
	"openshift.io/hypershift/hypershift-operator/controllers/hostedcluster"
	"openshift.io/hypershift/hypershift-operator/controllers/nodepool"

	capiv1 "sigs.k8s.io/cluster-api/api/v1alpha4"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	capiaws.AddToScheme(scheme)
	clientgoscheme.AddToScheme(scheme)
	hyperv1.AddToScheme(scheme)
	capiv1.AddToScheme(scheme)
	configv1.AddToScheme(scheme)
	securityv1.AddToScheme(scheme)
	operatorv1.AddToScheme(scheme)
	routev1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	cmd := &cobra.Command{
		Use: "hypershift-operator",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(1)
		},
	}
	cmd.AddCommand(NewStartCommand())

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func NewStartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Runs the Hypershift operator",
	}

	var namespace string
	var deploymentName string
	var metricsAddr string
	var enableLeaderElection bool
	var operatorImage string

	cmd.Flags().StringVar(&namespace, "namespace", "hypershift", "The namespace this operator lives in")
	cmd.Flags().StringVar(&deploymentName, "deployment-name", "operator", "The name of the deployment of this operator")
	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	cmd.Flags().BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	cmd.Flags().StringVar(&operatorImage, "operator-image", "", "A specific operator image.")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

		mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme:             scheme,
			MetricsBindAddress: metricsAddr,
			Port:               9443,
			LeaderElection:     enableLeaderElection,
			LeaderElectionID:   "b2ed43ca.hypershift.openshift.io",
			// Use a non-caching client everywhere. The default split client does not
			// promise to invalidate the cache during writes (nor does it promise
			// sequential create/get coherence), and we have code which (probably
			// incorrectly) assumes a get immediately following a create/update will
			// return the updated resource. All client consumers will need audited to
			// ensure they are tolerant of stale data (or we need a cache or client that
			// makes stronger coherence guarantees).
			NewClient: func(_ cache.Cache, config *rest.Config, options client.Options) (client.Client, error) {
				return client.New(config, options)
			},
		})
		if err != nil {
			setupLog.Error(err, "unable to start manager")
			os.Exit(1)
		}

		// Add some flexibility to getting the operator image. Use the flag if given,
		// but if that's empty and we're running in a deployment, use the
		// hypershift operator's image by default.
		// TODO: There needs to be some strategy for specifying images everywhere
		kubeClient, err := kubernetes.NewForConfig(mgr.GetConfig())
		if err != nil {
			setupLog.Error(err, "unable to create kube client")
			os.Exit(1)
		}
		lookupOperatorImage := func(deployments appsv1client.DeploymentInterface, name string) (string, error) {
			if len(operatorImage) > 0 {
				setupLog.Info("using operator image from arguments")
				return operatorImage, nil
			}
			deployment, err := deployments.Get(context.TODO(), name, metav1.GetOptions{})
			if err != nil {
				return "", fmt.Errorf("failed to get operator deployment: %w", err)
			}
			for _, container := range deployment.Spec.Template.Spec.Containers {
				// TODO: could use downward API for this too, overkill?
				if container.Name == "operator" {
					setupLog.Info("using operator image from deployment")
					return container.Image, nil
				}
			}
			return "", fmt.Errorf("couldn't locate operator container on deployment")
		}
		operatorImage, err := lookupOperatorImage(kubeClient.AppsV1().Deployments(namespace), deploymentName)
		if err != nil {
			setupLog.Error(err, fmt.Sprintf("failed to find operator image: %s", err), "controller", "hypershift")
			os.Exit(1)
		}
		setupLog.Info("using operator image", "operator-image", operatorImage)

		if err = (&hostedcluster.HostedClusterReconciler{
			Client:        mgr.GetClient(),
			OperatorImage: operatorImage,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "HostedCluster")
			os.Exit(1)
		}

		if err := (&nodepool.NodePoolReconciler{
			Client: mgr.GetClient(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "nodePool")
			os.Exit(1)
		}

		if err := (&externalinfracluster.ExternalInfraClusterReconciler{
			Client: mgr.GetClient(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "ExternalInfraCluster")
			os.Exit(1)
		}

		// +kubebuilder:scaffold:builder

		setupLog.Info("starting manager")

		if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
			setupLog.Error(err, "problem running manager")
			os.Exit(1)
		}
	}

	return cmd
}
