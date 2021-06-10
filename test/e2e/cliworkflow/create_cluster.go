// +build e2e

package cliworkflow

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
	awsutil "github.com/openshift/hypershift/cmd/infra/aws/util"
	e2eutil "github.com/openshift/hypershift/test/e2e/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	hyperv1 "github.com/openshift/hypershift/api/v1alpha1"
	cmdcluster "github.com/openshift/hypershift/cmd/cluster"
)

const CreateClusterTestName = "CreateCluster"

// CreateClusterTest implements a test that mimics the operation described in the
// HyperShift quick start (creating a basic guest cluster).
//
// This test is meant to provide a first, fast signal to detect regression; it
// is recommended to use it as a PR blocker test.
type CreateClusterTest struct {
	AWSCredentialsFile string
	AWSRegion          string
	PullSecretFile     string
	ReleaseImage       string
	ArtifactDir        string
	BaseDomain         string
}

func (o CreateClusterTest) New(ctx context.Context, log logr.Logger) (string, func(t *testing.T)) {
	return CreateClusterTestName, func(t *testing.T) { o.test(ctx, t, log) }
}

func (o CreateClusterTest) test(ctx context.Context, t *testing.T, log logr.Logger) {
	g := NewWithT(t)

	awsSession := awsutil.NewSession()
	awsConfig := awsutil.NewConfig(o.AWSCredentialsFile, o.AWSRegion)
	iamClient := iam.New(awsSession, awsConfig)
	ec2Client := ec2.New(awsSession, awsConfig)
	elbClient := elb.New(awsSession, awsConfig)
	route53Client := route53.New(awsSession, awsutil.NewRoute53Config(o.AWSCredentialsFile))

	client := e2eutil.GetClientOrDie()

	log.Info("Testing OCP release image", "image", o.ReleaseImage)

	// Create a namespace in which to place hostedclusters
	namespace := e2eutil.GenerateNamespace(t, ctx, client, "e2e-clusters-")
	name := e2eutil.SimpleNameGenerator.GenerateName("example-")

	// Define the cluster we'll be testing
	hostedCluster := &hyperv1.HostedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace.Name,
			Name:      name,
		},
	}

	// Ensure we clean up after the test
	defer func() {
		e2eutil.DestroyCluster(t, context.Background(), hostedCluster, o.AWSCredentialsFile, o.AWSRegion, o.BaseDomain, o.ArtifactDir)
		e2eutil.DeleteNamespace(t, context.Background(), client, namespace.Name)
	}()

	// Create the cluster
	createClusterOpts := cmdcluster.Options{
		Namespace:          hostedCluster.Namespace,
		Name:               hostedCluster.Name,
		InfraID:            hostedCluster.Name,
		ReleaseImage:       o.ReleaseImage,
		PullSecretFile:     o.PullSecretFile,
		AWSCredentialsFile: o.AWSCredentialsFile,
		Region:             o.AWSRegion,
		EC2Client:          ec2Client,
		Route53Client:      route53Client,
		ELBClient:          elbClient,
		IAMClient:          iamClient,
		// TODO: generate a key on the fly
		SSHKeyFile:       "",
		NodePoolReplicas: 2,
		InstanceType:     "m4.large",
		BaseDomain:       o.BaseDomain,
	}
	err := cmdcluster.CreateCluster(ctx, createClusterOpts)
	g.Expect(err).NotTo(HaveOccurred(), "failed to create cluster")

	// Get the newly created cluster
	err = client.Get(ctx, crclient.ObjectKeyFromObject(hostedCluster), hostedCluster)
	g.Expect(err).NotTo(HaveOccurred(), "failed to get hostedcluster")
	t.Logf("Created hostedcluster %s/%s", hostedCluster.Namespace, hostedCluster.Name)

	// Get the newly created nodepool
	nodepool := &hyperv1.NodePool{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: hostedCluster.Namespace,
			Name:      hostedCluster.Name,
		},
	}
	err = client.Get(ctx, crclient.ObjectKeyFromObject(nodepool), nodepool)
	g.Expect(err).NotTo(HaveOccurred(), "failed to get nodepool")
	t.Logf("Created nodepool %s/%s", nodepool.Namespace, nodepool.Name)

	// Perform some very basic assertions about the guest cluster
	guestClient := e2eutil.WaitForGuestClient(t, ctx, client, hostedCluster)

	e2eutil.WaitForReadyNodes(t, ctx, guestClient, nodepool)

	e2eutil.WaitForReadyClusterOperators(t, ctx, guestClient, hostedCluster)
}
