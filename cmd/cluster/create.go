package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	hyperapi "github.com/openshift/hypershift/api"
	apifixtures "github.com/openshift/hypershift/api/fixtures"
	awsinfra "github.com/openshift/hypershift/cmd/infra/aws"
	"github.com/openshift/hypershift/version"

	cr "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// NoopReconcile is just a default mutation function that does nothing.
var NoopReconcile controllerutil.MutateFn = func() error { return nil }

type Options struct {
	Namespace                 string
	Name                      string
	ReleaseImage              string
	PullSecretFile            string
	AWSCredentialsFile        string
	ClusterAWSCredentialsFile string
	SSHKeyFile                string
	NodePoolReplicas          int
	Render                    bool
	InfraID                   string
	InfrastructureJSON        string
	IAMJSON                   string
	InstanceType              string
	Region                    string
}

func NewCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Creates basic functional HostedCluster resources",
	}

	var releaseImage string
	defaultVersion, err := version.LookupDefaultOCPVersion()
	if err != nil {
		fmt.Println("WARN: Unable to lookup default OCP version with error:", err)
		fmt.Println("WARN: The 'release-image' flag is required in this case.")
		releaseImage = ""
	} else {
		releaseImage = defaultVersion.PullSpec
	}

	opts := Options{
		Namespace:                 "clusters",
		Name:                      "example",
		ReleaseImage:              releaseImage,
		PullSecretFile:            "",
		AWSCredentialsFile:        "",
		ClusterAWSCredentialsFile: "",
		SSHKeyFile:                "",
		NodePoolReplicas:          2,
		Render:                    false,
		InfrastructureJSON:        "",
		Region:                    "us-east-1",
		InfraID:                   "",
		InstanceType:              "m4.large",
	}

	cmd.Flags().StringVar(&opts.Namespace, "namespace", opts.Namespace, "A namespace to contain the generated resources")
	cmd.Flags().StringVar(&opts.Name, "name", opts.Name, "A name for the cluster")
	cmd.Flags().StringVar(&opts.ReleaseImage, "release-image", opts.ReleaseImage, "The OCP release image for the cluster")
	cmd.Flags().StringVar(&opts.PullSecretFile, "pull-secret", opts.PullSecretFile, "Path to a pull secret (required)")
	cmd.Flags().StringVar(&opts.AWSCredentialsFile, "aws-creds", opts.AWSCredentialsFile, "Path to an AWS credentials file used for infrastructure (required)")
	cmd.Flags().StringVar(&opts.ClusterAWSCredentialsFile, "cluster-aws-creds", opts.ClusterAWSCredentialsFile, "Path to an AWS credentials file used for the hosted cluster. If unspecified, use aws-creds by default.")
	cmd.Flags().StringVar(&opts.SSHKeyFile, "ssh-key", opts.SSHKeyFile, "Path to an SSH key file")
	cmd.Flags().IntVar(&opts.NodePoolReplicas, "node-pool-replicas", opts.NodePoolReplicas, "If >0, create a default NodePool with this many replicas")
	cmd.Flags().BoolVar(&opts.Render, "render", opts.Render, "Render output as YAML to stdout instead of applying")
	cmd.Flags().StringVar(&opts.InfrastructureJSON, "infra-json", opts.InfrastructureJSON, "Path to file containing infrastructure information for the cluster. If not specified, infrastructure will be created")
	cmd.Flags().StringVar(&opts.IAMJSON, "iam-json", opts.IAMJSON, "Path to file containing IAM information for the cluster. If not specified, IAM will be created")
	cmd.Flags().StringVar(&opts.Region, "region", opts.Region, "Region to use for AWS infrastructure.")
	cmd.Flags().StringVar(&opts.InfraID, "infra-id", opts.InfraID, "Infrastructure ID to use for AWS resources.")
	cmd.Flags().StringVar(&opts.InstanceType, "instance-type", opts.InstanceType, "Instance type for AWS instances.")

	cmd.MarkFlagRequired("pull-secret")
	cmd.MarkFlagRequired("aws-creds")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT)
		go func() {
			<-sigs
			cancel()
		}()
		return CreateCluster(ctx, opts)
	}

	return cmd
}

func CreateCluster(ctx context.Context, opts Options) error {
	pullSecret, err := ioutil.ReadFile(opts.PullSecretFile)
	if err != nil {
		return fmt.Errorf("failed to read pull secret file: %w", err)
	}

	awsCredentials, err := ioutil.ReadFile(opts.AWSCredentialsFile)
	if err != nil {
		return fmt.Errorf("failed to read aws credentials: %w", err)
	}

	var clusterAwsCredentials []byte
	if len(opts.ClusterAWSCredentialsFile) > 0 {
		creds, err := ioutil.ReadFile(opts.ClusterAWSCredentialsFile)
		if err != nil {
			return fmt.Errorf("failed to read cluster aws credentials: %w", err)
		}
		clusterAwsCredentials = creds
		log.Info("using cluster aws credentials", "file", opts.ClusterAWSCredentialsFile)
	} else {
		clusterAwsCredentials = awsCredentials
		log.Info("using cluster aws credentials", "file", opts.AWSCredentialsFile)
	}

	var sshKey []byte
	if len(opts.SSHKeyFile) > 0 {
		key, err := ioutil.ReadFile(opts.SSHKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read ssh key file: %w", err)
		}
		sshKey = key
	}
	if len(opts.ReleaseImage) == 0 {
		return fmt.Errorf("release-image flag is required if default can not be fetched")
	}
	var infra *awsinfra.CreateInfraOutput
	if len(opts.InfrastructureJSON) > 0 {
		rawInfra, err := ioutil.ReadFile(opts.InfrastructureJSON)
		if err != nil {
			return fmt.Errorf("failed to read infra json file: %w", err)
		}
		infra = &awsinfra.CreateInfraOutput{}
		if err = json.Unmarshal(rawInfra, infra); err != nil {
			return fmt.Errorf("failed to load infra json: %w", err)
		}
	}
	if infra == nil {
		infraID := opts.InfraID
		if len(infraID) == 0 {
			infraID = fmt.Sprintf("%s-%s", opts.Name, utilrand.String(5))
		}
		opt := awsinfra.CreateInfraOptions{
			Region:             opts.Region,
			InfraID:            infraID,
			AWSCredentialsFile: opts.AWSCredentialsFile,
		}
		infra, err = opt.CreateInfra()
		if err != nil {
			return fmt.Errorf("failed to create infra: %w", err)
		}
	}

	var iamInfo *awsinfra.CreateIAMOutput
	if len(opts.IAMJSON) > 0 {
		rawIAM, err := ioutil.ReadFile(opts.IAMJSON)
		if err != nil {
			return fmt.Errorf("failed to read iam json file: %w", err)
		}
		iamInfo = &awsinfra.CreateIAMOutput{}
		if err = json.Unmarshal(rawIAM, iamInfo); err != nil {
			return fmt.Errorf("failed to load infra json: %w", err)
		}
	} else {
		opt := awsinfra.CreateIAMOptions{
			Region:             opts.Region,
			AWSCredentialsFile: opts.AWSCredentialsFile,
			InfraID:            infra.InfraID,
		}
		iamInfo, err = opt.CreateIAM()
		if err != nil {
			return fmt.Errorf("failed to create iam: %w", err)
		}
	}

	exampleObjects := apifixtures.ExampleOptions{
		Namespace:        opts.Namespace,
		Name:             opts.Name,
		ReleaseImage:     opts.ReleaseImage,
		PullSecret:       pullSecret,
		AWSCredentials:   clusterAwsCredentials,
		SigningKey:       iamInfo.ServiceAccountSigningKey,
		IssuerURL:        iamInfo.IssuerURL,
		SSHKey:           sshKey,
		NodePoolReplicas: opts.NodePoolReplicas,
		InfraID:          infra.InfraID,
		ComputeCIDR:      infra.ComputeCIDR,
		AWS: apifixtures.ExampleAWSOptions{
			Region:          infra.Region,
			Zone:            infra.Zone,
			VPCID:           infra.VPCID,
			SubnetID:        infra.PrivateSubnetID,
			SecurityGroupID: infra.SecurityGroupID,
			InstanceProfile: iamInfo.ProfileName,
			InstanceType:    opts.InstanceType,
			Roles:           iamInfo.Roles,
		},
	}.Resources().AsObjects()

	switch {
	case opts.Render:
		for _, object := range exampleObjects {
			err := hyperapi.YamlSerializer.Encode(object, os.Stdout)
			if err != nil {
				return fmt.Errorf("failed to encode objects: %w", err)
			}
			fmt.Println("---")
		}
	default:
		client, err := crclient.New(cr.GetConfigOrDie(), crclient.Options{Scheme: hyperapi.Scheme})
		if err != nil {
			return fmt.Errorf("failed to create kube client: %w", err)
		}
		for _, object := range exampleObjects {
			key := crclient.ObjectKeyFromObject(object)
			_, err = controllerutil.CreateOrUpdate(ctx, client, object, NoopReconcile)
			if err != nil {
				return fmt.Errorf("failed to create object %q: %w", key, err)
			}
			log.Info("applied resource", "namespace", key.Namespace, "name", key.Name)
		}
		return nil
	}

	return nil
}
