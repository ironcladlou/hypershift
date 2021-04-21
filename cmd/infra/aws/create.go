package aws

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"
)

type CreateInfraOptions struct {
	Provisioner string

	AWSCredentialsFile string

	InfraID        string
	Region         string
	BaseDomain     string
	Subdomain      string
	AdditionalTags []string

	DeleteOnFailure bool

	TerraformOutputsFile string
}

type AWSInfrastructure struct {
	Region                                 string `json:"region"`
	Zone                                   string `json:"zone"`
	ID                                     string `json:"id"`
	ComputeCIDR                            string `json:"computeCIDR"`
	VPCID                                  string `json:"vpcID"`
	PrivateSubnetID                        string `json:"privateSubnetID"`
	PublicSubnetID                         string `json:"publicSubnetID"`
	WorkerSecurityGroupID                  string `json:"workerSecurityGroupID"`
	WorkerInstanceProfileID                string `json:"workerInstanceProfileID"`
	BaseDomainZoneID                       string `json:"baseDomainZoneID"`
	Subdomain                              string `json:"subdomain"`
	SubdomainPrivateZoneID                 string `json:"subdomainPrivateZoneID"`
	SubdomainPublicZoneID                  string `json:"subdomainPublicZoneID"`
	OIDCIngressRoleArn                     string `json:"oidcIngressRoleArn"`
	OIDCImageRegistryRoleArn               string `json:"oidcImageRegistryRoleArn"`
	OIDCCSIDriverRoleArn                   string `json:"oidcCSIDriverRoleArn"`
	OIDCIssuerURL                          string `json:"oidcIssuerURL"`
	OIDCBucketName                         string `json:"oidcBucketName"`
	ServiceAccountSigningKey               []byte `json:"serviceAccountSigningKey"`
	KubeCloudControllerUserAccessKeyID     string `json:"kubeCloudControllerUserAccessKeyID"`
	KubeCloudControllerUserAccessKeySecret string `json:"kubeCloudControllerUserAccessKeySecret"`
	NodePoolManagementUserAccessKeyID      string `json:"nodePoolManagementUserAccessKeyID"`
	NodePoolManagementUserAccessKeySecret  string `json:"nodePoolManagementUserAccessKeySecret"`
}

type Provisioner interface {
	Provision(context.Context, *CreateInfraOptions) (*AWSInfrastructure, error)
	//Destroy(context.Context, DestroyInfraOptions) error
}

func NewCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Creates AWS infrastructure resources for a cluster",
	}

	opts := CreateInfraOptions{
		Provisioner:     "cloudformations",
		Region:          "us-east-1",
		DeleteOnFailure: false,
	}

	cmd.Flags().StringVar(&opts.Provisioner, "provisioner", opts.Provisioner, "one of: cloudformations, terraform")
	cmd.Flags().StringVar(&opts.InfraID, "infra-id", opts.InfraID, "Cluster ID with which to tag AWS resources (required)")
	cmd.Flags().StringVar(&opts.AWSCredentialsFile, "aws-creds", opts.AWSCredentialsFile, "Path to an AWS credentials file (required)")
	cmd.Flags().StringVar(&opts.Region, "region", opts.Region, "Region where cluster infra should be created")
	cmd.Flags().StringSliceVar(&opts.AdditionalTags, "additional-tags", opts.AdditionalTags, "Additional tags to set on AWS resources")
	cmd.Flags().StringVar(&opts.BaseDomain, "base-domain", opts.BaseDomain, "The base domain for the cluster")
	cmd.Flags().StringVar(&opts.Subdomain, "subdomain", opts.Subdomain, "The subdomain for the cluster")
	cmd.Flags().BoolVar(&opts.DeleteOnFailure, "delete-on-failure", opts.DeleteOnFailure, "Delete the infra stack if creation fails")
	cmd.Flags().StringVar(&opts.TerraformOutputsFile, "terraform-outputs-file", opts.TerraformOutputsFile, "Path to Terraform outputs JSON file")

	cmd.MarkFlagRequired("infra-id")
	cmd.MarkFlagRequired("aws-creds")
	cmd.MarkFlagRequired("base-domain")
	cmd.MarkFlagRequired("subdomain")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT)
		go func() {
			<-sigs
			cancel()
		}()
		output, err := opts.Run(ctx)
		if err != nil {
			return err
		}
		data, err := json.Marshal(output)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	return cmd
}

func (o *CreateInfraOptions) Run(ctx context.Context) (*AWSInfrastructure, error) {
	log.Info("Provisioning infrastructure", "id", o.InfraID)

	// Run the provisioner
	var provisioner Provisioner
	switch o.Provisioner {
	case "terraform":
		provisioner = &TerraformProvisioner{}
	case "cloudformations":
		fallthrough
	default:
		provisioner = &CloudFormationProvisioner{}
	}
	infra, err := provisioner.Provision(ctx, o)
	if err != nil {
		return nil, err
	}
	log.Info("Provisioned infrastructure", "id", infra.ID)

	// Initialize the provisioned infrastructure. This should all probably be deleted
	// once OIDC is ported to use native k8s support through the apiserver.
	log.Info("Initializing infrastructure", "id", infra.ID)

	awsSession := newSession()
	awsConfig := newConfig(o.AWSCredentialsFile, o.Region)
	s3client := s3.New(awsSession, awsConfig)

	block, _ := pem.Decode(infra.ServiceAccountSigningKey)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the service account signing key")
	}
	serviceAccountSigningKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from service account signing key block")
	}

	err = o.configureOIDC(s3client, serviceAccountSigningKey, infra.OIDCBucketName, infra.OIDCIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to install OIDC discovery data: %w", err)
	}

	log.Info("Initialized infrastructure", "id", infra.ID)

	return infra, err
}

func (o *CreateInfraOptions) configureOIDC(s3Client s3iface.S3API, privKey *rsa.PrivateKey, bucketName string, issuerURL string) error {
	pubKey := &privKey.PublicKey
	pubKeyDERBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(pubKeyDERBytes)
	pubKeyDERHash := hasher.Sum(nil)
	kid := base64.RawURLEncoding.EncodeToString(pubKeyDERHash)

	var keys []jose.JSONWebKey
	keys = append(keys, jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	})

	const jwksKey = "openid/v1/jwks"
	type KeyResponse struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}
	jwks, err := json.MarshalIndent(KeyResponse{Keys: keys}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal KeyResponse: %w", err)
	}

	if _, err := s3Client.PutObject(&s3.PutObjectInput{
		ACL:    aws.String("public-read"),
		Body:   bytes.NewReader(jwks),
		Bucket: aws.String(bucketName),
		Key:    aws.String(jwksKey),
	}); err != nil {
		return fmt.Errorf("failed to put jwks in bucket: %w", err)
	}
	log.Info("JWKS document updated", "bucket", bucketName)

	discoveryTemplate := `{
	"issuer": "%s",
	"jwks_uri": "%s/%s",
	"response_types_supported": [
		"id_token"
	],
	"subject_types_supported": [
		"public"
	],
	"id_token_signing_alg_values_supported": [
		"RS256"
	],
	"claims_supported": [
		"aud",
		"exp",
		"sub",
		"iat",
		"iss",
		"sub"
	]
}`

	discoveryJSON := fmt.Sprintf(discoveryTemplate, issuerURL, issuerURL, jwksKey)
	if _, err := s3Client.PutObject(&s3.PutObjectInput{
		ACL:    aws.String("public-read"),
		Body:   aws.ReadSeekCloser(strings.NewReader(discoveryJSON)),
		Bucket: aws.String(bucketName),
		Key:    aws.String(".well-known/openid-configuration"),
	}); err != nil {
		return fmt.Errorf("failed to put discovery JSON in bucket: %w", err)
	}
	log.Info("OIDC discovery document updated", "bucket", bucketName)

	return nil
}
