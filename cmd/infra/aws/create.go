package aws

import (
	"bytes"
	"context"
	"crypto"
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
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"

	"github.com/openshift/hypershift/cmd/infra/aws/cloudformation"
	"github.com/openshift/hypershift/cmd/infra/aws/provisioner"
	"github.com/openshift/hypershift/cmd/infra/aws/terraform"
	awsutil "github.com/openshift/hypershift/cmd/infra/aws/util"
)

type CreateInfraOptions struct {
	Provisioner string

	AWSCredentialsFile string

	InfraID    string
	Region     string
	BaseDomain string
	Subdomain  string

	CFAdditionalTags  []string
	CFDeleteOnFailure bool

	TerraformDir string
}

func NewCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Creates AWS infrastructure resources for a cluster",
	}

	cmd.AddCommand(terraform.NewTerraformCommand())

	opts := CreateInfraOptions{
		Provisioner:       provisioner.CloudFormationProvisionerType,
		Region:            "us-east-1",
		CFDeleteOnFailure: false,
	}

	cmd.Flags().StringVar(&opts.Provisioner, "provisioner", opts.Provisioner, "one of: cloudformation, terraform")
	cmd.Flags().StringVar(&opts.InfraID, "infra-id", opts.InfraID, "Cluster ID with which to tag AWS resources (required)")
	cmd.Flags().StringVar(&opts.AWSCredentialsFile, "aws-creds", opts.AWSCredentialsFile, "Path to an AWS credentials file (required)")
	cmd.Flags().StringVar(&opts.Region, "region", opts.Region, "Region where cluster infra should be created")
	cmd.Flags().StringSliceVar(&opts.CFAdditionalTags, "additional-tags", opts.CFAdditionalTags, "Additional tags to set on AWS resources")
	cmd.Flags().StringVar(&opts.BaseDomain, "base-domain", opts.BaseDomain, "The base domain for the cluster")
	cmd.Flags().StringVar(&opts.Subdomain, "subdomain", opts.Subdomain, "The subdomain for the cluster")
	cmd.Flags().BoolVar(&opts.CFDeleteOnFailure, "delete-on-failure", opts.CFDeleteOnFailure, "Delete the CloudFormations stack if creation fails")
	cmd.Flags().StringVar(&opts.TerraformDir, "terraform-dir", opts.TerraformDir, "Path to a directory for the cluster's Terraform state")

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

func (o *CreateInfraOptions) Run(ctx context.Context) (*provisioner.AWSInfrastructure, error) {
	log.Info("Provisioning infrastructure", "id", o.InfraID)

	// Run the provisioner
	var p provisioner.Provisioner
	switch o.Provisioner {
	case provisioner.TerraformProvisionerType:
		p = &terraform.TerraformProvisioner{
			AWSCredentialsFile: o.AWSCredentialsFile,
			Directory:          o.TerraformDir,
		}
	case provisioner.CloudFormationProvisionerType:
		fallthrough
	default:
		p = &cloudformation.CloudFormationProvisioner{
			AWSCredentialsFile:       o.AWSCredentialsFile,
			DeleteOnProvisionFailure: o.CFDeleteOnFailure,
		}
	}
	infra, err := p.Provision(ctx, &provisioner.ProvisionOptions{
		InfraID:    o.InfraID,
		Region:     o.Region,
		BaseDomain: o.BaseDomain,
		Subdomain:  o.Subdomain,
	})
	if err != nil {
		return nil, err
	}

	// Initialize the provisioned infrastructure. This should probably be deleted
	// once OIDC is ported to use native k8s support through the apiserver.
	if err := o.configureOIDC(ctx, infra); err != nil {
		return nil, fmt.Errorf("failed to configure OIDC for infastructure: %w", err)
	}

	return infra, err
}

func (o *CreateInfraOptions) configureOIDC(ctx context.Context, infra *provisioner.AWSInfrastructure) error {
	log.Info("Configuring OIDC support for infrastructure", "id", infra.ID)
	awsSession := awsutil.NewSession()
	awsConfig := awsutil.NewConfig(o.AWSCredentialsFile, o.Region)
	s3client := s3.New(awsSession, awsConfig)

	block, _ := pem.Decode(infra.ServiceAccountSigningKey)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the service account signing key")
	}
	serviceAccountSigningKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key from service account signing key block")
	}

	pubKey := &serviceAccountSigningKey.PublicKey
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

	if _, err := s3client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		ACL:    aws.String("public-read"),
		Body:   bytes.NewReader(jwks),
		Bucket: aws.String(infra.OIDCBucketName),
		Key:    aws.String(jwksKey),
	}); err != nil {
		return fmt.Errorf("failed to put jwks in bucket: %w", err)
	}
	log.Info("JWKS document updated", "bucket", infra.OIDCBucketName)

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

	discoveryJSON := fmt.Sprintf(discoveryTemplate, infra.OIDCIssuerURL, infra.OIDCIssuerURL, jwksKey)
	if _, err := s3client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		ACL:    aws.String("public-read"),
		Body:   aws.ReadSeekCloser(strings.NewReader(discoveryJSON)),
		Bucket: aws.String(infra.OIDCBucketName),
		Key:    aws.String(".well-known/openid-configuration"),
	}); err != nil {
		return fmt.Errorf("failed to put discovery JSON in bucket: %w", err)
	}
	log.Info("OIDC discovery document updated", "bucket", infra.OIDCBucketName)

	log.Info("Finished configuring OIDC support for infrastructure", "id", infra.ID)
	return nil
}
