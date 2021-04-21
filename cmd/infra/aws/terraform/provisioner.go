package terraform

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/bombsimon/logrusr"
	"github.com/sirupsen/logrus"

	"github.com/openshift/hypershift/cmd/infra/aws/provisioner"
	awsutil "github.com/openshift/hypershift/cmd/infra/aws/util"
)

var log = logrusr.NewLogger(logrus.New())

type TerraformProvisioner struct {
	AWSCredentialsFile string
	Directory          string
}

//go:embed cluster.tf
var terraformClusterConfig string

type terraformOutput struct {
	Value     string `json:"value"`
	Type      string `json:"type"`
	Sensitive bool   `json:"sensitive"`
}

func (p *TerraformProvisioner) Provision(ctx context.Context, opts *provisioner.ProvisionOptions) (*provisioner.AWSInfrastructure, error) {
	// Go find the zone ID for the base domain as a convenience
	awsSession := awsutil.NewSession()
	r53 := route53.New(awsSession, awsutil.NewConfig(p.AWSCredentialsFile, "us-east-1"))
	baseDomainZoneID, err := awsutil.LookupZone(r53, opts.BaseDomain, false)
	if err != nil {
		return nil, fmt.Errorf("couldn't find a public zone for base domain %s: %w", opts.BaseDomain, err)
	}
	log.Info("Discovered base domain zone", "baseDomain", opts.BaseDomain, "id", baseDomainZoneID)

	// Set up the cluster state directory
	if _, err := os.Stat(p.Directory); os.IsNotExist(err) {
		if err := os.MkdirAll(p.Directory, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %q: %w", p.Directory, err)
		} else {
			log.Info("Created terraform directory", "dir", p.Directory)
		}
	}
	configPath := filepath.Join(p.Directory, "cluster.tf")
	if err := ioutil.WriteFile(configPath, []byte(terraformClusterConfig), 0644); err != nil {
		return nil, fmt.Errorf("failed to write terraform config: %w", err)
	} else {
		log.Info("Wrote terraform config", "path", configPath)
	}
	initCommand := exec.Command("terraform", "init")
	initCommand.Dir = p.Directory
	initCommand.Env = append(os.Environ(), "AWS_SHARED_CREDENTIALS_FILE="+p.AWSCredentialsFile)
	initCommand.Stdout = os.Stdout
	initCommand.Stderr = os.Stderr
	if err := initCommand.Run(); err != nil {
		return nil, fmt.Errorf("terraform returned an error: %w", err)
	}

	// Apply the infrastructure
	args := []string{
		"apply",
		"--auto-approve",
		fmt.Sprintf("--var=aws_region=%s", opts.Region),
		fmt.Sprintf("--var=cluster_id=%s", opts.InfraID),
		fmt.Sprintf("--var=cluster_domain=%s", opts.Subdomain),
		fmt.Sprintf("--var=base_domain_zone_id=%s", baseDomainZoneID),
	}
	applyCommand := exec.Command("terraform", args...)
	applyCommand.Dir = p.Directory
	applyCommand.Env = append(os.Environ(), "AWS_SHARED_CREDENTIALS_FILE="+p.AWSCredentialsFile)
	applyCommand.Stdout = os.Stdout
	applyCommand.Stderr = os.Stderr
	if err := applyCommand.Run(); err != nil {
		return nil, fmt.Errorf("terraform returned an error: %w", err)
	}

	// Return the infrastructure details
	return getInfrastructure(p.Directory)
}

func (p *TerraformProvisioner) Destroy(ctx context.Context, opts *provisioner.DestroyOptions) error {
	infra, err := getInfrastructure(p.Directory)
	if err != nil {
		return fmt.Errorf("failed to get infrastructure from terraform state: %w", err)
	}

	args := []string{
		"destroy",
		"--auto-approve",
		fmt.Sprintf("--var=aws_region=%s", infra.Region),
		fmt.Sprintf("--var=cluster_id=%s", infra.ID),
		fmt.Sprintf("--var=cluster_domain=%s", infra.Subdomain),
		fmt.Sprintf("--var=base_domain_zone_id=%s", infra.BaseDomainZoneID),
	}
	destroyCommand := exec.Command("terraform", args...)
	destroyCommand.Env = append(os.Environ(), "AWS_SHARED_CREDENTIALS_FILE="+p.AWSCredentialsFile)
	destroyCommand.Dir = p.Directory
	destroyCommand.Stdout = os.Stdout
	destroyCommand.Stderr = os.Stderr
	if err := destroyCommand.Run(); err != nil {
		return fmt.Errorf("terraform returned an error: %w", err)
	}

	return nil
}

func getInfrastructure(dir string) (*provisioner.AWSInfrastructure, error) {
	outputCmd := exec.Command("terraform", "output", "--json")
	outputCmd.Dir = dir
	outputJson, err := outputCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("terraform output returned an error: %w", err)
	}
	var outputs map[string]terraformOutput
	if err := json.Unmarshal(outputJson, &outputs); err != nil {
		return nil, fmt.Errorf("failed to read outputs data: %w", err)
	}

	return &provisioner.AWSInfrastructure{
		ID:                                     outputs["cluster_id"].Value,
		Region:                                 outputs["region"].Value,
		Zone:                                   outputs["az"].Value,
		ComputeCIDR:                            outputs["compute_cidr"].Value,
		VPCID:                                  outputs["vpc_id"].Value,
		PrivateSubnetID:                        outputs["private_subnet_id"].Value,
		PublicSubnetID:                         outputs["public_subnet_id"].Value,
		WorkerSecurityGroupID:                  outputs["worker_sg_id"].Value,
		WorkerInstanceProfileID:                outputs["worker_instance_profile_id"].Value,
		BaseDomainZoneID:                       outputs["base_domain_zone_id"].Value,
		Subdomain:                              outputs["cluster_domain"].Value,
		SubdomainPrivateZoneID:                 outputs["private_zone_id"].Value,
		SubdomainPublicZoneID:                  outputs["public_zone_id"].Value,
		OIDCIngressRoleArn:                     outputs["region"].Value,
		OIDCImageRegistryRoleArn:               outputs["oidc_registry_role_arn"].Value,
		OIDCCSIDriverRoleArn:                   outputs["oidc_csi_role_arn"].Value,
		OIDCIssuerURL:                          outputs["oidc_issuer_url"].Value,
		OIDCBucketName:                         outputs["oidc_bucket_name"].Value,
		KubeCloudControllerUserAccessKeyID:     outputs["cloud_controller_access_key_id"].Value,
		KubeCloudControllerUserAccessKeySecret: outputs["cloud_controller_access_key_secret"].Value,
		NodePoolManagementUserAccessKeyID:      outputs["node_pool_access_key_id"].Value,
		NodePoolManagementUserAccessKeySecret:  outputs["node_pool_access_key_secret"].Value,
		ServiceAccountSigningKey:               []byte(outputs["service_account_signing_key"].Value),
	}, nil
}
