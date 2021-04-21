package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type TerraformOutput struct {
	Value     string `json:"value"`
	Type      string `json:"type"`
	Sensitive bool   `json:"sensitive"`
}

type TerraformProvisioner struct {
}

func (p *TerraformProvisioner) Provision(ctx context.Context, opts *CreateInfraOptions) (*AWSInfrastructure, error) {
	data, err := ioutil.ReadFile(opts.TerraformOutputsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", opts.TerraformOutputsFile, err)
	}
	var outputs map[string]TerraformOutput
	if err := json.Unmarshal(data, &outputs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", opts.TerraformOutputsFile, err)
	}

	return &AWSInfrastructure{
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
