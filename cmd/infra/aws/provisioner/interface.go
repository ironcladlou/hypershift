package provisioner

import "context"

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

type ProvisionOptions struct {
	InfraID    string
	Region     string
	BaseDomain string
	Subdomain  string
}

type DestroyOptions struct {
	InfraID string
	Region  string
}

const (
	CloudFormationProvisionerType = "cloudformation"
	TerraformProvisionerType      = "terraform"
)

type Provisioner interface {
	Provision(context.Context, *ProvisionOptions) (*AWSInfrastructure, error)
	Destroy(context.Context, *DestroyOptions) error
}
