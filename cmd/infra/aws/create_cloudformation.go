package aws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
	"k8s.io/apimachinery/pkg/util/wait"

	hypercf "github.com/openshift/hypershift/cmd/infra/aws/cloudformation"
)

type StackOutput struct {
	StackID                                string `json:"stackID"`
	Region                                 string `json:"region"`
	Zone                                   string `json:"zone"`
	InfraID                                string `json:"infraID"`
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
	KubeCloudControllerUserAccessKeyID     string `json:"kubeCloudControllerUserAccessKeyID"`
	KubeCloudControllerUserAccessKeySecret string `json:"kubeCloudControllerUserAccessKeySecret"`
	NodePoolManagementUserAccessKeyID      string `json:"nodePoolManagementUserAccessKeyID"`
	NodePoolManagementUserAccessKeySecret  string `json:"nodePoolManagementUserAccessKeySecret"`
}

type CloudFormationProvisioner struct {
}

func (p *CloudFormationProvisioner) Provision(ctx context.Context, opts *CreateInfraOptions) (*AWSInfrastructure, error) {
	awsSession := newSession()
	awsConfig := newConfig(opts.AWSCredentialsFile, opts.Region)
	r53Config := newConfig(opts.AWSCredentialsFile, "us-east-1")

	cf := cloudformation.New(awsSession, awsConfig)
	r53 := route53.New(awsSession, r53Config)

	// Create or get an existing stack
	stack, err := p.getOrCreateStack(ctx, cf, r53, opts)
	if err != nil {
		return nil, err
	}

	// Configure DNS for the subdomain
	err = p.configureSubdomain(ctx, cf, r53, stack.StackID)

	// Generate PKI
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	serviceAccountSigningKey := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privKey),
	})

	return &AWSInfrastructure{
		Region:                                 stack.Region,
		Zone:                                   stack.Zone,
		ID:                                     stack.InfraID,
		ComputeCIDR:                            stack.ComputeCIDR,
		VPCID:                                  stack.VPCID,
		PrivateSubnetID:                        stack.PrivateSubnetID,
		PublicSubnetID:                         stack.PublicSubnetID,
		WorkerSecurityGroupID:                  stack.WorkerSecurityGroupID,
		WorkerInstanceProfileID:                stack.WorkerInstanceProfileID,
		BaseDomainZoneID:                       stack.BaseDomainZoneID,
		Subdomain:                              stack.Subdomain,
		SubdomainPrivateZoneID:                 stack.SubdomainPrivateZoneID,
		SubdomainPublicZoneID:                  stack.SubdomainPublicZoneID,
		OIDCIngressRoleArn:                     stack.OIDCIngressRoleArn,
		OIDCImageRegistryRoleArn:               stack.OIDCImageRegistryRoleArn,
		OIDCCSIDriverRoleArn:                   stack.OIDCCSIDriverRoleArn,
		OIDCIssuerURL:                          stack.OIDCIssuerURL,
		OIDCBucketName:                         stack.OIDCBucketName,
		ServiceAccountSigningKey:               serviceAccountSigningKey,
		KubeCloudControllerUserAccessKeyID:     stack.KubeCloudControllerUserAccessKeyID,
		KubeCloudControllerUserAccessKeySecret: stack.KubeCloudControllerUserAccessKeySecret,
		NodePoolManagementUserAccessKeyID:      stack.NodePoolManagementUserAccessKeyID,
		NodePoolManagementUserAccessKeySecret:  stack.NodePoolManagementUserAccessKeySecret,
	}, nil
}

func (p *CloudFormationProvisioner) getOrCreateStack(ctx context.Context, cf *cloudformation.CloudFormation, r53 route53iface.Route53API, o *CreateInfraOptions) (*StackOutput, error) {
	log.Info("Creating infrastructure", "id", o.InfraID, "baseDomain", o.BaseDomain, "subdomain", o.Subdomain)

	publicZoneID, err := lookupZone(r53, o.BaseDomain, false)
	if err != nil {
		return nil, fmt.Errorf("couldn't find a public zone for base domain %s: %w", o.BaseDomain, err)
	}
	log.Info("Discovered base domain zone", "baseDomain", o.BaseDomain, "id", publicZoneID)

	stackName := o.InfraID

	var stack *cloudformation.Stack
	if existing, err := getStack(cf, stackName); err == nil {
		stack = existing
		log.Info("Found existing stack", "id", *stack.StackId)
	} else {
		newStack, err := p.createStack(ctx, cf, publicZoneID, o)
		if err != nil {
			return nil, fmt.Errorf("failed to create stack: %w", err)
		}
		stack = newStack
	}

	output := &StackOutput{
		InfraID:                                o.InfraID,
		StackID:                                *stack.StackId,
		Region:                                 getStackOutput(stack, "Region"),
		Zone:                                   getStackOutput(stack, "Zone"),
		ComputeCIDR:                            getStackOutput(stack, "ComputeCIDR"),
		VPCID:                                  getStackOutput(stack, "VPCId"),
		PrivateSubnetID:                        getStackOutput(stack, "PrivateSubnetId"),
		PublicSubnetID:                         getStackOutput(stack, "PublicSubnetId"),
		WorkerSecurityGroupID:                  getStackOutput(stack, "WorkerSecurityGroupId"),
		WorkerInstanceProfileID:                getStackOutput(stack, "WorkerInstanceProfileId"),
		BaseDomainZoneID:                       getStackOutput(stack, "BaseDomainHostedZoneId"),
		Subdomain:                              getStackOutput(stack, "Subdomain"),
		SubdomainPrivateZoneID:                 getStackOutput(stack, "SubdomainPrivateZoneId"),
		SubdomainPublicZoneID:                  getStackOutput(stack, "SubdomainPublicZoneId"),
		OIDCIngressRoleArn:                     getStackOutput(stack, "OIDCIngressRoleArn"),
		OIDCImageRegistryRoleArn:               getStackOutput(stack, "OIDCImageRegistryRoleArn"),
		OIDCCSIDriverRoleArn:                   getStackOutput(stack, "OIDCCSIDriverRoleArn"),
		OIDCIssuerURL:                          getStackOutput(stack, "OIDCIssuerURL"),
		OIDCBucketName:                         getStackOutput(stack, "OIDCBucketName"),
		KubeCloudControllerUserAccessKeyID:     getStackOutput(stack, "KubeCloudControllerUserAccessKeyId"),
		KubeCloudControllerUserAccessKeySecret: getStackOutput(stack, "KubeCloudControllerUserAccessKeySecret"),
		NodePoolManagementUserAccessKeyID:      getStackOutput(stack, "NodePoolManagementUserAccessKeyId"),
		NodePoolManagementUserAccessKeySecret:  getStackOutput(stack, "NodePoolManagementUserAccessKeySecret"),
	}

	return output, nil
}

func (p *CloudFormationProvisioner) createStack(ctx context.Context, cf *cloudformation.CloudFormation, baseDomainZoneID string, o *CreateInfraOptions) (*cloudformation.Stack, error) {
	createStackInput := &cloudformation.CreateStackInput{
		Capabilities: []*string{aws.String(cloudformation.CapabilityCapabilityNamedIam)},
		TemplateBody: &hypercf.ClusterTemplate,
		StackName:    aws.String(o.InfraID),
		Tags: []*cloudformation.Tag{
			{
				Key:   aws.String("hypershift.openshift.io/infra"),
				Value: aws.String("owned"),
			},
		},
		Parameters: []*cloudformation.Parameter{
			{
				ParameterKey:   aws.String("InfrastructureName"),
				ParameterValue: aws.String(o.InfraID),
			},
			{
				ParameterKey:   aws.String("BaseDomainHostedZoneId"),
				ParameterValue: aws.String(baseDomainZoneID),
			},
			{
				ParameterKey:   aws.String("Subdomain"),
				ParameterValue: aws.String(o.Subdomain),
			},
		},
	}

	if o.DeleteOnFailure {
		createStackInput.OnFailure = aws.String(cloudformation.OnFailureDelete)
	} else {
		createStackInput.OnFailure = aws.String(cloudformation.OnFailureRollback)
	}

	createStackOutput, err := cf.CreateStack(createStackInput)
	if err != nil {
		return nil, err
	}

	log.Info("Waiting for infrastructure to be created", "id", o.InfraID, "stackID", *createStackOutput.StackId)
	var stack *cloudformation.Stack
	err = wait.PollUntil(5*time.Second, func() (bool, error) {
		latest, err := getStack(cf, *createStackOutput.StackId)
		if err != nil {
			log.Error(err, "failed to get stack", "id", *createStackOutput.StackId)
			return false, nil
		}
		stack = latest
		switch *stack.StackStatus {
		case cloudformation.StackStatusCreateComplete:
			return true, nil
		case cloudformation.StackStatusCreateInProgress:
			return false, nil
		case cloudformation.StackStatusCreateFailed:
			return false, fmt.Errorf("stack creation failed")
		case cloudformation.StackStatusRollbackInProgress,
			cloudformation.StackStatusRollbackComplete,
			cloudformation.StackStatusRollbackFailed:
			return false, fmt.Errorf("stack creation failed and was rolled back")
		default:
			return false, fmt.Errorf("unexpected stack creation status: %s", *stack.StackStatus)
		}
	}, ctx.Done())
	if err != nil {
		// If anything went wrong and the stack exists, save te user a trip to AWS
		// by dumping events which usually describe the specific failure.
		if stack != nil {
			if out, err := cf.DescribeStackEvents(&cloudformation.DescribeStackEventsInput{
				StackName: stack.StackName,
			}); err != nil {
				log.Error(err, "failed to describe stack events")
			} else {
				events := sortableStackEvents(out.StackEvents)
				sort.Sort(events)
				for _, event := range events {
					log.Info("found stack event",
						"Timestamp", aws.TimeValue(event.Timestamp),
						"ResourceType", aws.StringValue(event.ResourceType),
						"LogicalResourceId", aws.StringValue(event.LogicalResourceId),
						"ResourceStatus", aws.StringValue(event.ResourceStatus),
						"ResourceStatusReason", aws.StringValue(event.ResourceStatusReason))
				}
			}
		}

		return nil, err
	}
	return stack, nil
}

func (p *CloudFormationProvisioner) configureSubdomain(ctx context.Context, cf *cloudformation.CloudFormation, r53 route53iface.Route53API, stackID string) error {
	var nameservers, zoneID, subdomain string
	err := wait.PollUntil(5*time.Second, func() (bool, error) {
		stack, err := getStack(cf, stackID)
		if err != nil {
			log.Error(err, "failed to get stack", "id", stackID)
			return false, nil
		}
		nameservers = getStackOutput(stack, "SubdomainPublicZoneNameServers")
		subdomain = getStackOutput(stack, "Subdomain")
		zoneID = getStackOutput(stack, "BaseDomainHostedZoneId")
		if len(nameservers) > 0 {
			return true, nil
		}
		return false, nil
	}, ctx.Done())
	if err != nil {
		return fmt.Errorf("subdomain nameservers were not published: %w", err)
	}

	records := []*route53.ResourceRecord{}
	for _, ns := range strings.Split(nameservers, ",") {
		records = append(records, &route53.ResourceRecord{Value: aws.String(ns)})
	}

	params := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action: aws.String("UPSERT"),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name:            aws.String(subdomain),
						Type:            aws.String("NS"),
						ResourceRecords: records,
						TTL:             aws.Int64(60),
					},
				},
			},
		},
		HostedZoneId: aws.String(zoneID),
	}

	_, err = r53.ChangeResourceRecordSets(params)
	if err != nil {
		return fmt.Errorf("failed to create NS record for subdomain: %w", err)
	}
	log.Info("Updated subdomain NS record in base zone", "zoneID", zoneID, "subdomain", subdomain, "nameservers", nameservers)

	return nil
}
