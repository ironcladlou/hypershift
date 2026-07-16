//go:build e2ev2

package lifecycle

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultAWSRegion = "us-east-1"
)

type AWSPlatformConfig struct {
	region         string
	zones          []string
	roleARN        string
	sharedDir      string
	additionalTags []string
}

func NewAWSPlatformConfig(sharedDir string) *AWSPlatformConfig {
	cfg := &AWSPlatformConfig{
		region:    envOrDefault("HYPERSHIFT_AWS_REGION", defaultAWSRegion),
		roleARN:   os.Getenv("HYPERSHIFT_AWS_ROLE_ARN"),
		sharedDir: sharedDir,
	}

	zonesStr := envOrDefault("HYPERSHIFT_AWS_ZONES", "us-east-1a")
	cfg.zones = strings.Split(zonesStr, ",")

	cfg.additionalTags = []string{
		fmt.Sprintf("expirationDate=%s", time.Now().Add(4*time.Hour).UTC().Format(time.RFC3339)),
	}

	log.Printf("AWS platform config: region=%s, zones=%v, role-arn=%s", cfg.region, cfg.zones, cfg.roleARN)
	return cfg
}

func (a *AWSPlatformConfig) Name() string { return "aws" }

func (a *AWSPlatformConfig) DefaultBaseDomain() string {
	return "origin-ci-int-aws.dev.rhcloud.com"
}

func (a *AWSPlatformConfig) ClusterSpecs(releaseImage, n1Image string) []ClusterSpec {
	return []ClusterSpec{
		{
			Variant:    "public",
			OutputFile: "cluster-name-public",
		},
		{
			Variant:      "upgrade",
			OutputFile:   "cluster-name-upgrade",
			ReleaseImage: n1Image,
		},
	}
}

func (a *AWSPlatformConfig) CreateArgs() []string {
	args := []string{
		"--region=" + a.region,
		"--zones=" + strings.Join(a.zones, ","),
		"--root-volume-size=64",
		"--root-volume-type=gp3",
		"--public-only",
	}
	if a.roleARN != "" {
		args = append(args, "--role-arn="+a.roleARN)
	}
	for _, tag := range a.additionalTags {
		args = append(args, "--additional-tags="+tag)
	}
	return args
}

func (a *AWSPlatformConfig) PreCreate(ctx context.Context, cl crclient.WithWatch, namespace string) error {
	return nil
}

func (a *AWSPlatformConfig) PostCreate(ctx context.Context, cl crclient.WithWatch, namespace string, clusterNames map[string]string) error {
	return nil
}

func (a *AWSPlatformConfig) PostAvailable(ctx context.Context, cl crclient.WithWatch, namespace string, clusterNames map[string]string) error {
	return nil
}

func (a *AWSPlatformConfig) PostVersionRollout(ctx context.Context, cl crclient.WithWatch, namespace string, clusterNames map[string]string) error {
	return nil
}

func (a *AWSPlatformConfig) TestMatrix(releaseImage string) TestMatrix {
	return TestMatrix{
		Parallel: []TestGroup{
			{
				Name:        "public",
				ClusterFile: "cluster-name-public",
				//LabelFilter: "hosted-cluster-aws || nodepool-lifecycle || control-plane-workloads || hosted-cluster-health || hosted-cluster-security || hosted-cluster-compliance || hosted-cluster-metrics || hosted-cluster-image-registry",
				LabelFilter: "hosted-cluster-aws || control-plane-workloads || hosted-cluster-health",
				JUnitFile:   "junit_aws_public.xml",
			},
		},
		Sequential: []SequentialGroup{
			{
				Name: "upgrade-and-chaos",
				Steps: []TestGroup{
					{
						Name:        "upgrade",
						ClusterFile: "cluster-name-upgrade",
						LabelFilter: "control-plane-upgrade",
						JUnitFile:   "junit_lifecycle_upgrade.xml",
						ExtraEnv:    []string{fmt.Sprintf("E2E_LATEST_RELEASE_IMAGE=%s", releaseImage)},
					},
					{
						Name:        "etcd-chaos",
						ClusterFile: "cluster-name-upgrade",
						LabelFilter: "etcd-chaos",
						JUnitFile:   "junit_lifecycle_etcd_chaos.xml",
					},
				},
			},
		},
	}
}

func (a *AWSPlatformConfig) SetupTestEnv(sharedDir string) {
}

func (a *AWSPlatformConfig) DestroyArgs() []string {
	args := []string{
		"--region=" + a.region,
	}
	if a.roleARN != "" {
		args = append(args, "--role-arn="+a.roleARN)
	}
	return args
}
