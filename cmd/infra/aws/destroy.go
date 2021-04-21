package aws

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/openshift/hypershift/cmd/infra/aws/cloudformation"
	"github.com/openshift/hypershift/cmd/infra/aws/provisioner"
	"github.com/openshift/hypershift/cmd/infra/aws/terraform"
)

type DestroyInfraOptions struct {
	Provisioner        string
	AWSCredentialsFile string
	Region             string
	InfraID            string
	TerraformDir       string
}

func NewDestroyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Destroys AWS infrastructure resources for a cluster",
	}

	opts := DestroyInfraOptions{
		Region:      "us-east-1",
		Provisioner: provisioner.CloudFormationProvisionerType,
	}

	cmd.Flags().StringVar(&opts.InfraID, "infra-id", opts.InfraID, "The cluster infrastructure ID to destroy (required)")
	cmd.Flags().StringVar(&opts.AWSCredentialsFile, "aws-creds", opts.AWSCredentialsFile, "Path to an AWS credentials file (required)")
	cmd.Flags().StringVar(&opts.Region, "region", opts.Region, "Region where cluster infra should be created")
	cmd.Flags().StringVar(&opts.Provisioner, "provisioner", opts.Provisioner, "One of: cloudformation, terraform")
	cmd.Flags().StringVar(&opts.TerraformDir, "terraform-dir", opts.TerraformDir, "Path to a directory for the cluster's Terraform state")

	cmd.MarkFlagRequired("infra-id")
	cmd.MarkFlagRequired("aws-creds")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT)
		go func() {
			<-sigs
			cancel()
		}()
		t := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-ctx.Done():
				log.Info("Destroy was cancelled")
				return nil
			case <-t.C:
				if err := opts.DestroyInfra(ctx); err != nil {
					log.Error(err, "failed to destroy infrastructure, will retry")
				} else {
					log.Info("Successfully destroyed AWS infra")
					return nil
				}
			}
		}
	}
	return cmd
}

func (o *DestroyInfraOptions) DestroyInfra(ctx context.Context) error {
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
			AWSCredentialsFile: o.AWSCredentialsFile,
		}
	}

	if err := p.Destroy(ctx, &provisioner.DestroyOptions{
		InfraID: o.InfraID,
		Region:  o.Region,
	}); err != nil {
		return fmt.Errorf("failed to destroy infrastructure: %w", err)
	}
	log.Info("Destroyed infrastructure", "id", o.InfraID, "region", o.Region)

	return nil
}
