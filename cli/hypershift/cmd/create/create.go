package create

import (
	"github.com/spf13/cobra"

	"github.com/openshift/hypershift/cli/hypershift/cmd/cluster"
	"github.com/openshift/hypershift/cli/hypershift/cmd/infra"
	"github.com/openshift/hypershift/cli/hypershift/cmd/kubeconfig"
	"github.com/openshift/hypershift/cli/hypershift/cmd/nodepool"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "create",
		Short:        "Commands for creating HyperShift resources",
		SilenceUsage: true,
	}

	cmd.AddCommand(cluster.NewCreateCommand())
	cmd.AddCommand(infra.NewCreateCommand())
	cmd.AddCommand(infra.NewCreateIAMCommand())
	cmd.AddCommand(kubeconfig.NewCreateCommand())
	cmd.AddCommand(nodepool.NewCreateCommand())

	return cmd
}
