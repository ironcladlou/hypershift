package terraform

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func NewTerraformCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "terraform",
		Short: "Terraform provisioning commands",
	}

	cmd.AddCommand(newInfraJSONCommand())

	return cmd
}

func newInfraJSONCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "infra-json",
		Short: "Renders the cluster's state as infrastructure JSON",
	}

	var dir string

	cmd.Flags().StringVar(&dir, "dir", dir, "Path to a directory for the cluster's Terraform state")

	cmd.MarkFlagRequired("dir")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		infra, err := getInfrastructure(dir)
		if err != nil {
			return err
		}
		data, err := json.Marshal(infra)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	return cmd
}
