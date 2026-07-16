//go:build e2ev2

// e2e-env generates a local development environment for running the
// v2 e2e lifecycle tests. It creates a simulated prow job directory with
// a mise.toml that provides the environment variables and tasks the
// lifecycle binaries expect.
//
// Usage:
//
//	e2e-env init --platform aws --release-image <image> [options]
//	e2e-env list
//	e2e-env clean <run-id>
package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/openshift/hypershift/test/e2e/v2/lifecycle"
)

//go:embed mise.toml.tmpl
var miseTemplate string

//go:embed cluster.mise.toml.tmpl
var clusterMiseTemplate string

//go:embed scripts
var scriptsFS embed.FS

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		log.Fatalf("Failed to find repo root: %v", err)
	}
	localDir := filepath.Join(repoRoot, ".e2e")

	switch os.Args[1] {
	case "init":
		cmdInit(localDir, repoRoot, os.Args[2:])
	case "list":
		cmdList(localDir)
	case "clean":
		if len(os.Args) < 3 {
			log.Fatal("Usage: e2e-env clean <run-id>")
		}
		cmdClean(localDir, os.Args[2])
	case "-h", "--help", "help":
		printUsage()
	default:
		log.Fatalf("Unknown command: %s\nRun 'e2e-env --help' for usage.", os.Args[1])
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `e2e-env sets up local development environments for running v2 e2e
lifecycle tests. It generates a run directory under .e2e/ containing
a mise.toml that provides environment variables and tasks matching the
interface expected by the lifecycle test binaries (create-guests, run-tests,
destroy-guests, dump-guests).

Each run directory is self-contained and isolated by a unique prow job ID
that determines cluster names deterministically. Re-initializing an existing
run (--run-id) preserves the prow job ID so cluster names remain stable.

After creating clusters with 'mise run create', use 'mise run sync' to
extract per-cluster kubeconfigs into clusters/<variant>/ subdirectories.
Navigating into a cluster directory scopes oc/kubectl to that guest cluster.

Usage:
  e2e-env <command> [options]

Commands:
  init      Create or re-initialize a run environment
  list      List existing runs
  clean     Remove a run directory

Examples:
  # Create a new AWS run environment
  e2e-env init --platform aws \
    --release-image quay.io/openshift-release-dev/ocp-release:4.22.3-multi \
    --base-domain example.devcluster.openshift.com \
    --namespace my-ns \
    --kubeconfig ~/.kube/config

  # Re-initialize an existing run (preserves prow job ID and cluster names)
  e2e-env init --run-id 0715-1325-3c5f --platform aws \
    --release-image quay.io/openshift-release-dev/ocp-release:4.22.3-multi

  # List runs and clean up
  e2e-env list
  e2e-env clean 0715-1325-3c5f
`)
}

type initConfig struct {
	Platform     string `json:"platform"`
	ReleaseImage string `json:"releaseImage"`
	BaseDomain   string `json:"baseDomain,omitempty"`
	Namespace    string `json:"namespace"`
	NodeCount    int    `json:"nodeCount"`
	Kubeconfig   string `json:"kubeconfig,omitempty"`
	PullSecret   string `json:"pullSecret,omitempty"`
	N1Image      string `json:"n1Image,omitempty"`
	Variants     string `json:"variants,omitempty"`
	RunID        string `json:"runID"`
	ProwJobID    string `json:"prowJobID"`

	// AWS-specific
	Region  string `json:"region,omitempty"`
	Zones   string `json:"zones,omitempty"`
	RoleARN string `json:"roleARN,omitempty"`
}

type envVar struct {
	Key   string
	Value string
}

type clusterInfo struct {
	Variant   string
	EnvSuffix string
	Name      string
}

type clusterTemplateData struct {
	ClusterName string
	Namespace   string
	BaseDomain  string
	BinDir      string
}

type variantTestInfo struct {
	Variant     string
	ClusterName string
	ExtraEnv    []envVar
}

type templateData struct {
	ProwJobID    string
	ReleaseImage string
	Platform     string
	BaseDomain   string
	Namespace    string
	NodeCount    int
	BinDir       string
	RepoRoot     string
	PlatformEnv  []envVar
	Variants     string
	N1Image      string
	Kubeconfig   string
	PullSecret   string
	Clusters     []clusterInfo
	TestVariants []variantTestInfo
}

func cmdInit(localDir, repoRoot string, args []string) {
	flagSet := flag.NewFlagSet("init", flag.ExitOnError)
	flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, `Create or re-initialize a local e2e run environment.

Generates a run directory with a mise.toml providing environment variables
and tasks for the v2 lifecycle binaries. When --run-id references an existing
run, the prow job ID is preserved so cluster names remain stable.

Available mise tasks after init:
  build              Build all v2 e2e binaries
  create             Create hosted clusters
  sync               Extract per-cluster kubeconfigs into clusters/<variant>/
  test               Run tests (orchestrated by run-tests binary)
  test:<variant>     Run tests against a specific cluster variant
  dump               Dump all clusters
  dump:<variant>     Dump a specific cluster
  destroy            Tear down clusters
  all                Build + create + test + destroy

Test filtering:
  Each test:<variant> task accepts a --filter flag to set a Ginkgo label
  filter, and passes extra arguments through to the test binary:

    mise run test:public --filter nodepool-lifecycle
    mise run test:public --filter 'nodepool-lifecycle || hosted-cluster-health'
    mise run test:public --ginkgo.dry-run   # extra args passed through
    mise run test:public                    # runs all tests (no filter)

Usage:
  e2e-env init [flags]

Flags:
`)
		flagSet.PrintDefaults()
	}
	cfg := initConfig{}
	flagSet.StringVar(&cfg.Platform, "platform", "", "Platform (aws, azure) [required]")
	flagSet.StringVar(&cfg.ReleaseImage, "release-image", "", "OCP release image [required]")
	flagSet.StringVar(&cfg.BaseDomain, "base-domain", "", "Ingress base domain [default: platform default]")
	flagSet.StringVar(&cfg.Namespace, "namespace", "clusters", "HostedCluster namespace")
	flagSet.IntVar(&cfg.NodeCount, "node-count", 3, "NodePool replicas")
	flagSet.StringVar(&cfg.Kubeconfig, "kubeconfig", "", "Management cluster kubeconfig path")
	flagSet.StringVar(&cfg.PullSecret, "pull-secret", "", "Pull secret file path")
	flagSet.StringVar(&cfg.N1Image, "n1-image", "", "N-1 release image for upgrade variant")
	flagSet.StringVar(&cfg.Variants, "variants", "", "Comma-separated cluster variants to create (default: all)")
	flagSet.StringVar(&cfg.RunID, "run-id", "", "Custom run ID [default: generated]")
	flagSet.StringVar(&cfg.ProwJobID, "prow-job-id", "", "Prow job ID for deterministic cluster naming [default: generated]")
	flagSet.StringVar(&cfg.Region, "region", "us-east-1", "AWS region")
	flagSet.StringVar(&cfg.Zones, "zones", "us-east-1a", "AWS availability zones (comma-separated)")
	flagSet.StringVar(&cfg.RoleARN, "role-arn", "", "AWS role ARN")
	flagSet.Parse(args)

	if cfg.RunID == "" {
		cfg.RunID = generateRunID()
	}

	runDir := filepath.Join(localDir, cfg.RunID)

	// If re-initializing an existing run, load saved config and apply
	// any flags the user passed on top of it.
	configPath := filepath.Join(runDir, "config.json")
	if saved, err := loadConfig(configPath); err == nil {
		log.Printf("Re-initializing existing run %s", cfg.RunID)
		cfg = mergeConfig(saved, cfg, flagSet)
	}

	if cfg.Platform == "" {
		log.Fatal("--platform is required")
	}
	if cfg.ReleaseImage == "" {
		log.Fatal("--release-image is required")
	}

	if cfg.N1Image == "" {
		cfg.N1Image = cfg.ReleaseImage
	}

	// Set platform env vars so NewPlatformConfig reads them.
	switch cfg.Platform {
	case "aws":
		os.Setenv("HYPERSHIFT_AWS_REGION", cfg.Region)
		os.Setenv("HYPERSHIFT_AWS_ZONES", cfg.Zones)
		if cfg.RoleARN != "" {
			os.Setenv("HYPERSHIFT_AWS_ROLE_ARN", cfg.RoleARN)
		}
	case "azure":
		// Azure reads its own env vars; nothing to inject for local dev.
	default:
		log.Fatalf("Unsupported platform: %s", cfg.Platform)
	}

	sharedDir := filepath.Join(runDir, "shared")
	if err := os.MkdirAll(sharedDir, 0755); err != nil {
		log.Fatalf("Failed to create shared dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0755); err != nil {
		log.Fatalf("Failed to create artifacts dir: %v", err)
	}

	if cfg.ProwJobID == "" {
		cfg.ProwJobID = generateShortID()
	}
	prowJobID := cfg.ProwJobID

	platform, err := lifecycle.NewPlatformConfig(cfg.Platform, sharedDir)
	if err != nil {
		log.Fatalf("Failed to initialize platform config: %v", err)
	}

	if cfg.BaseDomain == "" {
		cfg.BaseDomain = platform.DefaultBaseDomain()
	}

	specs := lifecycle.FilterClusterSpecs(platform.ClusterSpecs(cfg.ReleaseImage, cfg.N1Image), cfg.Variants)

	clusterNames := make(map[string]string)
	for _, spec := range specs {
		clusterNames[spec.OutputFile] = lifecycle.DeriveClusterName(prowJobID, spec.Variant)
	}

	matrix := lifecycle.FilterTestMatrix(platform.TestMatrix(cfg.ReleaseImage), specs)

	if cfg.Kubeconfig != "" {
		abs, err := filepath.Abs(cfg.Kubeconfig)
		if err != nil {
			log.Fatalf("Failed to resolve kubeconfig path: %v", err)
		}
		cfg.Kubeconfig = abs
	}

	// Write embedded scripts to run directory.
	if err := writeEmbeddedScripts(runDir); err != nil {
		log.Fatalf("Failed to write scripts: %v", err)
	}

	// Build template data and render mise.toml.
	data := buildTemplateData(cfg, repoRoot, prowJobID, specs, clusterNames, matrix)

	// Pre-render per-cluster mise.toml files.
	if err := writeClusterMiseFiles(runDir, cfg, data); err != nil {
		log.Fatalf("Failed to write per-cluster mise.toml files: %v", err)
	}

	tmpl, err := template.New("mise.toml").Parse(miseTemplate)
	if err != nil {
		log.Fatalf("Failed to parse mise.toml template: %v", err)
	}

	misePath := filepath.Join(runDir, "mise.toml")
	f, err := os.Create(misePath)
	if err != nil {
		log.Fatalf("Failed to create mise.toml: %v", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		log.Fatalf("Failed to execute mise.toml template: %v", err)
	}

	// Save config for re-init.
	if err := saveConfig(configPath, cfg); err != nil {
		log.Fatalf("Failed to save config: %v", err)
	}

	// Auto-trust so mise doesn't prompt.
	cmd := exec.Command("mise", "trust")
	cmd.Dir = runDir
	cmd.Run()

	// Print summary.
	fmt.Printf("Created run: %s\n", cfg.RunID)
	fmt.Printf("  Directory: %s\n", runDir)
	fmt.Printf("  Prow Job ID: %s\n", prowJobID)
	fmt.Printf("  Platform: %s\n", cfg.Platform)
	fmt.Printf("  Clusters:\n")
	for _, spec := range specs {
		fmt.Printf("    %s: %s\n", spec.Variant, clusterNames[spec.OutputFile])
	}
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Printf("  cd %s\n", runDir)
	fmt.Println("  mise run build     # build binaries")
	fmt.Println("  mise run create    # create clusters")
	fmt.Println("  mise run sync      # sync per-cluster kubeconfigs and environments")
	fmt.Println("  mise run test      # run tests (orchestrated)")
	fmt.Println("  mise run dump      # dump all clusters")
	fmt.Println("  mise run destroy   # tear down clusters")
	fmt.Println("  mise run all       # build + create + test + destroy")
	fmt.Println()
	fmt.Println("Per-cluster tasks:")
	for _, spec := range specs {
		fmt.Printf("  mise run dump:%s\n", spec.Variant)
	}
	printVariantTasks(specs, clusterNames)
	fmt.Println()
	fmt.Println("Test filtering:")
	fmt.Println("  mise run test:<variant> --filter '<label-expression>'")
	fmt.Println("  mise run test:<variant> --help")
	fmt.Println()
	fmt.Println("Cluster directories (after sync):")
	for _, spec := range specs {
		fmt.Printf("  cd clusters/%s    # oc/kubectl with guest kubeconfig\n", spec.Variant)
	}
	fmt.Println()
	fmt.Println("Cleanup:")
	fmt.Printf("  bin/e2e-env clean %s\n", cfg.RunID)
}

func buildTemplateData(cfg initConfig, repoRoot, prowJobID string, specs []lifecycle.ClusterSpec, clusterNames map[string]string, matrix lifecycle.TestMatrix) templateData {
	binDir := filepath.Join(repoRoot, "bin")

	data := templateData{
		ProwJobID:    prowJobID,
		ReleaseImage: cfg.ReleaseImage,
		Platform:     cfg.Platform,
		BaseDomain:   cfg.BaseDomain,
		Namespace:    cfg.Namespace,
		NodeCount:    cfg.NodeCount,
		BinDir:       binDir,
		RepoRoot:     repoRoot,
		Variants:     cfg.Variants,
		Kubeconfig:   cfg.Kubeconfig,
		PullSecret:   cfg.PullSecret,
	}

	if cfg.N1Image != cfg.ReleaseImage {
		data.N1Image = cfg.N1Image
	}

	switch cfg.Platform {
	case "aws":
		data.PlatformEnv = append(data.PlatformEnv, envVar{"HYPERSHIFT_AWS_REGION", cfg.Region})
		data.PlatformEnv = append(data.PlatformEnv, envVar{"HYPERSHIFT_AWS_ZONES", cfg.Zones})
		if cfg.RoleARN != "" {
			data.PlatformEnv = append(data.PlatformEnv, envVar{"HYPERSHIFT_AWS_ROLE_ARN", cfg.RoleARN})
		}
	}

	for _, spec := range specs {
		name := clusterNames[spec.OutputFile]
		variantUpper := strings.ToUpper(strings.ReplaceAll(spec.Variant, "-", "_"))
		data.Clusters = append(data.Clusters, clusterInfo{
			Variant:   spec.Variant,
			EnvSuffix: variantUpper,
			Name:      name,
		})
	}

	// Build variant test info by collecting extra env vars from all
	// test groups targeting each variant's cluster.
	clusterFileToVariant := make(map[string]string)
	for _, spec := range specs {
		clusterFileToVariant[spec.OutputFile] = spec.Variant
	}
	variantEnvs := make(map[string][]envVar)
	collectEnvs := func(groups []lifecycle.TestGroup) {
		for _, g := range groups {
			variant := clusterFileToVariant[g.ClusterFile]
			for _, e := range g.ExtraEnv {
				k, v, ok := strings.Cut(e, "=")
				if ok {
					variantEnvs[variant] = append(variantEnvs[variant], envVar{k, v})
				}
			}
		}
	}
	collectEnvs(matrix.Parallel)
	for _, sg := range matrix.Sequential {
		collectEnvs(sg.Steps)
	}
	for _, spec := range specs {
		name := clusterNames[spec.OutputFile]
		if name == "" {
			continue
		}
		data.TestVariants = append(data.TestVariants, variantTestInfo{
			Variant:     spec.Variant,
			ClusterName: name,
			ExtraEnv:    variantEnvs[spec.Variant],
		})
	}

	return data
}

func writeEmbeddedScripts(runDir string) error {
	scriptsDir := filepath.Join(runDir, "scripts")
	if err := os.MkdirAll(scriptsDir, 0755); err != nil {
		return fmt.Errorf("creating scripts dir: %w", err)
	}

	return fs.WalkDir(scriptsFS, "scripts", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		content, err := scriptsFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading embedded %s: %w", path, err)
		}
		dest := filepath.Join(runDir, path)
		if err := os.WriteFile(dest, content, 0755); err != nil {
			return fmt.Errorf("writing %s: %w", dest, err)
		}
		return nil
	})
}

func writeClusterMiseFiles(runDir string, cfg initConfig, data templateData) error {
	tmpl, err := template.New("cluster.mise.toml").Parse(clusterMiseTemplate)
	if err != nil {
		return fmt.Errorf("parsing cluster template: %w", err)
	}

	for _, cluster := range data.Clusters {
		clusterData := clusterTemplateData{
			ClusterName: cluster.Name,
			Namespace:   cfg.Namespace,
			BaseDomain:  cfg.BaseDomain,
			BinDir:      data.BinDir,
		}

		clusterDir := filepath.Join(runDir, "clusters", cluster.Variant)
		if err := os.MkdirAll(clusterDir, 0755); err != nil {
			return fmt.Errorf("creating %s: %w", clusterDir, err)
		}
		path := filepath.Join(clusterDir, "mise.toml")
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("creating %s: %w", path, err)
		}
		if err := tmpl.Execute(f, clusterData); err != nil {
			f.Close()
			return fmt.Errorf("rendering %s: %w", path, err)
		}
		f.Close()

		cmd := exec.Command("mise", "trust")
		cmd.Dir = clusterDir
		cmd.Run()
	}
	return nil
}

func printVariantTasks(specs []lifecycle.ClusterSpec, clusterNames map[string]string) {
	for _, spec := range specs {
		name := clusterNames[spec.OutputFile]
		if name == "" {
			continue
		}
		fmt.Printf("  mise run test:%s   # → %s\n", spec.Variant, name)
	}
}

func cmdList(localDir string) {
	entries, err := os.ReadDir(localDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No runs found.")
			return
		}
		log.Fatalf("Failed to read %s: %v", localDir, err)
	}

	if len(entries) == 0 {
		fmt.Println("No runs found.")
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id := entry.Name()
		runDir := filepath.Join(localDir, id)
		misePath := filepath.Join(runDir, "mise.toml")

		data, err := os.ReadFile(misePath)
		if err != nil {
			continue
		}
		content := string(data)

		platform := extractTomlValue(content, "HYPERSHIFT_PLATFORM")
		prowID := extractTomlValue(content, "PROW_JOB_ID")

		var clusters []string
		sharedDir := filepath.Join(runDir, "shared")
		sharedEntries, _ := os.ReadDir(sharedDir)
		for _, f := range sharedEntries {
			if strings.HasPrefix(f.Name(), "cluster-name-") {
				nameData, err := os.ReadFile(filepath.Join(sharedDir, f.Name()))
				if err == nil {
					clusters = append(clusters, fmt.Sprintf("%s=%s", f.Name(), strings.TrimSpace(string(nameData))))
				}
			}
		}

		clusterStr := ""
		if len(clusters) > 0 {
			clusterStr = " " + strings.Join(clusters, " ")
		}
		fmt.Printf("%-30s  platform=%-6s  prow=%s%s\n", id, platform, prowID, clusterStr)
	}
}

func cmdClean(localDir, runID string) {
	runDir := filepath.Join(localDir, runID)
	if _, err := os.Stat(runDir); os.IsNotExist(err) {
		log.Fatalf("Run not found: %s", runID)
	}
	if err := os.RemoveAll(runDir); err != nil {
		log.Fatalf("Failed to remove %s: %v", runDir, err)
	}
	fmt.Printf("Removed %s\n", runID)
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find repo root (no go.mod found)")
		}
		dir = parent
	}
}

func generateRunID() string {
	b := make([]byte, 2)
	rand.Read(b)
	return time.Now().Format("0102-1504") + "-" + hex.EncodeToString(b)
}

func generateShortID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func saveConfig(path string, cfg initConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func loadConfig(path string) (initConfig, error) {
	var cfg initConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	return cfg, json.Unmarshal(data, &cfg)
}

// mergeConfig uses the saved config as a base and overlays only the
// flags the user explicitly set on this invocation.
func mergeConfig(saved, cli initConfig, fs *flag.FlagSet) initConfig {
	result := saved
	result.RunID = cli.RunID
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "platform":
			result.Platform = cli.Platform
		case "release-image":
			result.ReleaseImage = cli.ReleaseImage
		case "base-domain":
			result.BaseDomain = cli.BaseDomain
		case "namespace":
			result.Namespace = cli.Namespace
		case "node-count":
			result.NodeCount = cli.NodeCount
		case "kubeconfig":
			result.Kubeconfig = cli.Kubeconfig
		case "pull-secret":
			result.PullSecret = cli.PullSecret
		case "n1-image":
			result.N1Image = cli.N1Image
		case "variants":
			result.Variants = cli.Variants
		case "prow-job-id":
			result.ProwJobID = cli.ProwJobID
		case "region":
			result.Region = cli.Region
		case "zones":
			result.Zones = cli.Zones
		case "role-arn":
			result.RoleARN = cli.RoleARN
		}
	})
	return result
}

func extractTomlValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+" =") || strings.HasPrefix(line, key+"=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, "\"")
				return val
			}
		}
	}
	return ""
}
