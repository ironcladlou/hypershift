// +build e2e

package e2e

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/bombsimon/logrusr"
	"github.com/go-logr/logr"
	"github.com/openshift/hypershift/test/e2e/cliworkflow"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/errors"

	"github.com/openshift/hypershift/version"
)

var log = logrusr.NewLogger(logrus.New())

type options struct {
	AWSCredentialsFile   string
	Region               string
	PullSecretFile       string
	LatestReleaseImage   string
	PreviousReleaseImage string
	IsRunningInCI        bool
	UpgradeTestsEnabled  bool
	ArtifactDir          string
	BaseDomain           string
}

var opts = &options{}

func init() {
	flag.StringVar(&opts.AWSCredentialsFile, "e2e.aws-credentials-file", "", "path to AWS credentials")
	flag.StringVar(&opts.Region, "e2e.aws-region", "us-east-1", "AWS region for clusters")
	flag.StringVar(&opts.PullSecretFile, "e2e.pull-secret-file", "", "path to pull secret")
	flag.StringVar(&opts.LatestReleaseImage, "e2e.latest-release-image", "", "The latest OCP release image for use by tests")
	flag.StringVar(&opts.PreviousReleaseImage, "e2e.previous-release-image", "", "The previous OCP release image relative to the latest")
	flag.StringVar(&opts.ArtifactDir, "e2e.artifact-dir", "", "The directory where cluster resources and logs should be dumped. If empty, nothing is dumped")
	flag.StringVar(&opts.BaseDomain, "e2e.base-domain", "", "The ingress base domain for the cluster")
}

func (o *options) SetDefaults() error {
	if len(o.LatestReleaseImage) == 0 {
		defaultVersion, err := version.LookupDefaultOCPVersion()
		if err != nil {
			return fmt.Errorf("couldn't look up default OCP version: %w", err)
		}
		o.LatestReleaseImage = defaultVersion.PullSpec
	}
	// TODO: This is actually basically a required field right now. Maybe the input
	// to tests should be a small API spec that describes the tests and their
	// inputs to avoid having to make every test input required. Or extract
	// e2e test suites into subcommands with their own distinct flags to make
	// selectively running them easier?
	if len(o.PreviousReleaseImage) == 0 {
		o.PreviousReleaseImage = o.LatestReleaseImage
	}

	o.IsRunningInCI = os.Getenv("OPENSHIFT_CI") == "true"

	if o.IsRunningInCI {
		if len(o.ArtifactDir) == 0 {
			o.ArtifactDir = os.Getenv("ARTIFACT_DIR")
		}
		if len(o.BaseDomain) == 0 {
			// TODO: make this an envvar with change to openshift/release, then change here
			o.BaseDomain = "origin-ci-int-aws.dev.rhcloud.com"
		}
	}

	return nil
}

func (o *options) Validate() error {
	var errs []error

	if len(o.LatestReleaseImage) == 0 {
		errs = append(errs, fmt.Errorf("latest release image is required"))
	}

	if len(o.BaseDomain) == 0 {
		errs = append(errs, fmt.Errorf("base domain is required"))
	}

	return errors.NewAggregate(errs)
}

// rootContext should be used as the parent context for any test code, and will
// be cancelled if a SIGINT or SIGTERM is received.
var rootContext context.Context

func TestMain(m *testing.M) {
	// Bind flags to the test options
	flag.Parse()

	// Set defaults for the test options
	if err := opts.SetDefaults(); err != nil {
		log.Error(err, "failed to set up global test options")
		os.Exit(1)
	}

	// Validate the test options
	if err := opts.Validate(); err != nil {
		log.Error(err, "invalid global test options")
		os.Exit(1)
	}

	// Set up a root context for all tests and set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	rootContext = ctx
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Info("tests received shutdown signal and will be cancelled")
		cancel()
	}()

	// Everything's okay to run tests
	log.Info("Running e2e tests", "options", opts)
	os.Exit(m.Run())
}

// SuiteTest is what individual implementations should conform to.
type SuiteTest interface {
	New(ctx context.Context, log logr.Logger) (string, func(t *testing.T))
}

// TestSuite runs all the e2e tests. Any new tests need to be added to this
// list in order for them to run.
func TestSuite(t *testing.T) {
	tests := []SuiteTest{
		cliworkflow.CreateClusterTest{
			AWSCredentialsFile: opts.AWSCredentialsFile,
			AWSRegion:          opts.Region,
			PullSecretFile:     opts.PullSecretFile,
			ReleaseImage:       opts.LatestReleaseImage,
			ArtifactDir:        opts.ArtifactDir,
			BaseDomain:         opts.BaseDomain,
		},
	}

	for i := range tests {
		test := tests[i]
		name, testFn := test.New(rootContext, log)
		t.Run(name, testFn)
	}
}
