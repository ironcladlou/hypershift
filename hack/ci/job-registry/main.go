package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	releaseRepository = "openshift/release"
	releaseMainURL    = "https://github.com/openshift/release/blob/main/"
	defaultSippyURL   = "https://sippy.dptools.openshift.org"
	sippyPresubmits   = "Presubmits"
	jobsRoot          = "ci-operator/jobs"
	hypershiftJobsDir = "ci-operator/jobs/openshift/hypershift"
)

var (
	releaseVersionRE  = regexp.MustCompile(`(?:^|-)release-(\d+\.\d+)(?:-|$)`)
	embeddedVersionRE = regexp.MustCompile(`(?:^|-)([4-9])-(\d{1,2})(?:-|$)`)
	conformanceRE     = regexp.MustCompile(`(?:^|/)hypershift-.+-conformance(?:-|$)`)
)

// Registry is the stable, serializable contract emitted by this command.
type Registry struct {
	// APIVersion identifies the schema used to serialize the registry.
	APIVersion string `yaml:"api_version" json:"api_version"`
	// Jobs contains every discovered job, ordered by stable job ID.
	Jobs []Job `yaml:"jobs" json:"jobs"`
}

// Job describes one Prow job. A Prow job name is its globally unique, stable
// identity and is also retained as Name to keep identity and display concerns
// separate in the serialized contract.
type Job struct {
	// ID is the globally unique, stable identity of the Prow job.
	ID string `yaml:"id" json:"id"`
	// Name is the current Prow job name displayed by reporting tools.
	Name string `yaml:"name" json:"name"`
	// Type identifies the Prow job type and is either "periodic" or "presubmit".
	Type string `yaml:"type" json:"type"`
	// Source canonically locates the generated job definition in openshift/release.
	Source Source `yaml:"source" json:"source"`
	// Versions lists the concrete OpenShift releases tested by the job. It is
	// empty when no concrete release can be inferred; branch names such as main
	// are not versions.
	Versions []string `yaml:"versions,flow" json:"versions"`
	// Platforms lists each infrastructure platform inferred from the job name,
	// context, and labels. It is empty when no platform can be inferred.
	Platforms []string `yaml:"platforms,flow" json:"platforms"`
	// E2EFramework identifies the HyperShift E2E framework as "v1" or "v2";
	// non-E2E jobs use "none".
	E2EFramework string `yaml:"e2e_framework" json:"e2e_framework"`
	// Variant is the ci-operator configuration variant from the generated Prow
	// job label. It is omitted when the job has no variant label.
	Variant string `yaml:"variant,omitempty" json:"variant,omitempty"`
	// Presubmit contains presubmit-only behavior and is omitted for periodics.
	Presubmit *Presubmit `yaml:"presubmit,omitempty" json:"presubmit,omitempty"`
	// SippyURL is a deterministic Sippy navigation URL. A non-nil URL does not
	// guarantee that Sippy currently has data for the job. It is nil when no
	// reliable Sippy route can be constructed.
	SippyURL *string `yaml:"sippy_url" json:"sippy_url"`
}

// Presubmit contains properties that do not apply to periodic jobs.
type Presubmit struct {
	// Required reports whether the job is non-optional when it applies. It is
	// the inverse of Prow's optional field and does not imply AlwaysRun.
	Required bool `yaml:"required" json:"required"`
	// AlwaysRun reports whether Prow automatically runs the job for every
	// matching pull request, subject to its other conditions.
	AlwaysRun bool `yaml:"always_run" json:"always_run"`
	// Branches contains regular expressions selecting branches where the job
	// applies. An empty list means all branches not excluded by SkipBranches.
	Branches []string `yaml:"branches,flow" json:"branches"`
	// SkipBranches contains regular expressions excluding branches from the job.
	SkipBranches []string `yaml:"skip_branches,flow" json:"skip_branches"`
	// RunIfChanged is a regular expression that conditionally runs the job when
	// a matching file changes. It is omitted when the job has no such condition.
	RunIfChanged string `yaml:"run_if_changed,omitempty" json:"run_if_changed,omitempty"`
	// SkipIfOnlyChanged is a regular expression that skips the job when every
	// changed file matches. It is omitted when the job has no such condition.
	SkipIfOnlyChanged string `yaml:"skip_if_only_changed,omitempty" json:"skip_if_only_changed,omitempty"`
}

// Source is a canonical reference into openshift/release. The job ID selects
// the entry within the generated YAML file.
type Source struct {
	// Repository is the canonical GitHub owner and repository name.
	Repository string `yaml:"repository" json:"repository"`
	// Path is the repository-relative path to the generated Prow configuration.
	Path string `yaml:"path" json:"path"`
	// URL links to Path on the main branch of Repository.
	URL string `yaml:"url" json:"url"`
}

type prowConfig struct {
	Periodics  []prowJob            `yaml:"periodics"`
	Presubmits map[string][]prowJob `yaml:"presubmits"`
}

type prowJob struct {
	Name              string            `yaml:"name"`
	Context           string            `yaml:"context"`
	Labels            map[string]string `yaml:"labels"`
	Optional          bool              `yaml:"optional"`
	AlwaysRun         bool              `yaml:"always_run"`
	Branches          []string          `yaml:"branches"`
	SkipBranches      []string          `yaml:"skip_branches"`
	RunIfChanged      string            `yaml:"run_if_changed"`
	SkipIfOnlyChanged string            `yaml:"skip_if_only_changed"`
	Spec              struct {
		Containers []struct {
			Args []string `yaml:"args"`
		} `yaml:"containers"`
	} `yaml:"spec"`
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		exitf("determine home directory: %v", err)
	}
	releaseDir := flag.String("release-dir", filepath.Join(home, "Projects", "openshift-release"), "path to an openshift/release checkout")
	sippyBaseURL := flag.String("sippy-base-url", defaultSippyURL, "base URL for generated Sippy job links")
	outputFormat := flag.String("format", "yaml", "output format: yaml or json")
	flag.Parse()

	registry, err := discover(*releaseDir)
	if err != nil {
		exitf("discover jobs: %v", err)
	}
	populateSippyURLs(&registry, *sippyBaseURL)

	switch *outputFormat {
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		encoder.SetIndent(2)
		defer encoder.Close()
		if err := encoder.Encode(registry); err != nil {
			exitf("render YAML registry: %v", err)
		}
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(registry); err != nil {
			exitf("render JSON registry: %v", err)
		}
	default:
		exitf("unsupported output format %q: expected yaml or json", *outputFormat)
	}
}

func populateSippyURLs(registry *Registry, baseURL string) {
	for i := range registry.Jobs {
		job := &registry.Jobs[i]
		if job.Type == "presubmit" {
			link := sippyJobURL(baseURL, sippyPresubmits, job.Name, true)
			job.SippyURL = &link
			continue
		}

		match := releaseVersionRE.FindStringSubmatch(job.Name)
		if match == nil {
			continue
		}
		link := sippyJobURL(baseURL, match[1], job.Name, false)
		job.SippyURL = &link
	}
}

func sippyJobURL(baseURL, release, name string, analysis bool) string {
	filter := `{"items":[{"columnField":"name","operatorValue":"equals","value":` + strconv.Quote(name) + `}]}`
	query := url.Values{"filters": []string{filter}}
	path := strings.TrimRight(baseURL, "/") + "/sippy-ng/jobs/" + url.PathEscape(release)
	if analysis {
		path += "/analysis"
	}
	return path + "?" + query.Encode()
}

func discover(releaseDir string) (Registry, error) {
	root := filepath.Join(releaseDir, jobsRoot)
	if info, err := os.Stat(root); err != nil {
		return Registry{}, err
	} else if !info.IsDir() {
		return Registry{}, fmt.Errorf("%s is not a directory", root)
	}

	registry := Registry{APIVersion: "job-registry/v1", Jobs: []Job{}}
	seen := map[string]Source{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !isJobConfig(entry.Name()) {
			return nil
		}

		rel, err := filepath.Rel(releaseDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		isHypershiftConfig := strings.HasPrefix(rel, hypershiftJobsDir+"/")

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Most of openshift/release is irrelevant. This textual check keeps the
		// full-tree scan cheap; parsed jobs are still checked structurally below.
		if !isHypershiftConfig && !bytes.Contains(data, []byte("hypershift-")) {
			return nil
		}

		var config prowConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		source := Source{Repository: releaseRepository, Path: rel, URL: releaseMainURL + rel}
		for _, candidate := range config.Periodics {
			if isHypershiftConfig || isHypershiftConformance(candidate) {
				if err := addJob(&registry, seen, candidate, "periodic", source); err != nil {
					return err
				}
			}
		}
		for _, candidates := range config.Presubmits {
			for _, candidate := range candidates {
				if isHypershiftConfig || isHypershiftConformance(candidate) {
					if err := addJob(&registry, seen, candidate, "presubmit", source); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return Registry{}, err
	}

	sort.Slice(registry.Jobs, func(i, j int) bool { return registry.Jobs[i].ID < registry.Jobs[j].ID })
	return registry, nil
}

func isJobConfig(name string) bool {
	return strings.HasSuffix(name, "-periodics.yaml") || strings.HasSuffix(name, "-presubmits.yaml")
}

func isHypershiftConformance(job prowJob) bool {
	if conformanceRE.MatchString(job.Context) {
		return true
	}
	for _, container := range job.Spec.Containers {
		for _, arg := range container.Args {
			if strings.HasPrefix(arg, "--target=") && conformanceRE.MatchString(strings.TrimPrefix(arg, "--target=")) {
				return true
			}
		}
	}
	return false
}

func addJob(registry *Registry, seen map[string]Source, candidate prowJob, jobType string, source Source) error {
	if candidate.Name == "" {
		return errors.New("encountered a job without a name in " + source.Path)
	}
	if prior, exists := seen[candidate.Name]; exists {
		return fmt.Errorf("duplicate job identity %q in %s and %s", candidate.Name, prior.Path, source.Path)
	}
	seen[candidate.Name] = source
	job := Job{
		ID:           candidate.Name,
		Name:         candidate.Name,
		Type:         jobType,
		Source:       source,
		Versions:     versions(candidate),
		Platforms:    platforms(candidate),
		E2EFramework: framework(candidate),
		Variant:      candidate.Labels["ci-operator.openshift.io/variant"],
		SippyURL:     nil, // Populated after all jobs are discovered.
	}
	if jobType == "presubmit" {
		job.Presubmit = &Presubmit{
			Required:          !candidate.Optional,
			AlwaysRun:         candidate.AlwaysRun,
			Branches:          nonNil(candidate.Branches),
			SkipBranches:      nonNil(candidate.SkipBranches),
			RunIfChanged:      candidate.RunIfChanged,
			SkipIfOnlyChanged: candidate.SkipIfOnlyChanged,
		}
	}
	registry.Jobs = append(registry.Jobs, job)
	return nil
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func versions(job prowJob) []string {
	values := map[string]struct{}{}
	if match := releaseVersionRE.FindStringSubmatch(job.Name); match != nil {
		values[match[1]] = struct{}{}
	}
	for _, match := range embeddedVersionRE.FindAllStringSubmatch(job.Name, -1) {
		values[match[1]+"."+match[2]] = struct{}{}
	}
	return sortedKeys(values)
}

func platforms(job prowJob) []string {
	text := strings.ToLower(job.Name + " " + job.Context)
	for key, value := range job.Labels {
		text += " " + strings.ToLower(key) + "=" + strings.ToLower(value)
	}
	values := map[string]struct{}{}
	rules := []struct {
		name    string
		needles []string
	}{
		{"aro", []string{"-aks", "hypershift-aks", "aro-hcp", "e2e-aro-"}},
		{"kubevirt", []string{"kubevirt"}},
		{"openstack", []string{"openstack"}},
		{"powervs", []string{"powervs"}},
		{"ibmcloud", []string{"ibmcloud"}},
		{"aws", []string{"-aws", "hypershift-aws"}},
		{"azure", []string{"-azure", "hypershift-azure", "azure4"}},
		{"gcp", []string{"-gcp", "-gke", "hypershift-gcp"}},
		{"agent", []string{"-mce-", "e2e-agent-", "hypershift-mce-agent"}},
		{"baremetal", []string{"-metal-", "baremetalds", "equinix"}},
	}
	for _, rule := range rules {
		for _, needle := range rule.needles {
			if strings.Contains(text, needle) {
				values[rule.name] = struct{}{}
				break
			}
		}
	}
	return sortedKeys(values)
}

func framework(job prowJob) string {
	text := strings.ToLower(job.Name + " " + job.Context)
	if strings.Contains(text, "e2e-v2") {
		return "v2"
	}
	if strings.Contains(text, "e2e") || strings.Contains(text, "conformance") {
		return "v1"
	}
	return "none"
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
