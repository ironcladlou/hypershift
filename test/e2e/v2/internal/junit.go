//go:build e2ev2

package internal

import (
	"encoding/xml"
	"slices"
	"strings"

	"github.com/onsi/ginkgo/v2/types"
)

const informingSkipPrefix = "informing test failure: "

type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []*JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
	XMLName    xml.Name         `xml:"testsuite"`
	Name       string           `xml:"name,attr"`
	NumTests   int              `xml:"tests,attr"`
	NumSkipped int              `xml:"skipped,attr"`
	NumFailed  int              `xml:"failures,attr"`
	Duration   float64          `xml:"time,attr"`
	TestCases  []*JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	XMLName       xml.Name        `xml:"testcase"`
	Name          string          `xml:"name,attr"`
	Duration      float64         `xml:"time,attr"`
	Lifecycle     string          `xml:"lifecycle,attr,omitempty"`
	Properties    []*JUnitProperty `xml:"properties>property,omitempty"`
	SkipMessage   *JUnitSkipMessage   `xml:"skipped,omitempty"`
	FailureOutput *JUnitFailureOutput `xml:"failure,omitempty"`
}

type JUnitProperty struct {
	XMLName xml.Name `xml:"property"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:"value,attr"`
}

type JUnitSkipMessage struct {
	XMLName xml.Name `xml:"skipped"`
	Message string   `xml:"message,attr,omitempty"`
}

type JUnitFailureOutput struct {
	XMLName xml.Name `xml:"failure"`
	Message string   `xml:"message,attr,omitempty"`
	Output  string   `xml:",chardata"`
}

// BuildLifecycleReport builds a JUnit test suite containing only informing tests
// from the Ginkgo report. Informing failures that were converted to skips by
// InformingAwareFailHandler are re-emitted as failures with lifecycle="informing".
// This supplemental JUnit file is picked up by ci-to-bigquery and loaded into
// the ci_analysis_us.junit BigQuery table with the lifecycle column populated.
func BuildLifecycleReport(suiteName string, specReports types.SpecReports) *JUnitTestSuites {
	suite := &JUnitTestSuite{
		Name: suiteName + " [informing]",
	}

	for _, spec := range specReports {
		if spec.LeafNodeType != types.NodeTypeIt {
			continue
		}
		if !slices.Contains(spec.Labels(), "Informing") {
			continue
		}

		tc := &JUnitTestCase{
			Name:      spec.FullText(),
			Duration:  spec.RunTime.Seconds(),
			Lifecycle: "informing",
			Properties: []*JUnitProperty{
				{Name: "lifecycle", Value: "informing"},
			},
		}

		switch {
		case isInformingFailureSkip(spec):
			msg := strings.TrimPrefix(spec.Failure.Message, informingSkipPrefix)
			tc.FailureOutput = &JUnitFailureOutput{
				Message: msg,
				Output:  spec.Failure.Location.String(),
			}
			suite.NumFailed++
		case spec.State == types.SpecStateFailed || spec.State == types.SpecStatePanicked:
			tc.FailureOutput = &JUnitFailureOutput{
				Message: spec.Failure.Message,
				Output:  spec.Failure.Location.String(),
			}
			suite.NumFailed++
		case spec.State == types.SpecStateSkipped:
			tc.SkipMessage = &JUnitSkipMessage{
				Message: spec.Failure.Message,
			}
			suite.NumSkipped++
		}

		suite.TestCases = append(suite.TestCases, tc)
		suite.NumTests++
	}

	suite.Duration = sumDuration(suite.TestCases)

	return &JUnitTestSuites{
		Suites: []*JUnitTestSuite{suite},
	}
}

// isInformingFailureSkip returns true if the spec was skipped by
// InformingAwareFailHandler due to an informing test failure.
func isInformingFailureSkip(spec types.SpecReport) bool {
	return spec.State == types.SpecStateSkipped &&
		slices.Contains(spec.Labels(), "Informing") &&
		strings.HasPrefix(spec.Failure.Message, informingSkipPrefix)
}

func sumDuration(cases []*JUnitTestCase) float64 {
	var total float64
	for _, tc := range cases {
		total += tc.Duration
	}
	return total
}
