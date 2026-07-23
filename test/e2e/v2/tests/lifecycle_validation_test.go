//go:build e2ev2

package tests

import (
	. "github.com/onsi/ginkgo/v2"
)

// TODO(CNTRLPLANE-3863): Remove this file after validating lifecycle JUnit
// output in CI. This is a temporary synthetic test that intentionally fails
// with Label("Informing") to verify that:
// 1. InformingAwareFailHandler converts the failure to a skip
// 2. The ReportAfterSuite re-emits it as a failure with lifecycle="informing"
// 3. The job still passes (exit 0)
var _ = Describe("[sig-hypershift][Jira:Hypershift][Feature:InformingLifecycle] Lifecycle Validation",
	Label("informing-lifecycle-validation"), func() {
		It("should demonstrate informing lifecycle JUnit output", Label("Informing"), func() {
			Fail("This intentional failure validates that informing tests emit lifecycle metadata in JUnit")
		})
	})
