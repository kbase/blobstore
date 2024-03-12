package kbaseauthcontroller

// this file simply lists the template and the jar in the KBase jars repo (https://github.com/kbase/jars)
// that are required to run the KBase auth server in test mode.
const (
	// authTemplates is the zip file containing templates for the server
	authTemplates = "kbase/auth2/kbase-auth2templates-0.2.4.zip"

	// auth2ShadowAllJar is the jar required for the server
	authShadowAllJar = "kbase/auth2/kbase-auth2-test-shadow-all-0.7.0.jar"
)
