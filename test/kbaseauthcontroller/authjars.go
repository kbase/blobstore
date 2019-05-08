package kbaseauthcontroller

// this file simply lists the jars that are required to run the KBase auth server in test mode.
const (
	// authTemplates is the zip file containing templates for the server
	authTemplates = "kbase/auth2/kbase-auth2templates-0.2.4.zip"
)

// jars contains the list of jars in the KBase jars repo (https://github.com/kbase/jars)
// required for the auth server.
// might want to make the paths non-unix specific... yagni
var jars = []string{
	"kbase/auth2/kbase-auth2-0.2.4.jar",
	"kbase/auth2/kbase-auth2test-0.2.4.jar",
	//lib
	"apache_commons/commons-codec-1.8.jar",
	"apache_commons/commons-validator-1.5.1.jar",
	"google/guava-18.0.jar",
	"ini4j/ini4j-0.5.2.jar",
	"jcommander/jcommander-1.48.jar",
	"mongo/mongo-java-driver-3.3.0.jar",
	"mustache/compiler-0.9.3.jar",
	"nulab-inc/zxcvbn-1.2.2.jar",
	//logging
	"kbase/common/kbase-common-0.0.22.jar",
	"jna/jna-3.4.0.jar",
	"logback/logback-core-1.1.2.jar",
	"logback/logback-classic-1.1.2.jar",
	"slf4j/slf4j-api-1.7.25.jar",
	"syslog4j/syslog4j-0.9.46.jar",
	//yauaa
	"yauaa/yauaa-1.3.jar",
	"apache_commons/commons-lang3-3.5.jar",
	"apache_commons/commons-collections4-4.1.jar",
	"apache_commons/commons-logging-1.2.jar",
	"kohsuke/args4j-2.33.jar",
	"snakeyaml/snakeyaml-1.18.jar",
	//jackson
	"jackson/jackson-annotations-2.5.4.jar",
	"jackson/jackson-core-2.5.4.jar",
	"jackson/jackson-databind-2.5.4.jar",
	"jackson/jackson-jaxrs-base-2.5.4.jar",
	"jackson/jackson-jaxrs-json-provider-2.5.4.jar",
	"jackson/jackson-module-jaxb-annotations-2.5.4.jar",
	//jersey
	"jersey/entity-filtering/jersey-entity-filtering-2.23.2.jar",
	"jersey/entity-filtering/jersey-media-json-jackson-2.23.2.jar",
	"jersey/mvc/jersey-mvc-2.23.2.jar",
	"jersey/mvc/jersey-mvc-mustache-2.23.2.jar",
	"jersey/jersey-client-2.23.2.jar",
	"jersey/jersey-common-2.23.2.jar",
	"jersey/jersey-container-servlet-2.23.2.jar",
	"jersey/jersey-container-servlet-core-2.23.2.jar",
	"jersey/jersey-guava-2.23.2.jar",
	"jersey/jersey-media-jaxb-2.23.2.jar",
	"jersey/jersey-server-2.23.2.jar",
	//jerseydeps
	"annotation/javax.annotation-api-1.2.jar",
	"asm/asm-debug-all-5.0.4.jar",
	"inject/javax.inject-2.5.0-b05.jar",
	"javassist/javassist-3.20.0-GA.jar",
	"jaxb/jaxb-api-2.2.7.jar",
	"jaxrs/javax.ws.rs-api-2.0.1.jar",
	"osgi/org.osgi.core-4.2.0.jar",
	"persistence/persistence-api-1.0.jar",
	"servlet/javax.servlet-api-3.0.1.jar",
	"validationapi/validation-api-1.1.0.Final.jar",
	//jerseydep_hk2
	"hk2/aopalliance-repackaged-2.5.0-b05.jar",
	"hk2/hk2-api-2.5.0-b05.jar",
	"hk2/hk2-locator-2.5.0-b05.jar",
	"hk2/hk2-utils-2.5.0-b05.jar",
	"hk2/osgi-resource-locator-1.0.1.jar",
	//test
	"jetty/jetty-all-9.3.11.v20160721-uber.jar",
}
