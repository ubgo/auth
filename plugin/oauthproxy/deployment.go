package oauthproxy

import (
	"net/url"
	"strings"
)

// vendorURLVars are the variables hosts set to a deployment's address,
// better-auth's list, in its order. VERCEL_URL holds a bare host and gets
// https://; the others are used only when they parse as an absolute URL.
var vendorURLVars = []string{"VERCEL_URL", "NETLIFY_URL", "RENDER_URL", "AWS_LAMBDA_FUNCTION_NAME", "GOOGLE_CLOUD_FUNCTION_NAME", "AZURE_FUNCTION_NAME"}

// DeploymentURL infers this deployment's URL from the host's environment,
// better-auth's vendor URL inference, for auth.WithBaseURL on a preview:
//
//	auth.WithBaseURL(oauthproxy.DeploymentURL(os.Getenv, "http://localhost:8080"))
//
// getenv is passed in (os.Getenv in an app) so nothing is read behind the
// caller's back; fallback is returned when no variable holds a usable URL.
//
//ds:def id=oauthproxy-deploymenturl-5n8wq2kt owner=@khanakia stability=stable
func DeploymentURL(getenv func(string) string, fallback string) string {
	for _, name := range vendorURLVars {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			continue
		}
		if name == "VERCEL_URL" && !strings.Contains(v, "://") {
			v = "https://" + v
		}
		if u, err := url.Parse(v); err == nil && u.IsAbs() && u.Host != "" && (u.Scheme == "https" || u.Scheme == "http") {
			return strings.TrimSuffix(v, "/")
		}
	}
	return fallback
}
