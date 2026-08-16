package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
)

// -----------------------------------------------
//   AUTH CONTEXT
// -----------------------------------------------

// AuthContext records which principal (if any) authenticated-mode deep-scan
// checks run as for a given cloud. This is what makes the authenticated vs.
// anonymous distinction meaningful in the report -- e.g. an "authenticated
// list succeeded" finding is only actionable if the analyst knows whether
// that was their own account or a completely unauthenticated fallback.
type AuthContext struct {
	Cloud         string `json:"cloud"`
	Authenticated bool   `json:"authenticated"`
	Principal     string `json:"principal,omitempty"`
	Account       string `json:"account,omitempty"`
	Extra         string `json:"extra,omitempty"`
}

// resolveAuthContexts checks credential/identity status for every cloud in
// the requested scan scope and prints a banner for each.
func resolveAuthContexts(clouds []string) []AuthContext {
	logSection("Identity / Auth Context")
	var contexts []AuthContext
	for _, c := range clouds {
		var ctx AuthContext
		switch strings.ToLower(strings.TrimSpace(c)) {
		case "aws":
			ctx = resolveAWSIdentity()
		case "gcp":
			ctx = resolveGCPIdentity()
		case "azure":
			ctx = resolveAzureIdentity()
		case "alibaba":
			ctx = resolveAlibabaIdentity()
		default:
			continue
		}
		printIdentityBanner(ctx)
		contexts = append(contexts, ctx)
	}
	return contexts
}

// -----------------------------------------------
//   AWS -- sts get-caller-identity
// -----------------------------------------------

func resolveAWSIdentity() AuthContext {
	ctx := AuthContext{Cloud: "aws"}
	rc, stdout, _ := runCmd([]string{"aws", "sts", "get-caller-identity", "--output", "json"}, 15*time.Second)
	if rc != 0 || strings.TrimSpace(stdout) == "" {
		return ctx
	}
	var identity struct {
		Account string `json:"Account"`
		Arn     string `json:"Arn"`
		UserId  string `json:"UserId"`
	}
	if err := json.Unmarshal([]byte(stdout), &identity); err != nil {
		return ctx
	}
	ctx.Authenticated = true
	ctx.Principal = identity.Arn
	ctx.Account = identity.Account
	ctx.Extra = identity.UserId
	return ctx
}

// -----------------------------------------------
//   GCP -- Application Default Credentials
// -----------------------------------------------
//
// GCP support now uses the native storage SDK (gcloud.go) instead of
// shelling out to `gsutil`, so identity resolution follows the same
// Application Default Credentials chain: GOOGLE_APPLICATION_CREDENTIALS,
// `gcloud auth application-default login`, or an attached service account.

func resolveGCPIdentity() AuthContext {
	ctx := AuthContext{Cloud: "gcp"}

	cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	creds, err := google.FindDefaultCredentials(cctx)
	if err != nil {
		return ctx
	}

	// Service-account key files carry the identity directly.
	if len(creds.JSON) > 0 {
		var sa struct {
			ClientEmail string `json:"client_email"`
			ProjectID   string `json:"project_id"`
			Type        string `json:"type"`
		}
		if err := json.Unmarshal(creds.JSON, &sa); err == nil && sa.ClientEmail != "" {
			ctx.Authenticated = true
			ctx.Principal = sa.ClientEmail
			ctx.Account = firstNonEmpty(sa.ProjectID, creds.ProjectID)
			ctx.Extra = sa.Type
			return ctx
		}
	}

	// User ADC (gcloud auth application-default login) has no email in the
	// credentials JSON -- recover it via the OAuth2 tokeninfo endpoint.
	token, err := creds.TokenSource.Token()
	if err != nil || token.AccessToken == "" {
		return ctx
	}
	email := gcpTokenInfoEmail(cctx, token.AccessToken)
	if email == "" {
		// We do have a valid token even if we can't resolve the email --
		// still authenticated, just without a friendly principal name.
		ctx.Authenticated = true
		ctx.Principal = "authenticated (email unknown)"
		ctx.Account = creds.ProjectID
		return ctx
	}
	ctx.Authenticated = true
	ctx.Principal = email
	ctx.Account = creds.ProjectID
	return ctx
}

func gcpTokenInfoEmail(ctx context.Context, accessToken string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://oauth2.googleapis.com/tokeninfo?access_token="+url.QueryEscape(accessToken), nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	var info struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return ""
	}
	return info.Email
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// -----------------------------------------------
//   AZURE -- az account show
// -----------------------------------------------

func resolveAzureIdentity() AuthContext {
	ctx := AuthContext{Cloud: "azure"}
	rc, stdout, _ := runCmd([]string{"az", "account", "show", "--output", "json"}, 15*time.Second)
	if rc != 0 || strings.TrimSpace(stdout) == "" {
		return ctx
	}
	var account struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		User struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"user"`
		TenantID string `json:"tenantId"`
	}
	if err := json.Unmarshal([]byte(stdout), &account); err != nil {
		return ctx
	}
	ctx.Authenticated = true
	ctx.Principal = account.User.Name
	ctx.Account = account.ID
	ctx.Extra = "tenant: " + account.TenantID
	return ctx
}

// -----------------------------------------------
//   ALIBABA -- aliyun sts GetCallerIdentity
// -----------------------------------------------

func resolveAlibabaIdentity() AuthContext {
	ctx := AuthContext{Cloud: "alibaba"}
	rc, stdout, _ := runCmd([]string{"aliyun", "sts", "GetCallerIdentity"}, 15*time.Second)
	if rc != 0 || strings.TrimSpace(stdout) == "" {
		return ctx
	}
	var identity struct {
		AccountId string `json:"AccountId"`
		Arn       string `json:"Arn"`
		UserId    string `json:"UserId"`
	}
	if err := json.Unmarshal([]byte(stdout), &identity); err != nil {
		return ctx
	}
	ctx.Authenticated = true
	ctx.Principal = identity.Arn
	ctx.Account = identity.AccountId
	ctx.Extra = identity.UserId
	return ctx
}
