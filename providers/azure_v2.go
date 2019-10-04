package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"

	oidc "github.com/coreos/go-oidc"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/google/uuid"
)

type AzureV2Provider struct {
	*ProviderData
	*OIDCProvider

	Tenant          string
	PermittedGroups []string
}

func NewAzureV2Provider(p *ProviderData) *AzureV2Provider {
	p.ProviderName = "Azure v2"
	return &AzureV2Provider{ProviderData: p, OIDCProvider: &OIDCProvider{ProviderData: p}}
}

func (p *AzureV2Provider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	s, err = p.OIDCProvider.Redeem(redirectURL, code)
	if err != nil {
		return nil, fmt.Errorf("OIDCProvider failed to redeem code: %v", err)
	}

	// Extract Azure claims.
	// https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
	var claims struct {
		Roles  []string `json:"roles"`
		Groups []string `json:"groups"`
	}
	json.Unmarshal([]byte(s.IDToken), &claims)
	s.Roles = claims.Roles
	s.Groups = claims.Groups
	log.Printf("Session: %v", s)
	return
}

func (p *AzureV2Provider) Configure(tenant string) error {
	// Note: Do NOT attempt to use the aliases mentioned in the Azure docs, it will fail due to coreos/oidc's strict validation
	// https://github.com/MicrosoftDocs/azure-docs/issues/38427
	// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#fetch-the-openid-connect-metadata-document
	_, err := uuid.Parse(tenant);
	if err != nil {
		return fmt.Errorf("given azure-tenant `%s` is not a UUID", tenant)
	}
	p.Tenant = tenant

	discoveryURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", p.Tenant)

	// Configure discoverable provider data.
	oidcProvider, err := oidc.NewProvider(context.Background(), discoveryURL)
	if err != nil {
		return fmt.Errorf("Unable to discovery OIDC URL: %v", err)
	}
	p.OIDCProvider.Verifier = oidcProvider.Verifier(&oidc.Config{
		ClientID: p.ClientID,
	})
	p.LoginURL, err = url.Parse(oidcProvider.Endpoint().AuthURL)
	if err != nil {
		return fmt.Errorf("Unable to parse OIDC Authentication URL: %v", err)
	}
	p.RedeemURL, err = url.Parse(oidcProvider.Endpoint().TokenURL)
	if err != nil {
		return fmt.Errorf("Unable to parse OIDC Token URL: %v", err)
	}
	p.ProfileURL, err = url.Parse("https://graph.microsoft.com/oidc/userinfo")
	if err != nil {
		return fmt.Errorf("Unable to parse OIDC UserInfo URL: %v", err)
	}
	if p.Scope == "" {
		p.Scope = "openid"
	}
	return nil
}

func (p *AzureV2Provider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	p.OIDCProvider.RefreshSessionIfNeeded(s)

	// re-check that the user is in the proper group(s)
	if !p.ValidateGroup(s.Email) {
		return false, fmt.Errorf("%s is no longer in the group(s)", s.Email)
	}

	return true, nil
}

func (p *AzureV2Provider) ValidateSessionState(s *sessions.SessionState) bool {
	return p.OIDCProvider.ValidateSessionState(s)
}
