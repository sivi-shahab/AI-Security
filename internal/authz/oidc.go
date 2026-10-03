package authz

import (
	"context"
	"errors"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// KeycloakVerifier validates Keycloak access tokens: signature against the realm JWKS (refreshed on key
// rotation), issuer, audience (our client id, added by an audience mapper) and expiry. ID tokens are refused.
func KeycloakVerifier(ctx context.Context, issuer, audience string) (func(context.Context, string) (Claims, error), error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	v := p.Verifier(&oidc.Config{ClientID: audience})
	return func(ctx context.Context, raw string) (Claims, error) {
		tok, err := v.Verify(ctx, raw)
		if err != nil {
			return Claims{}, err
		}
		var c struct {
			Claims
			Type     string `json:"typ"`
			AuthTime int64  `json:"auth_time"`
		}
		if err := tok.Claims(&c); err != nil {
			return Claims{}, err
		}
		if c.Type != "Bearer" {
			return Claims{}, errors.New("not an access token")
		}
		c.Subject = tok.Subject
		c.Claims.AuthTime = time.Unix(c.AuthTime, 0)
		return c.Claims, nil
	}, nil
}
