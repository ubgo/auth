package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth/plugin/organization"
)

// TestOrgDomains_OneOrganizationProvesADomain pins, on every engine, the
// rule that a proved domain belongs to one organization. markVerified has no
// pre-check of its own: the unique verified_domain column is the only guard,
// and it holds only if each engine both refuses a second non-NULL value and
// accepts many NULLs, so several organizations may claim the same domain
// while none has proved it.
func TestOrgDomains_OneOrganizationProvesADomain(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		// Every proof succeeds: who wins is decided by the column, not by
		// the DNS answer.
		proves := organization.DomainVerifierFunc(func(context.Context, organization.DomainChallenge) (bool, error) { return true, nil })
		w := orgSetup(t, e, organization.Domains(organization.DomainsConfig{Verifier: proves}))
		ctx := request(w.a, w.owner.Token)
		beta := must[organization.Org](t)(w.org.Create(ctx, organization.CreateRequest{Name: "Beta", Slug: "beta"}))
		gamma := must[organization.Org](t)(w.org.Create(ctx, organization.CreateRequest{Name: "Gamma", Slug: "gamma"}))

		const domain = "claimed-domain.com"
		// Three unproved claims: three NULL verified_domain values under
		// the unique constraint, which every engine must accept.
		var claims []organization.OrgDomain
		for _, orgID := range []string{w.o.ID, beta.ID, gamma.ID} {
			claims = append(claims, must[organization.OrgDomain](t)(w.org.AddDomain(ctx, organization.AddDomainRequest{OrgID: orgID, Domain: domain})))
		}
		for i, c := range claims {
			if c.Verified {
				t.Fatalf("claim %d verified at add", i)
			}
		}

		if d := must[organization.OrgDomain](t)(w.org.VerifyDomain(ctx, claims[0].ID)); !d.Verified {
			t.Fatalf("first proof = %+v, want verified", d)
		}
		// The second organization's proof, and the operator's Go override,
		// are both refused by the column.
		if _, err := w.org.VerifyDomain(ctx, claims[1].ID); !errors.Is(err, organization.ErrDomainTaken) {
			t.Fatalf("second organization's proof = %v, want ErrDomainTaken", err)
		}
		if _, err := w.org.MarkDomainVerified(context.Background(), claims[2].ID); !errors.Is(err, organization.ErrDomainTaken) {
			t.Fatalf("MarkDomainVerified for a third organization = %v, want ErrDomainTaken", err)
		}

		// The refused claims are still there, unproved; the winner proved.
		for i, orgID := range []string{w.o.ID, beta.ID, gamma.ID} {
			list := must[[]organization.OrgDomain](t)(w.org.ListDomains(ctx, orgID))
			if len(list) != 1 || list[0].Domain != domain || list[0].Verified != (i == 0) {
				t.Fatalf("org %d domains = %+v, want one claim of %s, verified only for the first", i, list, domain)
			}
		}
	})
}
