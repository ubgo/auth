package samlidp

import "context"

// LookupForTest exposes the SP lookup (static, then store, then checked) to
// the external tests.
func LookupForTest(p *Plugin, entityID string) (ServiceProvider, error) {
	return p.lookupSP(context.Background(), entityID)
}
