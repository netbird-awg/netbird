package scim

import (
	"os"
	"strings"
)

const (
	localIntegrationsEnabledEnv = "NB_LOCAL_INTEGRATIONS_ENABLED"
	localSCIMEnabledEnv         = "NB_LOCAL_SCIM_ENABLED"
)

// Enabled keeps the local SCIM implementation opt-in so upstream deployments
// retain their existing behavior.
func Enabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(localIntegrationsEnabledEnv)), "true") &&
		strings.EqualFold(strings.TrimSpace(os.Getenv(localSCIMEnabledEnv)), "true")
}
