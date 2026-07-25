package edr

import (
	"os"
	"strings"
)

const (
	localIntegrationsEnabledEnv = "NB_LOCAL_INTEGRATIONS_ENABLED"
	localEDREnabledEnv          = "NB_LOCAL_EDR_ENABLED"
)

// Enabled keeps the local implementation isolated from the upstream
// integrated-validator stub.
func Enabled() bool {
	return envTrue(localIntegrationsEnabledEnv) && envTrue(localEDREnabledEnv)
}

func envTrue(name string) bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(name)), "true")
}
