package eventstreaming

import (
	"os"
	"strings"
)

const (
	localIntegrationsEnabledEnv   = "NB_LOCAL_INTEGRATIONS_ENABLED"
	localEventStreamingEnabledEnv = "NB_LOCAL_EVENT_STREAMING_ENABLED"
)

// Enabled keeps the local implementation isolated from upstream behavior.
func Enabled() bool {
	return envTrue(localIntegrationsEnabledEnv) && envTrue(localEventStreamingEnabledEnv)
}

func envTrue(name string) bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(name)), "true")
}
