package ldapsync

import (
	"os"
	"strings"
)

const (
	localIntegrationsEnabledEnv = "NB_LOCAL_INTEGRATIONS_ENABLED"
	localLDAPSyncEnabledEnv     = "NB_LOCAL_LDAP_SYNC_ENABLED"
)

func Enabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(localIntegrationsEnabledEnv)), "true")
}

func SyncEnabled() bool {
	return Enabled() && strings.EqualFold(strings.TrimSpace(os.Getenv(localLDAPSyncEnabledEnv)), "true")
}
