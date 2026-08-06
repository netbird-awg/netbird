package store

import (
	"context"
	"time"

	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
	"github.com/netbirdio/netbird/shared/management/status"
)

func localLDAPSyncSQLOnly() error {
	return status.Errorf(status.PreconditionFailed, "local LDAP synchronization requires a SQL store")
}

func (s *FileStore) ListLDAPSyncConfigs(context.Context, string) ([]*ldapsyncmodel.Config, error) {
	return nil, localLDAPSyncSQLOnly()
}

func (s *FileStore) HasLDAPSyncConfig(context.Context, string, string) (bool, error) {
	return false, nil
}

func (s *FileStore) GetLDAPSyncConfig(context.Context, string, string) (*ldapsyncmodel.Config, error) {
	return nil, localLDAPSyncSQLOnly()
}

func (s *FileStore) SaveLDAPSyncConfig(context.Context, *ldapsyncmodel.Config, int64) error {
	return localLDAPSyncSQLOnly()
}

func (s *FileStore) UpdateLDAPSyncConfigRuntime(context.Context, *ldapsyncmodel.Config) error {
	return localLDAPSyncSQLOnly()
}

func (s *FileStore) CreateLDAPSyncRun(context.Context, *ldapsyncmodel.Run) error {
	return localLDAPSyncSQLOnly()
}

func (s *FileStore) GetLDAPSyncRun(context.Context, string, string, string) (*ldapsyncmodel.Run, error) {
	return nil, localLDAPSyncSQLOnly()
}

func (s *FileStore) CancelLDAPSyncRun(context.Context, string, string, string, time.Time) (*ldapsyncmodel.Run, error) {
	return nil, localLDAPSyncSQLOnly()
}

func (s *FileStore) ListLDAPSyncRuns(context.Context, string, string, int, int) ([]*ldapsyncmodel.Run, int64, error) {
	return nil, 0, localLDAPSyncSQLOnly()
}

func (s *FileStore) CountLDAPSyncRuns(context.Context, ...string) (int64, error) {
	return 0, localLDAPSyncSQLOnly()
}

func (s *FileStore) ClaimLDAPSyncRun(context.Context, time.Time, time.Duration, string) (*ldapsyncmodel.Run, error) {
	return nil, localLDAPSyncSQLOnly()
}

func (s *FileStore) RenewLDAPSyncRunLease(context.Context, string, string, string, string, time.Time, time.Duration) (bool, error) {
	return false, localLDAPSyncSQLOnly()
}

func (s *FileStore) UpdateLDAPSyncRun(context.Context, *ldapsyncmodel.Run) error {
	return localLDAPSyncSQLOnly()
}

func (s *FileStore) UpdateLDAPSyncRunOwned(context.Context, *ldapsyncmodel.Run, string) (bool, error) {
	return false, localLDAPSyncSQLOnly()
}

func (s *FileStore) GetLDAPSyncObjects(context.Context, string, string, string) ([]*ldapsyncmodel.Object, error) {
	return nil, localLDAPSyncSQLOnly()
}

func (s *FileStore) SaveLDAPSyncObjects(context.Context, []*ldapsyncmodel.Object) error {
	return localLDAPSyncSQLOnly()
}
