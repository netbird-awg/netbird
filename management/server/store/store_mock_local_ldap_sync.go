// Code generated for the local LDAP synchronization Store extension. DO NOT EDIT.

package store

import (
	"context"
	"reflect"
	"time"

	"github.com/golang/mock/gomock"

	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
)

func (m *MockStore) ListLDAPSyncConfigs(ctx context.Context, accountID string) ([]*ldapsyncmodel.Config, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListLDAPSyncConfigs", ctx, accountID)
	ret0, _ := ret[0].([]*ldapsyncmodel.Config)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStoreMockRecorder) ListLDAPSyncConfigs(ctx, accountID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListLDAPSyncConfigs", reflect.TypeOf((*MockStore)(nil).ListLDAPSyncConfigs), ctx, accountID)
}

func (m *MockStore) GetLDAPSyncConfig(ctx context.Context, accountID, connectorID string) (*ldapsyncmodel.Config, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLDAPSyncConfig", ctx, accountID, connectorID)
	ret0, _ := ret[0].(*ldapsyncmodel.Config)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStoreMockRecorder) GetLDAPSyncConfig(ctx, accountID, connectorID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLDAPSyncConfig", reflect.TypeOf((*MockStore)(nil).GetLDAPSyncConfig), ctx, accountID, connectorID)
}

func (m *MockStore) SaveLDAPSyncConfig(ctx context.Context, config *ldapsyncmodel.Config, expectedRevision int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveLDAPSyncConfig", ctx, config, expectedRevision)
	ret0, _ := ret[0].(error)
	return ret0
}

func (mr *MockStoreMockRecorder) SaveLDAPSyncConfig(ctx, config, expectedRevision any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveLDAPSyncConfig", reflect.TypeOf((*MockStore)(nil).SaveLDAPSyncConfig), ctx, config, expectedRevision)
}

func (m *MockStore) UpdateLDAPSyncConfigRuntime(ctx context.Context, config *ldapsyncmodel.Config) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateLDAPSyncConfigRuntime", ctx, config)
	ret0, _ := ret[0].(error)
	return ret0
}

func (mr *MockStoreMockRecorder) UpdateLDAPSyncConfigRuntime(ctx, config any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateLDAPSyncConfigRuntime", reflect.TypeOf((*MockStore)(nil).UpdateLDAPSyncConfigRuntime), ctx, config)
}

func (m *MockStore) CreateLDAPSyncRun(ctx context.Context, run *ldapsyncmodel.Run) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateLDAPSyncRun", ctx, run)
	ret0, _ := ret[0].(error)
	return ret0
}

func (mr *MockStoreMockRecorder) CreateLDAPSyncRun(ctx, run any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateLDAPSyncRun", reflect.TypeOf((*MockStore)(nil).CreateLDAPSyncRun), ctx, run)
}

func (m *MockStore) GetLDAPSyncRun(ctx context.Context, accountID, connectorID, runID string) (*ldapsyncmodel.Run, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLDAPSyncRun", ctx, accountID, connectorID, runID)
	ret0, _ := ret[0].(*ldapsyncmodel.Run)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStoreMockRecorder) GetLDAPSyncRun(ctx, accountID, connectorID, runID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLDAPSyncRun", reflect.TypeOf((*MockStore)(nil).GetLDAPSyncRun), ctx, accountID, connectorID, runID)
}

func (m *MockStore) CancelLDAPSyncRun(ctx context.Context, accountID, connectorID, runID string, finishedAt time.Time) (*ldapsyncmodel.Run, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CancelLDAPSyncRun", ctx, accountID, connectorID, runID, finishedAt)
	ret0, _ := ret[0].(*ldapsyncmodel.Run)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStoreMockRecorder) CancelLDAPSyncRun(ctx, accountID, connectorID, runID, finishedAt any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CancelLDAPSyncRun", reflect.TypeOf((*MockStore)(nil).CancelLDAPSyncRun), ctx, accountID, connectorID, runID, finishedAt)
}

func (m *MockStore) ListLDAPSyncRuns(ctx context.Context, accountID, connectorID string, offset, limit int) ([]*ldapsyncmodel.Run, int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListLDAPSyncRuns", ctx, accountID, connectorID, offset, limit)
	ret0, _ := ret[0].([]*ldapsyncmodel.Run)
	ret1, _ := ret[1].(int64)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

func (mr *MockStoreMockRecorder) ListLDAPSyncRuns(ctx, accountID, connectorID, offset, limit any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListLDAPSyncRuns", reflect.TypeOf((*MockStore)(nil).ListLDAPSyncRuns), ctx, accountID, connectorID, offset, limit)
}

func (m *MockStore) CountLDAPSyncRuns(ctx context.Context, statuses ...string) (int64, error) {
	m.ctrl.T.Helper()
	args := []any{ctx}
	for _, status := range statuses {
		args = append(args, status)
	}
	ret := m.ctrl.Call(m, "CountLDAPSyncRuns", args...)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStoreMockRecorder) CountLDAPSyncRuns(ctx any, statuses ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	args := append([]any{ctx}, statuses...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountLDAPSyncRuns", reflect.TypeOf((*MockStore)(nil).CountLDAPSyncRuns), args...)
}

func (m *MockStore) ClaimLDAPSyncRun(ctx context.Context, now time.Time, leaseDuration time.Duration, leaseOwner string) (*ldapsyncmodel.Run, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClaimLDAPSyncRun", ctx, now, leaseDuration, leaseOwner)
	ret0, _ := ret[0].(*ldapsyncmodel.Run)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStoreMockRecorder) ClaimLDAPSyncRun(ctx, now, leaseDuration, leaseOwner any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClaimLDAPSyncRun", reflect.TypeOf((*MockStore)(nil).ClaimLDAPSyncRun), ctx, now, leaseDuration, leaseOwner)
}

func (m *MockStore) RenewLDAPSyncRunLease(ctx context.Context, accountID, connectorID, runID, leaseOwner string, now time.Time, leaseDuration time.Duration) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RenewLDAPSyncRunLease", ctx, accountID, connectorID, runID, leaseOwner, now, leaseDuration)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStoreMockRecorder) RenewLDAPSyncRunLease(ctx, accountID, connectorID, runID, leaseOwner, now, leaseDuration any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RenewLDAPSyncRunLease", reflect.TypeOf((*MockStore)(nil).RenewLDAPSyncRunLease), ctx, accountID, connectorID, runID, leaseOwner, now, leaseDuration)
}

func (m *MockStore) UpdateLDAPSyncRun(ctx context.Context, run *ldapsyncmodel.Run) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateLDAPSyncRun", ctx, run)
	ret0, _ := ret[0].(error)
	return ret0
}

func (mr *MockStoreMockRecorder) UpdateLDAPSyncRun(ctx, run any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateLDAPSyncRun", reflect.TypeOf((*MockStore)(nil).UpdateLDAPSyncRun), ctx, run)
}

func (m *MockStore) UpdateLDAPSyncRunOwned(ctx context.Context, run *ldapsyncmodel.Run, leaseOwner string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateLDAPSyncRunOwned", ctx, run, leaseOwner)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStoreMockRecorder) UpdateLDAPSyncRunOwned(ctx, run, leaseOwner any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateLDAPSyncRunOwned", reflect.TypeOf((*MockStore)(nil).UpdateLDAPSyncRunOwned), ctx, run, leaseOwner)
}

func (m *MockStore) GetLDAPSyncObjects(ctx context.Context, accountID, connectorID, objectType string) ([]*ldapsyncmodel.Object, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLDAPSyncObjects", ctx, accountID, connectorID, objectType)
	ret0, _ := ret[0].([]*ldapsyncmodel.Object)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStoreMockRecorder) GetLDAPSyncObjects(ctx, accountID, connectorID, objectType any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLDAPSyncObjects", reflect.TypeOf((*MockStore)(nil).GetLDAPSyncObjects), ctx, accountID, connectorID, objectType)
}

func (m *MockStore) SaveLDAPSyncObjects(ctx context.Context, objects []*ldapsyncmodel.Object) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveLDAPSyncObjects", ctx, objects)
	ret0, _ := ret[0].(error)
	return ret0
}

func (mr *MockStoreMockRecorder) SaveLDAPSyncObjects(ctx, objects any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveLDAPSyncObjects", reflect.TypeOf((*MockStore)(nil).SaveLDAPSyncObjects), ctx, objects)
}
