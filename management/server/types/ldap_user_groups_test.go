package types

import (
	"reflect"
	"testing"
)

func TestNormalizeLDAPUserGroups(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		want   []string
	}{
		{
			name: "adds default to empty input",
			want: []string{DefaultLDAPUserGroup},
		},
		{
			name:   "keeps default first and removes duplicates",
			groups: []string{"ops", "netbird", "OPS", "developers", " "},
			want:   []string{"netbird", "ops", "developers"},
		},
		{
			name:   "normalizes a differently cased default",
			groups: []string{" NETBIRD ", "Ops"},
			want:   []string{"netbird", "Ops"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeLDAPUserGroups(tt.groups)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("NormalizeLDAPUserGroups() = %v, want %v", got, tt.want)
			}
		})
	}
}
