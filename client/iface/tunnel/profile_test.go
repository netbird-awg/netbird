package tunnel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeProfile(t *testing.T) {
	parameters := validParameters()
	raw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}

	profile, err := DecodeProfile(ProtocolAmneziaWG2, 7, raw)
	if err != nil {
		t.Fatalf("decode valid profile: %v", err)
	}
	if profile.Revision != 7 {
		t.Fatalf("expected revision 7, got %d", profile.Revision)
	}
}

func TestDecodeProfileRejectsUAPIInjection(t *testing.T) {
	parameters := validParameters()
	parameters.IPacket1 = "<r 8>\nprivate_key=00"
	raw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DecodeProfile(ProtocolAmneziaWG2, 1, raw); err == nil {
		t.Fatal("profile containing a UAPI line break was accepted")
	}
}

func TestDecodeProfileRejectsUnknownFields(t *testing.T) {
	raw := []byte(`{
		"jc":0,"jmin":0,"jmax":0,
		"s1":0,"s2":0,"s3":0,"s4":0,
		"h1":"101","h2":"102","h3":"103","h4":"104",
		"unexpected":true
	}`)

	if _, err := DecodeProfile(ProtocolAmneziaWG2, 1, raw); err == nil {
		t.Fatal("profile with an unknown field was accepted")
	}
}

func TestValidateRejectsOverlappingHeaders(t *testing.T) {
	parameters := validParameters()
	parameters.TransportHeader = "101-104"
	raw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DecodeProfile(ProtocolAmneziaWG2, 1, raw); err == nil {
		t.Fatal("profile with overlapping headers was accepted")
	}
}

func TestDecodeProfileRejectsOversizedInput(t *testing.T) {
	raw := []byte(`{"padding":"` +
		strings.Repeat("x", maxProfileParametersSize) +
		`"}`)

	if _, err := DecodeProfile(ProtocolAmneziaWG2, 1, raw); err == nil {
		t.Fatal("oversized profile was accepted")
	}
}

func validParameters() AWG2Parameters {
	return AWG2Parameters{
		InitiationHeader: "101",
		ResponseHeader:   "102",
		CookieHeader:     "103",
		TransportHeader:  "104",
	}
}
