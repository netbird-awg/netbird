package tunnel

import (
	"bytes"
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

func TestDecodeAWG3Profile(t *testing.T) {
	parameters := validParameters()
	parameters.InitiationPadding = headerProtectionNonceSize
	parameters.ResponsePadding = headerProtectionNonceSize
	parameters.CookiePadding = headerProtectionNonceSize
	parameters.TransportPadding = headerProtectionNonceSize
	raw, err := json.Marshal(awg3WireParameters{
		AWG2Parameters: parameters,
		AWG3Parameters: AWG3Parameters{
			ContentPaddingAddition:      "1-32",
			PersistentKeepaliveInterval: "20-30",
			RekeyAfterTime:              "120-180",
			MaxHandshakeAttempts:        "5-10",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x37}, headerProtectionKeySize)

	profile, err := DecodeProfileWithHeaderKey(
		ProtocolAmneziaWG3,
		8,
		raw,
		key,
	)
	if err != nil {
		t.Fatalf("decode valid AWG3 profile: %v", err)
	}
	if !profile.SupportsMode(ModeAmneziaWG2) ||
		!profile.SupportsMode(ModeAmneziaWG3) {
		t.Fatal("AWG3 profile does not support both AWG modes")
	}
}

func TestDecodeAWG3ProfileRejectsMissingHeaderKey(t *testing.T) {
	parameters := validParameters()
	parameters.InitiationPadding = headerProtectionNonceSize
	parameters.ResponsePadding = headerProtectionNonceSize
	parameters.CookiePadding = headerProtectionNonceSize
	parameters.TransportPadding = headerProtectionNonceSize
	raw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DecodeProfile(
		ProtocolAmneziaWG3,
		1,
		raw,
	); err == nil {
		t.Fatal("AWG3 profile without a header key was accepted")
	}
}

func TestDecodeAWG2ProfileRejectsAWG3Parameters(t *testing.T) {
	parameters := validParameters()
	raw, err := json.Marshal(awg3WireParameters{
		AWG2Parameters: parameters,
		AWG3Parameters: AWG3Parameters{
			ContentPaddingAddition: "1-32",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DecodeProfile(ProtocolAmneziaWG2, 1, raw); err == nil {
		t.Fatal("AWG2 profile with AWG3 parameters was accepted")
	}
}

func TestDecodeAWG2ProfileRejectsAWG3HeaderKey(t *testing.T) {
	parameters := validParameters()
	raw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DecodeProfileWithHeaderKey(
		ProtocolAmneziaWG2,
		1,
		raw,
		bytes.Repeat([]byte{0x37}, headerProtectionKeySize),
	); err == nil {
		t.Fatal("AWG2 profile with an AWG3 header key was accepted")
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
