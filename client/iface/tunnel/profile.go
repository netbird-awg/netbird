package tunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	ProtocolAmneziaWG2 = "awg2"
	AdapterRevision    = "2ae1edae71cfa2d5a3265e3d8e316f0a5914944f"

	maxProfileParametersSize = 32 * 1024
	maxJunkPacketCount       = 32
	maxJunkPacketSize        = 1280
	maxHandshakePadding      = 64
	maxTransportPadding      = 32
	maxIPacketSpecLength     = 4096
	maxIPacketTags           = 32
)

// Mode identifies the on-wire tunnel format selected for a peer.
type Mode uint8

const (
	ModeStandard Mode = iota
	ModeAmneziaWG
)

// String returns the UAPI representation of the tunnel mode.
func (m Mode) String() string {
	switch m {
	case ModeStandard:
		return "standard"
	case ModeAmneziaWG:
		return "amneziawg"
	default:
		return "unknown"
	}
}

// AWG2Parameters contains the bounded AmneziaWG v2 profile parameters.
type AWG2Parameters struct {
	JunkPacketCount int `json:"jc"`
	JunkPacketMin   int `json:"jmin"`
	JunkPacketMax   int `json:"jmax"`

	InitiationPadding int `json:"s1"`
	ResponsePadding   int `json:"s2"`
	CookiePadding     int `json:"s3"`
	TransportPadding  int `json:"s4"`

	InitiationHeader string `json:"h1"`
	ResponseHeader   string `json:"h2"`
	CookieHeader     string `json:"h3"`
	TransportHeader  string `json:"h4"`

	IPacket1 string `json:"i1,omitempty"`
	IPacket2 string `json:"i2,omitempty"`
	IPacket3 string `json:"i3,omitempty"`
	IPacket4 string `json:"i4,omitempty"`
	IPacket5 string `json:"i5,omitempty"`
}

// Profile is the validated userspace tunnel profile assigned by Management.
type Profile struct {
	ProtocolVersion string
	Revision        uint64
	AWG2            AWG2Parameters
}

// Equal reports whether two profiles describe the same immutable revision.
func (p *Profile) Equal(other *Profile) bool {
	if p == nil || other == nil {
		return p == other
	}
	return p.ProtocolVersion == other.ProtocolVersion &&
		p.Revision == other.Revision &&
		p.AWG2 == other.AWG2
}

// DecodeProfile decodes and validates an assigned tunnel profile.
func DecodeProfile(protocolVersion string, revision uint64, parameters []byte) (*Profile, error) {
	if len(parameters) == 0 {
		return nil, errors.New("tunnel profile parameters are empty")
	}
	if len(parameters) > maxProfileParametersSize {
		return nil, fmt.Errorf(
			"tunnel profile parameters exceed %d bytes",
			maxProfileParametersSize,
		)
	}
	if protocolVersion != ProtocolAmneziaWG2 {
		return nil, fmt.Errorf("unsupported tunnel protocol %q", protocolVersion)
	}

	var awg2 AWG2Parameters
	decoder := json.NewDecoder(bytes.NewReader(parameters))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&awg2); err != nil {
		return nil, fmt.Errorf("decode AWG2 parameters: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}

	profile := &Profile{
		ProtocolVersion: protocolVersion,
		Revision:        revision,
		AWG2:            awg2,
	}
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	return profile, nil
}

// Validate checks all profile inputs before they reach the WireGuard UAPI.
func (p *Profile) Validate() error {
	if p == nil {
		return errors.New("tunnel profile is nil")
	}
	if p.ProtocolVersion != ProtocolAmneziaWG2 {
		return fmt.Errorf("unsupported tunnel protocol %q", p.ProtocolVersion)
	}
	if p.Revision == 0 {
		return errors.New("tunnel profile revision must be positive")
	}
	if err := validateJunk(p.AWG2); err != nil {
		return err
	}
	if err := validatePadding(p.AWG2); err != nil {
		return err
	}
	if err := validateHeaders(p.AWG2); err != nil {
		return err
	}
	return validateIPackets(p.AWG2)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("tunnel profile contains trailing JSON")
		}
		return fmt.Errorf("decode trailing tunnel profile data: %w", err)
	}
	return nil
}

func validateJunk(parameters AWG2Parameters) error {
	if parameters.JunkPacketCount < 0 ||
		parameters.JunkPacketCount > maxJunkPacketCount {
		return fmt.Errorf("jc must be between 0 and %d", maxJunkPacketCount)
	}
	if parameters.JunkPacketCount == 0 &&
		parameters.JunkPacketMin == 0 &&
		parameters.JunkPacketMax == 0 {
		return nil
	}
	if parameters.JunkPacketMin <= 0 {
		return errors.New("jmin must be positive")
	}
	if parameters.JunkPacketMax < parameters.JunkPacketMin {
		return errors.New("jmax must not be smaller than jmin")
	}
	if parameters.JunkPacketMax > maxJunkPacketSize {
		return fmt.Errorf("jmax must not exceed %d", maxJunkPacketSize)
	}
	return nil
}

func validatePadding(parameters AWG2Parameters) error {
	handshake := []int{
		parameters.InitiationPadding,
		parameters.ResponsePadding,
		parameters.CookiePadding,
	}
	for i, padding := range handshake {
		if padding < 0 || padding > maxHandshakePadding {
			return fmt.Errorf(
				"s%d must be between 0 and %d",
				i+1,
				maxHandshakePadding,
			)
		}
	}
	if parameters.TransportPadding < 0 ||
		parameters.TransportPadding > maxTransportPadding {
		return fmt.Errorf(
			"s4 must be between 0 and %d",
			maxTransportPadding,
		)
	}
	return nil
}

type headerRange struct {
	start uint32
	end   uint32
}

func validateHeaders(parameters AWG2Parameters) error {
	specs := []string{
		parameters.InitiationHeader,
		parameters.ResponseHeader,
		parameters.CookieHeader,
		parameters.TransportHeader,
	}
	ranges := make([]headerRange, len(specs))
	for i, spec := range specs {
		parsed, err := parseHeaderRange(spec)
		if err != nil {
			return fmt.Errorf("parse h%d: %w", i+1, err)
		}
		if parsed.overlaps(headerRange{start: 1, end: 4}) {
			return fmt.Errorf("h%d overlaps standard WireGuard message types", i+1)
		}
		for j := 0; j < i; j++ {
			if parsed.overlaps(ranges[j]) {
				return fmt.Errorf("h%d overlaps h%d", i+1, j+1)
			}
		}
		ranges[i] = parsed
	}
	return nil
}

func parseHeaderRange(spec string) (headerRange, error) {
	if spec == "" || strings.ContainsAny(spec, "\r\n") {
		return headerRange{}, errors.New("header is empty or contains a line break")
	}
	parts := strings.Split(spec, "-")
	if len(parts) > 2 {
		return headerRange{}, errors.New("invalid range")
	}
	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return headerRange{}, fmt.Errorf("parse range start: %w", err)
	}
	end := start
	if len(parts) == 2 {
		end, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return headerRange{}, fmt.Errorf("parse range end: %w", err)
		}
	}
	if end < start {
		return headerRange{}, errors.New("range end is smaller than start")
	}
	return headerRange{start: uint32(start), end: uint32(end)}, nil
}

func (r headerRange) overlaps(other headerRange) bool {
	return r.start <= other.end && other.start <= r.end
}

func validateIPackets(parameters AWG2Parameters) error {
	specs := []string{
		parameters.IPacket1,
		parameters.IPacket2,
		parameters.IPacket3,
		parameters.IPacket4,
		parameters.IPacket5,
	}
	for i, spec := range specs {
		if spec == "" {
			continue
		}
		if strings.ContainsAny(spec, "\r\n") {
			return fmt.Errorf("i%d contains a line break", i+1)
		}
		if len(spec) > maxIPacketSpecLength {
			return fmt.Errorf("i%d exceeds %d bytes", i+1, maxIPacketSpecLength)
		}
		if strings.Count(spec, "<") > maxIPacketTags {
			return fmt.Errorf("i%d exceeds %d tags", i+1, maxIPacketTags)
		}
	}
	return nil
}
