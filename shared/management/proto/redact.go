package proto

// RedactTunnelProfileKeys clears tunnel profile header-protection keys from a
// sync response before it crosses a diagnostic or persistence boundary.
func RedactTunnelProfileKeys(response *SyncResponse) {
	if response == nil {
		return
	}

	redactTunnelProfileKey(response.GetPeerConfig())
	if networkMap := response.GetNetworkMap(); networkMap != nil {
		redactTunnelProfileKey(networkMap.GetPeerConfig())
	}
	if envelope := response.GetNetworkMapEnvelope(); envelope != nil {
		if full := envelope.GetFull(); full != nil {
			redactTunnelProfileKey(full.GetPeerConfig())
		}
	}
}

func redactTunnelProfileKey(peerConfig *PeerConfig) {
	if peerConfig == nil || peerConfig.TunnelProfile == nil {
		return
	}
	peerConfig.TunnelProfile.HeaderProtectionKey = nil
}
