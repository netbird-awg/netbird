package server

import (
	"context"
	"slices"

	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
)

func (am *DefaultAccountManager) onPeersInvalidated(ctx context.Context, accountID string, peerIDs []string) {
	peerIDs = slices.Clone(peerIDs)
	slices.Sort(peerIDs)
	peerIDs = slices.Compact(peerIDs)
	peerIDs = slices.DeleteFunc(peerIDs, func(peerID string) bool {
		return peerID == ""
	})
	if len(peerIDs) == 0 {
		return
	}

	log.WithContext(ctx).Debugf("revalidating peers %v for account %s", peerIDs, accountID)
	validPeers, _, err := am.GetValidatedPeers(ctx, accountID)
	if err != nil {
		// A configured validator must fail closed if its current state cannot be
		// evaluated. Closing the candidate streams forces a fresh validation
		// before they can receive another network map.
		log.WithContext(ctx).Errorf("failed to revalidate peers for account %s: %v", accountID, err)
		am.networkMapController.DisconnectPeers(ctx, accountID, peerIDs)
		return
	}

	changedPeerIDs := make([]string, 0, len(peerIDs))
	invalidPeerIDs := make([]string, 0, len(peerIDs))
	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peers, err := transaction.GetAccountPeers(
			ctx,
			store.LockingStrengthUpdate,
			accountID,
			"",
			"",
		)
		if err != nil {
			return err
		}
		peerByID := make(map[string]*nbpeer.Peer, len(peers))
		for _, peer := range peers {
			peerByID[peer.ID] = peer
		}
		for _, peerID := range peerIDs {
			peer, ok := peerByID[peerID]
			if !ok {
				continue
			}
			_, valid := validPeers[peerID]
			requiresApproval := !valid
			if peer.Status == nil {
				peer.Status = &nbpeer.PeerStatus{}
			}
			if peer.Status.RequiresApproval == requiresApproval {
				continue
			}
			peer.Status.RequiresApproval = requiresApproval
			if err := transaction.SavePeerStatus(ctx, accountID, peerID, *peer.Status); err != nil {
				return err
			}
			changedPeerIDs = append(changedPeerIDs, peerID)
			if requiresApproval {
				invalidPeerIDs = append(invalidPeerIDs, peerID)
			}
		}
		if len(changedPeerIDs) == 0 {
			return nil
		}
		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to persist EDR peer changes in account %s: %v", accountID, err)
		am.networkMapController.DisconnectPeers(ctx, accountID, peerIDs)
		return
	}
	if len(changedPeerIDs) == 0 {
		return
	}

	affectedPeerIDs := am.resolveAffectedPeersForPeerChanges(ctx, am.Store, accountID, changedPeerIDs)
	if err := am.networkMapController.OnPeersUpdated(ctx, accountID, changedPeerIDs, affectedPeerIDs); err != nil {
		log.WithContext(ctx).Errorf("failed to update EDR peer network maps for account %s: %v", accountID, err)
	}

	// EDR compliance is an access decision, not an SSO session-expiration
	// decision. Disconnect invalid peers of every enrollment type so reconnects
	// are re-evaluated, while compliant or bypassed peers retain their sessions.
	am.networkMapController.DisconnectPeers(ctx, accountID, invalidPeerIDs)
}
