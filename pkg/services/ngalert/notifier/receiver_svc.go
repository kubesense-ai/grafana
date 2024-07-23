package notifier

import (
	"context"
	"encoding/base64"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/secrets"
)

// ReceiverService is the service for managing alertmanager receivers.
type ReceiverService struct {
	authz             receiverAccessControlService
	receiverStore     receiverStore
	encryptionService secrets.Service
	log               log.Logger
}

// receiverAccessControlService provides access control for receivers.
type receiverAccessControlService interface {
	HasList(ctx context.Context, user identity.Requester) (bool, error)
	HasReadAll(ctx context.Context, user identity.Requester) (bool, error)
	AuthorizeReadDecryptedAll(ctx context.Context, user identity.Requester) error
}

type receiverStore interface {
	GetReceiver(ctx context.Context, orgID int64, uid string) (*models.Receiver, error)
	GetReceivers(ctx context.Context, orgID int64, uids ...string) ([]*models.Receiver, error)
	DeleteReceiver(ctx context.Context, orgID int64, uid string, callerProvenance models.Provenance, version string) error
}

func NewReceiverService(
	authz receiverAccessControlService,
	receiverStore receiverStore,
	encryptionService secrets.Service,
	log log.Logger,
) *ReceiverService {
	return &ReceiverService{
		authz:             authz,
		encryptionService: encryptionService,
		log:               log,
		receiverStore:     receiverStore,
	}
}

func (rs *ReceiverService) shouldDecrypt(ctx context.Context, user identity.Requester, reqDecrypt bool) (bool, error) {
	if !reqDecrypt {
		return false, nil
	}
	if err := rs.authz.AuthorizeReadDecryptedAll(ctx, user); err != nil {
		return false, err
	}

	return true, nil
}

// GetReceiver returns a receiver by name.
// The receiver's secure settings are decrypted if requested and the user has access to do so.
func (rs *ReceiverService) GetReceiver(ctx context.Context, q models.GetReceiverQuery, user identity.Requester) (definitions.GettableApiReceiver, error) {
	rcv, err := rs.receiverStore.GetReceiver(ctx, q.OrgID, models.GetUID(q.Name))
	if err != nil {
		return definitions.GettableApiReceiver{}, err
	}

	decrypt, err := rs.shouldDecrypt(ctx, user, q.Decrypt)
	if err != nil {
		return definitions.GettableApiReceiver{}, err
	}
	decryptFn := rs.decryptOrRedact(ctx, decrypt, q.Name, "")

	return ReceiverToGettable(rcv, decryptFn, false)
}

// GetReceivers returns a list of receivers a user has access to.
// Receivers can be filtered by name, and secure settings are decrypted if requested and the user has access to do so.
func (rs *ReceiverService) GetReceivers(ctx context.Context, q models.GetReceiversQuery, user identity.Requester) ([]definitions.GettableApiReceiver, error) {
	uids := make([]string, 0, len(q.Names))
	for _, name := range q.Names {
		uids = append(uids, models.GetUID(name))
	}

	receivers, err := rs.receiverStore.GetReceivers(ctx, q.OrgID, uids...)
	if err != nil {
		return nil, err
	}

	decrypt, err := rs.shouldDecrypt(ctx, user, q.Decrypt)
	if err != nil {
		return nil, err
	}

	readRedactedAccess, err := rs.authz.HasReadAll(ctx, user)
	if err != nil {
		return nil, err
	}

	listAccess, err := rs.authz.HasList(ctx, user)
	if err != nil {
		return nil, err
	}

	// User doesn't have any permissions on the receivers.
	// This is mostly a safeguard as it should not be possible with current API endpoints + middleware authentication.
	if !listAccess && !readRedactedAccess {
		return nil, nil
	}

	var output []definitions.GettableApiReceiver
	for i := q.Offset; i < len(receivers); i++ {
		r := receivers[i]

		decryptFn := rs.decryptOrRedact(ctx, decrypt, r.Name, "")

		// Only has permission to list. This reduces from:
		// - Has List permission
		// - Doesn't have ReadRedacted (or ReadDecrypted permission since it's a subset).
		listOnly := !readRedactedAccess

		res, err := ReceiverToGettable(r, decryptFn, listOnly)
		if err != nil {
			return nil, err
		}

		output = append(output, res)
		// stop if we have reached the limit or we have found all the requested receivers
		if (len(output) == q.Limit && q.Limit > 0) || (len(output) == len(q.Names)) {
			break
		}
	}

	return output, nil
}

// DeleteReceiver deletes a receiver by uid.
// UID field currently does not exist, we assume the uid is a particular hashed value of the receiver name.
func (rs *ReceiverService) DeleteReceiver(ctx context.Context, uid string, orgID int64, callerProvenance definitions.Provenance, version string) error {
	//TODO: Check delete permissions.
	return rs.receiverStore.DeleteReceiver(ctx, orgID, uid, models.Provenance(callerProvenance), version)
}

func (rs *ReceiverService) CreateReceiver(ctx context.Context, r definitions.GettableApiReceiver, orgID int64) (definitions.GettableApiReceiver, error) {
	// TODO: Stub
	panic("not implemented")
}

func (rs *ReceiverService) UpdateReceiver(ctx context.Context, r definitions.GettableApiReceiver, orgID int64) (definitions.GettableApiReceiver, error) {
	// TODO: Stub
	panic("not implemented")
}

func (rs *ReceiverService) decryptOrRedact(ctx context.Context, decrypt bool, name, fallback string) func(value string) string {
	return func(value string) string {
		if !decrypt {
			return definitions.RedactedValue
		}

		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			rs.log.Warn("failed to decode secure setting", "name", name, "error", err)
			return fallback
		}
		decrypted, err := rs.encryptionService.Decrypt(ctx, decoded)
		if err != nil {
			rs.log.Warn("failed to decrypt secure setting", "name", name, "error", err)
			return fallback
		}
		return string(decrypted)
	}
}
