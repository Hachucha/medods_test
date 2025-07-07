package stateless

import (
	"context"
)

func (s *StatelessAuthService) Logout(ctx context.Context, RefreshToken RefreshToken, userId UserID) error {
	refreshHash, err := s.refreshTokenAlgs.GetHash(string(RefreshToken))
	if err != nil {
		return err
	}

	err = s.authRepo.DeleteSession(ctx, userId, refreshHash)
	if err != nil {
		return err
	}

	return nil
}
