package stateless

func (s *StatelessAuthService) Logout(RefreshToken RefreshToken, userId UserID) error {
	refreshHash, err := s.refreshTokenAlgs.GetHash(string(RefreshToken))
	if err != nil {
		return err
	}

	err = s.authRepo.DeleteSession(userId, refreshHash)
	if err != nil {
		return err
	}

	return nil
}
