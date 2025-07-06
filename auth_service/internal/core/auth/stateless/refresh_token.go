package stateless

type RefreshTokenCommand struct {
	AccessToken  AccessToken
	RefreshToken RefreshToken
	UserAgent    string
	IP           string
}

func (s *StatelessAuthService) RefreshTokens(cmd RefreshTokenCommand) (TokenPair, error) {
	accessTokenPayload, err := s.accessTokenAlgs.Validate(cmd.AccessToken)
	if err != nil {
		return TokenPair{}, err
	}

	refreshHash, err := s.refreshTokenAlgs.GetHash(string(cmd.RefreshToken))
	if err != nil {
		return TokenPair{}, err
	}

	sessionData, err := s.authRepo.GetSession(accessTokenPayload.UserID, refreshHash)
	if err != nil {
		return TokenPair{}, err
	}

	if sessionData.UserAgent != cmd.UserAgent {
		return TokenPair{}, ErrUserAgentChanged
	}

	if sessionData.IP != cmd.IP {
		s.userIPChangedPublisher.Publish(UserIPChangedEvent{
			UserID: accessTokenPayload.UserID,
			OldIP:  sessionData.IP,
			NewIP:  cmd.IP,
		})
	}

	accessTokenPayload = AccessTokenPayload{
		UserID:      accessTokenPayload.UserID,
		TokenPairID: sessionData.TokenPairID,
		Role:        UserRole("user"),
	}

	newAccessToken, err := s.accessTokenAlgs.Generate(accessTokenPayload)
	if err != nil {
		return TokenPair{}, err
	}

	newRefreshTokenStr, err := s.refreshTokenAlgs.Generate()
	newRefreshToken := RefreshToken(newRefreshTokenStr)
	if err != nil {
		return TokenPair{}, err
	}

	newRefreshHash, err := s.refreshTokenAlgs.GetHash(string(newRefreshToken))
	if err != nil {
		return TokenPair{}, err
	}

	sessionData.RefreshHash = newRefreshHash

	err = s.authRepo.SaveSession(sessionData)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}
