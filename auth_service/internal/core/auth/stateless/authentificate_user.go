package stateless

type UserID string

type UserRole string

type TestAuthCommand struct {
	UserId    UserID
	UserAgent string
	IP        string
}

func (s *StatelessAuthService) TestAuthenticateUser(cmd TestAuthCommand) (TokenPair, error) {
	userID := cmd.UserId
	str, err := s.tokenPairIDGenerator.Generate()
	tokenPairID := TokenPairID(str)

	if err != nil {
		return TokenPair{}, err
	}

	accessTokenPayload := AccessTokenPayload{
		UserID:      userID,
		TokenPairID: tokenPairID,
		Role:        UserRole("user"),
	}

	accessToken, err := s.accessTokenAlgs.Generate(accessTokenPayload)
	if err != nil {
		return TokenPair{}, err
	}

	refreshTokenStr, err := s.refreshTokenAlgs.Generate()
	refreshToken := RefreshToken(refreshTokenStr)
	if err != nil {
		return TokenPair{}, err
	}

	refreshTokenHash, err := s.refreshTokenAlgs.GetHash(string(refreshToken))
	if err != nil {
		return TokenPair{}, err
	}

	sessionData := SessionData{
		UserID:      userID,
		TokenPairID: accessTokenPayload.TokenPairID,
		RefreshHash: refreshTokenHash,
		UserAgent:   cmd.UserAgent,
		IP:          cmd.IP,
	}
	err = s.authRepo.SaveSession(sessionData)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
