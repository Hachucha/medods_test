package stateless

import (
	"context"
	"log/slog"
)

type RefreshTokenCommand struct {
	AccessToken  AccessToken
	RefreshToken RefreshToken
	UserAgent    string
	IP           string
}

func (s *StatelessAuthService) RefreshTokens(ctx context.Context, cmd RefreshTokenCommand) (TokenPair, error) {
	accessTokenPayload, err := s.accessTokenAlgs.Validate(cmd.AccessToken)
	if err != nil && err != ErrAccessTokenExpired {
		return TokenPair{}, err
	}
	if accessTokenPayload.UserID == "" {
		return TokenPair{}, ErrAccessTokenInvalid
	}

	sessionData, err := s.authRepo.GetSession(ctx, accessTokenPayload.UserID, string(cmd.RefreshToken))
	if err != nil {
		s.logger.Error("Ошибка обновления токена", slog.Any("err", err), "useId:"+accessTokenPayload.UserID)
		return TokenPair{}, err
	}

	s.Logout(ctx, cmd.RefreshToken, accessTokenPayload.UserID)

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

	newTokenPairID, err := s.tokenPairIDGenerator.Generate()
	if err != nil {
		return TokenPair{}, err
	}

	sessionData.TokenPairID = TokenPairID(newTokenPairID)

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

	err = s.authRepo.SaveSession(ctx, sessionData)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}
