package stateless

import (
	"log/slog"
	"context"
)

type AuthRepository interface {
	SaveSession(ctx context.Context, session SessionData) error
	DeleteSession(ctx context.Context, userID UserID, refreshHash string) error
	GetSession(ctx context.Context, userID UserID, refreshHash string) (SessionData, error)
}

type AccessTokenAlgoHelper interface {
	Generate(user AccessTokenPayload) (AccessToken, error)
	Validate(token AccessToken) (AccessTokenPayload, error)
}

type RefreshTokenAlgoHelper interface {
	Generate() (string, error)
	GetHash(token string) (string, error)
}

type StringIdGenerator interface {
	Generate() (string, error)
}

type UserIPChangedPublisher interface {
	Publish(event UserIPChangedEvent)
}

type StatelessAuthService struct {
	authRepo               AuthRepository
	accessTokenAlgs        AccessTokenAlgoHelper
	refreshTokenAlgs       RefreshTokenAlgoHelper
	tokenPairIDGenerator   StringIdGenerator
	logger                 *slog.Logger
	userIPChangedPublisher UserIPChangedPublisher
}

func NewStatelessAuthService(
	authRepo AuthRepository,
	accessTokenAlgs AccessTokenAlgoHelper,
	refreshTokenAlgs RefreshTokenAlgoHelper,
	tokenPairIDGenerator StringIdGenerator,
	userIPChangedPublisher UserIPChangedPublisher,
	logger *slog.Logger) *StatelessAuthService {
	return &StatelessAuthService{
		authRepo:               authRepo,
		accessTokenAlgs:        accessTokenAlgs,
		refreshTokenAlgs:       refreshTokenAlgs,
		tokenPairIDGenerator:   tokenPairIDGenerator,
		logger:                 logger,
		userIPChangedPublisher: userIPChangedPublisher,
	}
}
