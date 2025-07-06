package stateless

type AccessToken string

type RefreshToken string

type TokenPairID string

type AccessTokenPayload struct {
	UserID      UserID
	TokenPairID TokenPairID
	Role        UserRole
}

type SessionData struct {
	UserID      UserID
	TokenPairID TokenPairID
	RefreshHash string
	UserAgent   string
	IP          string
}

type TokenPair struct {
	AccessToken  AccessToken
	RefreshToken RefreshToken
}
