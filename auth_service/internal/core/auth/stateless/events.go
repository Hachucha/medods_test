package stateless

type UserIPChangedEvent struct {
	UserID UserID
	OldIP  string
	NewIP  string
}
