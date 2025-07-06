package guidgenerator

import (
	"github.com/google/uuid"
)

type GuidGenerator struct {
}

func (g GuidGenerator) Generate() (string, error) {
	return uuid.New().String(), nil
}