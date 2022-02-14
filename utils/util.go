package utils

import (
	"math/rand"
	"strings"

	"github.com/google/uuid"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// GenerateRandomString generate a string of random characters of given length
func GenerateRandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	for i := 0; i < n; i++ {
		idx := rand.Int63() % int64(len(letterBytes))
		sb.WriteByte(letterBytes[idx])
	}
	return sb.String()
}

func GenerateUUID() string {
	id := uuid.New()

	return id.String()
}
