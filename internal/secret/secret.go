package secret

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func GetToken(userId int, expiration time.Duration, secret string) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:   "chirpy",
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Subject:  fmt.Sprintf("%d", userId),
	}
	signingMethod := jwt.SigningMethodHS256
	hoursInSeconds := 24 * 3600 * time.Second

	if expiration == 0 || expiration >= hoursInSeconds {
		expiration = hoursInSeconds
	}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().UTC().Add(expiration))

	return jwt.NewWithClaims(signingMethod, claims).SignedString([]byte(secret))
}

func GetRefreshToken() (string, error) {
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randomData), nil
}
