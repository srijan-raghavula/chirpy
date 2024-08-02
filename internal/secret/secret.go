package secret

import (
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

	if expiration >= hoursInSeconds {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().UTC().Add(hoursInSeconds))
	} else if expiration >= 0 && expiration < hoursInSeconds {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(expiration))
	}

	return jwt.NewWithClaims(signingMethod, claims).SignedString([]byte(secret))
}
