package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/ernestoaparicio/sso/pkg/ldap"
	"os"
	"strconv"
	"sync"
	"time"
)

type Service interface {
	Authenticate(ctx context.Context, u User) (Token, error)
}

var (
	ErrInconsistentIDs = errors.New("inconsistent IDs")
	ErrAlreadyExists   = errors.New("already exists")
	ErrNotFound        = errors.New("not found")
)

type User struct {
	MSID     string `json:"msid"`
	Password string `json:"password"`
}

type Token struct {
	JwtToken  string    `json:"jwttoken"`
	MSID      string    `json:"msid"`
	ExpiresAt time.Time `json:"expiresat"`
}

type JWTCustomClaims struct {
	MSID     string        `json:"msId" bson:"msId"`
	LdapUser ldap.LDAPUser `json: "ldapUser" bson:"ldapUser"`
	jwt.StandardClaims
}

type service struct {
	mtx sync.RWMutex
	u   map[string]User
}

func NewService() Service {
	return &service{
		u: map[string]User{},
	}
}

func (s *service) Authenticate(ctx context.Context, u User) (Token, error) {
	// Get from env vars
	expiresHours, err := strconv.Atoi(os.Getenv("TOKEN_EXPIRATION_HOURS"))
	if err != nil {
		return Token{}, err
	}

	fmt.Printf("checkpoint a, user %v", u)

	// Validate username/password against AD
	user, err := ldap.AuthenticateLDAP(u.MSID, u.Password)
	if err != nil {
		return Token{}, err
	}

	// todo implement reducer of memberOf array
	// Reduce memberOf
	//reduceMemberOf(user.MemberOf)

	// Set JWT claims
	claims := JWTCustomClaims{
		u.MSID,
		*user,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(expiresHours)).Unix(),
			Issuer:    "SSO API",
		},
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

	if err != nil {
		return Token{}, err
	}

	// Create auth token
	authToken := Token{
		JwtToken:  tokenString,
		MSID:      u.MSID,
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(expiresHours)),
	}

	return authToken, nil
}
