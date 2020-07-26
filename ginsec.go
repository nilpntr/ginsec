package ginsec

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"time"
)

// Default user claims
type MapClaims map[string]interface{}

// The Gin-JWT-Go middleware
type GinJWTMiddleware struct {
	// Realm name of the realm. Required.
	Realm string

	// Key secret key used to sign the jwt token. Required.
	Key []byte

	// Timeout expiration of the jwt token. Default is 1 hour.
	Timeout time.Duration

	// RefreshTimeout expiration of the refresh token. Default is 2 hours.
	RefreshTimeout time.Duration

	// IdentityKey set the identity key. Required.
	IdentityKey string

	// IdentityHandler set the identity handler function. Required.
	IdentityHandler func(*gin.Context) interface{}

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(data interface{}, c *gin.Context) bool

	// Unauthorized allow users to define a response. Optional.
	Unauthorized func(*gin.Context, int, string)

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via c.Get("JWT_PAYLOAD").
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(data interface{}) MapClaims

	// CookieName
	CookieName string

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "cookie:<name>"
	TokenLookup string
}

// Some constants used across GinSec.
const (
	SigningAlgorithm = "HS256"
	TokenHeadName    = "Bearer"
	AuthHeaderName   = "Authorization"
)

// Errors
var (
	ErrKeyEmpty             = errors.New("key cannot be empty")
	ErrIdentityHandlerEmpty = errors.New("idenity handler cannot be empty")
	ErrIdentityKeyEmpty     = errors.New("identity key cannot be empty")
	ErrEmptyAuthHeader      = errors.New("authentication header cannot be empty")
	ErrEmptyCookieToken     = errors.New("cookie cannot be empty")
	ErrInvalidAuthHeader    = errors.New("invalid authentication header")
	ErrMissingExpField      = errors.New("missing exp field")
	ErrWrongFormatOfExp     = errors.New("wrong exp field format")
	ErrExpiredToken         = errors.New("token expired")
	ErrForbidden            = errors.New("you don't have permission to access this resource")
	ErrClaimsIncorrect      = errors.New("you're claims are incorrect")
)

func New(mw *GinJWTMiddleware) (*GinJWTMiddleware, error) {
	if err := mw.MiddlewareInit(); err != nil {
		return nil, err
	}
	return mw, nil
}

func (mw *GinJWTMiddleware) MiddlewareInit() error {
	if mw.Key == nil {
		return ErrKeyEmpty
	}

	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.Realm == "" {
		mw.Realm = "GinSec"
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.RefreshTimeout == 0 {
		mw.RefreshTimeout = time.Hour * 2
	}

	if mw.IdentityKey == "" {
		return ErrIdentityKeyEmpty
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(data interface{}, c *gin.Context) bool {
			return true
		}
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		}
	}

	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}

	if mw.IdentityHandler == nil {
		return ErrIdentityHandlerEmpty
	}

	return nil
}

func (mw *GinJWTMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		mw.middlewareImpl(c)
	}
}

func (mw *GinJWTMiddleware) middlewareImpl(c *gin.Context) {
	claims, err := mw.GetClaimsFromJWT(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	if claims["exp"] == nil {
		mw.unauthorized(c, http.StatusBadRequest, ErrMissingExpField.Error())
		return
	}

	if _, ok := claims["exp"].(float64); !ok {
		mw.unauthorized(c, http.StatusBadRequest, ErrWrongFormatOfExp.Error())
		return
	}

	if int64(claims["exp"].(float64)) < time.Now().Unix() {
		mw.unauthorized(c, http.StatusUnauthorized, ErrExpiredToken.Error())
		return
	}

	c.Set("JWT_PAYLOAD", claims)
	identity := mw.IdentityHandler(c)

	if identity != nil {
		c.Set(mw.IdentityKey, identity)
	}

	if !mw.Authorizator(identity, c) {
		mw.unauthorized(c, http.StatusUnauthorized, ErrClaimsIncorrect.Error())
		return
	}

	c.Next()
}

func (mw *GinJWTMiddleware) GetClaimsFromJWT(c *gin.Context) (MapClaims, error) {
	token, err := mw.ParseToken(c)

	if err != nil {
		return nil, err
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

func (mw *GinJWTMiddleware) ParseToken(c *gin.Context) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(mw.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = mw.jwtFromHeader(c, v)
		case "cookie":
			token, err = mw.jwtFromCookie(c, v)
		}
	}

	if err != nil {
		return nil, err
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// save token string if valid
		c.Set("JWT_TOKEN", token)

		return mw.Key, nil
	})
}

func (mw *GinJWTMiddleware) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (mw *GinJWTMiddleware) jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (mw *GinJWTMiddleware) TokenGenerator(data interface{}) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := time.Now().UTC().Add(mw.Timeout)
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = time.Now().Unix()
	tokenString, err := mw.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire, nil
}

func (mw *GinJWTMiddleware) RefreshTokenGenerator(data interface{}) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := time.Now().UTC().Add(mw.RefreshTimeout)
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = time.Now().Unix()
	tokenString, err := mw.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire, nil
}

func (mw *GinJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	tokenString, err := token.SignedString(mw.Key)

	return tokenString, err
}

func (mw *GinJWTMiddleware) unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+mw.Realm)
	mw.Unauthorized(c, code, message)
}

func ExtractClaimsFromToken(token *jwt.Token) MapClaims {
	if token == nil {
		return make(MapClaims)
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims
}

func GetToken(c *gin.Context) string {
	token, exists := c.Get("JWT_TOKEN")
	if !exists {
		return ""
	}

	return token.(string)
}

func ExtractClaims(c *gin.Context) MapClaims {
	claims, exists := c.Get("JWT_PAYLOAD")
	if !exists {
		return make(MapClaims)
	}

	return claims.(MapClaims)
}

func (mw *GinJWTMiddleware) ParseTokenString(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return mw.Key, nil
	})
}
