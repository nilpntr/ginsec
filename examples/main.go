package main

import (
	"github.com/gin-gonic/gin"
	"github.com/nilpntr/ginsec"
	"log"
	"time"
)

type User struct {
	Username string
}

var (
	authMiddleware *ginsec.GinJWTMiddleware
	identityKey    = "username"
)

func IdentityHandler(c *gin.Context) {
	claims := ginsec.ExtractClaims(c)
	c.JSON(200, gin.H{
		"claims": claims,
	})
}

func TokenHandler(c *gin.Context) {
	data := User{Username: "gerard"}

	token, exp, err := authMiddleware.TokenGenerator(&data)
	if err != nil {
		c.String(500, err.Error())
		return
	}

	c.SetCookie("GINSEC-COOKIE-NAME", token, int(exp.Unix()-time.Now().Unix()), "/", "localhost", false, false)
	c.String(200, token)
}

func main() {
	middleware, err := ginsec.New(&ginsec.GinJWTMiddleware{
		Realm:          "GinSec",
		Key:            []byte("kaasje"),
		Timeout:        time.Hour,
		RefreshTimeout: time.Hour * 2,
		IdentityKey:    identityKey,
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := ginsec.ExtractClaims(c)
			return &User{
				Username: claims[identityKey].(string),
			}
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if v, ok := data.(*User); ok && v.Username == "gerard" {
				return true
			}
			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    code,
				"message": message,
			})
			return
		},
		PayloadFunc: func(data interface{}) ginsec.MapClaims {
			if v, ok := data.(*User); ok {
				return ginsec.MapClaims{
					identityKey: v.Username,
				}
			}
			return ginsec.MapClaims{}
		},
		CookieName:  "GINSEC-COOKIE-NAME",
		TokenLookup: "header: Authorization, cookie: GINSEC-COOKIE-NAME",
	})
	if err != nil {
		log.Fatal("Err: " + err.Error())
	}

	authMiddleware = middleware

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	auth := r.Group("/auth")
	{
		auth.GET("/identity", middleware.MiddlewareFunc(), IdentityHandler)
		auth.GET("/token", TokenHandler)
	}

	r.Run()
}
