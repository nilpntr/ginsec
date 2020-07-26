package main

import (
	"github.com/asks8m/ginsec"
	"github.com/gin-gonic/gin"
	"log"
	"time"
)

func IdentityHandler(c *gin.Context) {
	claims := ginsec.ExtractClaims(c)
	c.JSON(200, gin.H{
		"claims": claims,
	})
}

func main() {
	var identityKey = "username"

	type User struct {
		Username string
	}

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

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	auth := r.Group("/auth")
	{
		auth.GET("/identity", middleware.MiddlewareFunc(), IdentityHandler)
	}

	r.Run()
}
