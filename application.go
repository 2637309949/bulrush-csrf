// Copyright (c) 2018-2020 Double All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package csrf

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type (
	// CSRF defined
	CSRF struct {
		Secret string
		Cookie string
	}
)

var ignore = map[string]bool{
	"HEAD":    true,
	"OPTIONS": true,
}

// Plugin for Limit
func (l *CSRF) Plugin(router *gin.RouterGroup) {
	router.Use(func(ctx *gin.Context) {
		if _, ok := ignore[ctx.Request.Method]; ok {
			ctx.Next()
			return
		}
		if ctx.Request.Method == "GET" {
			l.create(ctx)
		} else {
			l.verify(ctx)
		}
	})
}

func (l *CSRF) create(ctx *gin.Context) {
	token, err := ctx.Cookie(l.Cookie)
	if err != nil {
		ctx.Next()
		return
	}
	ctx.Set("csrf", hasha(fmt.Sprintf("%s.%s", token, l.Secret)))
	ctx.Next()
}

func (l *CSRF) verify(ctx *gin.Context) {
	token, err := ctx.Cookie(l.Cookie)
	if err != nil {
		ctx.String(http.StatusForbidden, "failed csrf check, no cookie value found")
		return
	}

	// get the CSRF token
	csrf := _csrf(ctx)
	if csrf == "" {
		ctx.String(http.StatusForbidden, "failed csrf check, no cookie value found")
	}

	hash := hasha(fmt.Sprintf("%s.%s", token, l.Secret))

	// verify CSRF token passed in matches the hash
	if hash == csrf {
		ctx.Next()
	} else {
		ctx.String(http.StatusForbidden, "invalid csrf token")
	}
}
