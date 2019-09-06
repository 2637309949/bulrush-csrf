// Copyright (c) 2018-2020 Double All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package csrf

import (
	"crypto/sha1"
	"fmt"

	"github.com/2637309949/bulrush-utils/funcs"
	"github.com/gin-gonic/gin"
)

func hasha(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func _csrf(c *gin.Context) string {
	return funcs.Until(
		c.PostForm("_csrf"),
		c.Query("_csrf"),
		c.Request.Header.Get("x-xsrf-token"),
		func() interface{} {
			value, _ := c.Cookie("x-xsrf-token")
			return value
		},
	).(string)
}
