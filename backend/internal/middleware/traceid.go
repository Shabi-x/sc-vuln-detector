package middleware

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"
)

const TraceIDHeader = "X-Trace-Id"

func TraceID() gin.HandlerFunc {
	return func(c *gin.Context) {
		tid := c.GetHeader(TraceIDHeader)
		if tid == "" {
			tid = newTraceID()
		}
		c.Set("traceId", tid)
		c.Header(TraceIDHeader, tid)
		c.Next()
	}
}

func newTraceID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

