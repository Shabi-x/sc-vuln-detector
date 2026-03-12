package httpserver

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/middleware"
	"sc-vuln-detector/backend/internal/routes"
)

func New(gdb *gorm.DB) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(middleware.TraceID())

	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"http://localhost:5173", "http://127.0.0.1:5173"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Trace-Id"},
		ExposeHeaders: []string{"X-Trace-Id"},
		MaxAge:       12 * time.Hour,
	}))

	routes.Register(r, gdb)

	return r
}
