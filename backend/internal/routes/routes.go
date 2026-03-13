package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/handlers"
	"sc-vuln-detector/backend/internal/service"
)

func Register(r *gin.Engine, gdb *gorm.DB) {
	api := r.Group("/api")
	{
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		})

		if gdb != nil {
			contracts := api.Group("/contracts")
			{
				ch := handlers.NewContractHandlers(gdb)
				contracts.POST("/preprocess", ch.PreprocessContract)
				contracts.GET("", ch.ListContracts)
				contracts.GET("/:id", ch.GetContract)
				contracts.DELETE("/:id", ch.DeleteContract)
			}

			trainer := service.NewTrainer(gdb)

			prompts := api.Group("/prompts")
			{
				h := handlers.NewPromptHandlers(gdb)
				prompts.GET("", h.ListPrompts)
				prompts.POST("", h.CreatePrompt)
				prompts.PUT("/:id", h.UpdatePrompt)
				prompts.DELETE("/:id", h.DeletePrompt)
			}

			mappings := api.Group("/prompt-mappings")
			{
				h := handlers.NewPromptHandlers(gdb)
				mappings.GET("", h.ListMappings)
				mappings.POST("", h.CreateMapping)
				mappings.PUT("/:id", h.UpdateMapping)
				mappings.DELETE("/:id", h.DeleteMapping)
			}

			train := api.Group("/train")
			{
				h := handlers.NewTrainHandlers(gdb, trainer)
				train.POST("/jobs", h.CreateJob)
				train.GET("/jobs/:id", h.GetJob)
				train.GET("/jobs/:id/metrics", h.GetJobMetrics)
			}

			models := api.Group("/models")
			{
				h := handlers.NewTrainHandlers(gdb, trainer)
				models.GET("", h.ListModels)
				models.POST("/:id/load", h.LoadModel)
			}
		} else {
			contracts := api.Group("/contracts")
			{
				ch := handlers.NewContractHandlers(nil)
				contracts.POST("/preprocess", ch.PreprocessContract)
			}

			api.Any("/prompts", func(c *gin.Context) {
				c.JSON(http.StatusServiceUnavailable, gin.H{"message": "数据库未初始化"})
			})
			api.Any("/prompts/*any", func(c *gin.Context) {
				c.JSON(http.StatusServiceUnavailable, gin.H{"message": "数据库未初始化"})
			})
			api.Any("/prompt-mappings", func(c *gin.Context) {
				c.JSON(http.StatusServiceUnavailable, gin.H{"message": "数据库未初始化"})
			})
			api.Any("/prompt-mappings/*any", func(c *gin.Context) {
				c.JSON(http.StatusServiceUnavailable, gin.H{"message": "数据库未初始化"})
			})
		}
	}
}

