package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
	"sc-vuln-detector/backend/internal/service"
)

type TrainHandlers struct {
	DB      *gorm.DB
	Trainer *service.Trainer
}

func NewTrainHandlers(db *gorm.DB, trainer *service.Trainer) *TrainHandlers {
	return &TrainHandlers{DB: db, Trainer: trainer}
}

type createTrainJobRequest struct {
	PromptID    string                 `json:"promptId" binding:"required"`
	FewshotSize int                    `json:"fewshotSize" binding:"required"`
	DatasetRef  string                 `json:"datasetRef"`
	Params      map[string]interface{} `json:"params"`
}

// POST /api/train/jobs
func (h *TrainHandlers) CreateJob(c *gin.Context) {
	if h.Trainer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"message": "训练服务未初始化",
		})
		return
	}

	var req createTrainJobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "参数错误",
			"error":   err.Error(),
		})
		return
	}

	job, err := h.Trainer.CreateJob(c.Request.Context(), service.TrainRequest{
		PromptID:    req.PromptID,
		FewshotSize: req.FewshotSize,
		Params:      req.Params,
		DatasetRef:  req.DatasetRef,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "创建训练任务失败",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, job)
}

// GET /api/train/jobs/:id
func (h *TrainHandlers) GetJob(c *gin.Context) {
	id := c.Param("id")
	var job model.TrainJob
	if err := h.DB.First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"message": "任务不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "查询失败", "error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, job)
}

// GET /api/train/jobs/:id/metrics
func (h *TrainHandlers) GetJobMetrics(c *gin.Context) {
	id := c.Param("id")
	limitStr := c.Query("limit")
	limit := 200
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	var metrics []model.TrainMetric
	if err := h.DB.
		Where("job_id = ?", id).
		Order("step asc").
		Limit(limit).
		Find(&metrics).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "查询失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, metrics)
}

// GET /api/models
func (h *TrainHandlers) ListModels(c *gin.Context) {
	var models []model.TrainedModel
	if err := h.DB.Order("created_at desc").Find(&models).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "查询失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, models)
}

// POST /api/models/:id/load
// 当前实现为：将指定模型标记为 is_loaded=true，其他模型标记为 false，供后续检测模块使用。
func (h *TrainHandlers) LoadModel(c *gin.Context) {
	id := c.Param("id")

	if err := h.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.TrainedModel{}).Where("is_loaded = ?", true).
			Update("is_loaded", false).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.TrainedModel{}).Where("id = ?", id).
			Update("is_loaded", true).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "加载模型失败", "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "loadedId": id})
}

// Helper: generate UUID when needed in future
func newID() string {
	return uuid.NewString()
}

