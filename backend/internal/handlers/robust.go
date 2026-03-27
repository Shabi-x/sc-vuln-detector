package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
	"sc-vuln-detector/backend/internal/service"
)

type RobustHandlers struct {
	DB     *gorm.DB
	Robust *service.RobustService
}

func NewRobustHandlers(db *gorm.DB, robust *service.RobustService) *RobustHandlers {
	return &RobustHandlers{DB: db, Robust: robust}
}

type createRobustJobRequest struct {
	ModelID        string   `json:"modelId" binding:"required"`
	PromptID       string   `json:"promptId" binding:"required"`
	ContractIDs    []string `json:"contractIds" binding:"required"`
	Strategies     []string `json:"strategies"`
	VariantsPerSrc int      `json:"variantsPerSource"`
}

// GET /api/robust/jobs
func (h *RobustHandlers) ListJobs(c *gin.Context) {
	limit := 50
	var jobs []model.RobustJob
	if err := h.DB.Order("created_at desc").Limit(limit).Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "查询失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, jobs)
}

// POST /api/robust/evaluate
func (h *RobustHandlers) CreateJob(c *gin.Context) {
	if h.Robust == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": "鲁棒性服务未初始化"})
		return
	}
	var req createRobustJobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "参数错误", "error": err.Error()})
		return
	}
	job, err := h.Robust.CreateJob(c.Request.Context(), service.RobustEvaluateRequest{
		ModelID:        strings.TrimSpace(req.ModelID),
		PromptID:       strings.TrimSpace(req.PromptID),
		ContractIDs:    req.ContractIDs,
		Strategies:     req.Strategies,
		VariantsPerSrc: req.VariantsPerSrc,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "创建鲁棒性任务失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, job)
}

// GET /api/robust/jobs/:id
func (h *RobustHandlers) GetJob(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	var job model.RobustJob
	if err := h.DB.First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"message": "任务不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": "查询失败", "error": err.Error()})
		return
	}

	var metrics map[string]any
	if job.MetricsJSON != "" {
		_ = json.Unmarshal([]byte(job.MetricsJSON), &metrics)
	}

	c.JSON(http.StatusOK, gin.H{
		"job":     job,
		"metrics": metrics,
	})
}
