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

type DetectHandlers struct {
	DB       *gorm.DB
	Detector *service.Detector
}

func NewDetectHandlers(db *gorm.DB, detector *service.Detector) *DetectHandlers {
	return &DetectHandlers{DB: db, Detector: detector}
}

type detectRequest struct {
	ContractID string `json:"contractId" binding:"required"`
	PromptID   string `json:"promptId" binding:"required"`
	ModelID    string `json:"modelId"`
}

// POST /api/detect
func (h *DetectHandlers) DetectOne(c *gin.Context) {
	if h.Detector == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": "检测服务未初始化"})
		return
	}
	var req detectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "参数错误", "error": err.Error()})
		return
	}
	out, modelID, err := h.Detector.DetectOne(c.Request.Context(), service.DetectRequest{
		ContractID: strings.TrimSpace(req.ContractID),
		PromptID:   strings.TrimSpace(req.PromptID),
		ModelID:    strings.TrimSpace(req.ModelID),
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "检测失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"modelId": modelID,
		"result":  out,
	})
}

type createDetectBatchJobRequest struct {
	ContractIDs []string `json:"contractIds" binding:"required"`
	PromptID    string   `json:"promptId" binding:"required"`
	ModelID     string   `json:"modelId"`
}

// POST /api/detect/batch
func (h *DetectHandlers) CreateBatchJob(c *gin.Context) {
	if h.Detector == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": "检测服务未初始化"})
		return
	}
	var req createDetectBatchJobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "参数错误", "error": err.Error()})
		return
	}
	job, err := h.Detector.CreateBatchJob(
		c.Request.Context(),
		strings.TrimSpace(req.PromptID),
		strings.TrimSpace(req.ModelID),
		req.ContractIDs,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "创建任务失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, job)
}

type detectResultDTO struct {
	ID           string               `json:"id"`
	JobID        string               `json:"jobId"`
	ContractID   string               `json:"contractId"`
	ModelID      string               `json:"modelId"`
	PromptID     string               `json:"promptId"`
	Label        model.Label          `json:"label"`
	Confidence   float64              `json:"confidence"`
	VulnType     string               `json:"vulnType"`
	MatchedToken string               `json:"matchedToken"`
	TopK         []service.TokenScore `json:"topK"`
	ElapsedMS    int                  `json:"elapsedMs"`
	CreatedAt    string               `json:"createdAt"`
}

// GET /api/detect/jobs/:id
func (h *DetectHandlers) GetBatchJob(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	var job model.DetectJob
	if err := h.DB.First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"message": "任务不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": "查询失败", "error": err.Error()})
		return
	}

	var rows []model.DetectResult
	if err := h.DB.Where("job_id = ?", job.ID).Order("created_at desc").Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "查询结果失败", "error": err.Error()})
		return
	}

	results := make([]detectResultDTO, 0, len(rows))
	for _, r := range rows {
		topK := make([]service.TokenScore, 0)
		if r.TopKJSON != "" {
			_ = json.Unmarshal([]byte(r.TopKJSON), &topK)
		}
		results = append(results, detectResultDTO{
			ID:           r.ID,
			JobID:        r.JobID,
			ContractID:   r.ContractID,
			ModelID:      r.ModelID,
			PromptID:     r.PromptID,
			Label:        r.Label,
			Confidence:   r.Confidence,
			VulnType:     r.VulnType,
			MatchedToken: r.MatchedToken,
			TopK:         topK,
			ElapsedMS:    r.ElapsedMS,
			CreatedAt:    r.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"job":     job,
		"results": results,
	})
}
