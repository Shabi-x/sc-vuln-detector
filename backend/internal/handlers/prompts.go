package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
)

type PromptHandlers struct {
	DB *gorm.DB
}

func NewPromptHandlers(db *gorm.DB) *PromptHandlers {
	return &PromptHandlers{DB: db}
}

type createPromptRequest struct {
	Name          string           `json:"name" binding:"required"`
	Type          model.PromptType `json:"type" binding:"required"`
	Description   string           `json:"description"`
	TemplateText  string           `json:"templateText"`
	SoftConfigJSON string          `json:"softConfigJson"`
	IsActive      *bool            `json:"isActive"`
}

func (h *PromptHandlers) ListPrompts(c *gin.Context) {
	var out []model.Prompt
	q := h.DB.Model(&model.Prompt{})
	if t := strings.TrimSpace(c.Query("type")); t != "" {
		q = q.Where("type = ?", t)
	}
	if active := strings.TrimSpace(c.Query("active")); active == "true" {
		q = q.Where("is_active = ?", true)
	}
	if err := q.Order("updated_at desc").Find(&out).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "查询失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *PromptHandlers) CreatePrompt(c *gin.Context) {
	var req createPromptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "参数错误", "error": err.Error()})
		return
	}

	p := model.Prompt{
		ID:            uuid.NewString(),
		Name:          strings.TrimSpace(req.Name),
		Type:          req.Type,
		Description:   strings.TrimSpace(req.Description),
		TemplateText:  req.TemplateText,
		SoftConfigJSON: req.SoftConfigJSON,
		IsPreset:      false,
		IsActive:      true,
	}
	if req.IsActive != nil {
		p.IsActive = *req.IsActive
	}

	if p.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "name 不能为空"})
		return
	}
	if p.Type != model.PromptTypeHard && p.Type != model.PromptTypeSoft {
		c.JSON(http.StatusBadRequest, gin.H{"message": "type 必须为 hard 或 soft"})
		return
	}
	if p.Type == model.PromptTypeHard {
		if !strings.Contains(p.TemplateText, "[X]") {
			c.JSON(http.StatusBadRequest, gin.H{"message": "硬提示模板必须包含 [X]"})
			return
		}
	}

	if err := h.DB.Create(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "创建失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, p)
}

type updatePromptRequest struct {
	Name           *string           `json:"name"`
	Type           *model.PromptType `json:"type"`
	Description    *string           `json:"description"`
	TemplateText   *string           `json:"templateText"`
	SoftConfigJSON *string           `json:"softConfigJson"`
	IsActive       *bool             `json:"isActive"`
}

func (h *PromptHandlers) UpdatePrompt(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "id 不能为空"})
		return
	}

	var req updatePromptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "参数错误", "error": err.Error()})
		return
	}

	var p model.Prompt
	if err := h.DB.First(&p, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "未找到模板", "error": err.Error()})
		return
	}

	if req.Name != nil {
		p.Name = strings.TrimSpace(*req.Name)
	}
	if req.Type != nil {
		p.Type = *req.Type
	}
	if req.Description != nil {
		p.Description = strings.TrimSpace(*req.Description)
	}
	if req.TemplateText != nil {
		p.TemplateText = *req.TemplateText
	}
	if req.SoftConfigJSON != nil {
		p.SoftConfigJSON = *req.SoftConfigJSON
	}
	if req.IsActive != nil {
		p.IsActive = *req.IsActive
	}

	if p.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "name 不能为空"})
		return
	}
	if p.Type != model.PromptTypeHard && p.Type != model.PromptTypeSoft {
		c.JSON(http.StatusBadRequest, gin.H{"message": "type 必须为 hard 或 soft"})
		return
	}
	if p.Type == model.PromptTypeHard {
		if !strings.Contains(p.TemplateText, "[X]") {
			c.JSON(http.StatusBadRequest, gin.H{"message": "硬提示模板必须包含 [X]"})
			return
		}
	}

	if err := h.DB.Save(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "更新失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, p)
}

func (h *PromptHandlers) DeletePrompt(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "id 不能为空"})
		return
	}
	// 先删映射
	if err := h.DB.Where("prompt_id = ?", id).Delete(&model.PromptMapping{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "删除失败", "error": err.Error()})
		return
	}
	if err := h.DB.Delete(&model.Prompt{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "删除失败", "error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

type createMappingRequest struct {
	PromptID  string      `json:"promptId" binding:"required"`
	Token     string      `json:"token" binding:"required"`
	Label     model.Label `json:"label" binding:"required"`
	IsDefault *bool       `json:"isDefault"`
}

func (h *PromptHandlers) ListMappings(c *gin.Context) {
	promptID := strings.TrimSpace(c.Query("promptId"))
	if promptID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "promptId 必填"})
		return
	}
	var out []model.PromptMapping
	if err := h.DB.Order("updated_at desc").Find(&out, "prompt_id = ?", promptID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "查询失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *PromptHandlers) CreateMapping(c *gin.Context) {
	var req createMappingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "参数错误", "error": err.Error()})
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	if req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "token 不能为空"})
		return
	}
	if req.Label != model.LabelVulnerable && req.Label != model.LabelNonVulnerable {
		c.JSON(http.StatusBadRequest, gin.H{"message": "label 必须为 vulnerable 或 nonVulnerable"})
		return
	}

	m := model.PromptMapping{
		ID:        uuid.NewString(),
		PromptID:  req.PromptID,
		Token:     req.Token,
		Label:     req.Label,
		IsDefault: true,
	}
	if req.IsDefault != nil {
		m.IsDefault = *req.IsDefault
	}

	if err := h.DB.Create(&m).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "创建失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, m)
}

type updateMappingRequest struct {
	Token     *string      `json:"token"`
	Label     *model.Label `json:"label"`
	IsDefault *bool        `json:"isDefault"`
}

func (h *PromptHandlers) UpdateMapping(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "id 不能为空"})
		return
	}
	var req updateMappingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "参数错误", "error": err.Error()})
		return
	}

	var m model.PromptMapping
	if err := h.DB.First(&m, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "未找到映射", "error": err.Error()})
		return
	}
	if req.Token != nil {
		m.Token = strings.TrimSpace(*req.Token)
	}
	if req.Label != nil {
		m.Label = *req.Label
	}
	if req.IsDefault != nil {
		m.IsDefault = *req.IsDefault
	}
	if m.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "token 不能为空"})
		return
	}
	if m.Label != model.LabelVulnerable && m.Label != model.LabelNonVulnerable {
		c.JSON(http.StatusBadRequest, gin.H{"message": "label 必须为 vulnerable 或 nonVulnerable"})
		return
	}
	if err := h.DB.Save(&m).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "更新失败", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, m)
}

func (h *PromptHandlers) DeleteMapping(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "id 不能为空"})
		return
	}
	if err := h.DB.Delete(&model.PromptMapping{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "删除失败", "error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

