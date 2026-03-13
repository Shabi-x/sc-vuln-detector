package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
	"sc-vuln-detector/backend/internal/preprocess"
)

// ContractHandlers 负责合约预处理及入库
type ContractHandlers struct {
	db *gorm.DB
}

func NewContractHandlers(db *gorm.DB) *ContractHandlers {
	return &ContractHandlers{db: db}
}

type preprocessRequest struct {
	Source   string `json:"source" binding:"required"`
	Filename string `json:"filename"`
}

type preprocessResponse struct {
	Original struct {
		Source string `json:"source"`
		Lines  int    `json:"lines"`
	} `json:"original"`
	Processed struct {
		Source string `json:"source"`
		Lines  int    `json:"lines"`
	} `json:"processed"`
	RemovedLines     int     `json:"removedLines"`
	CompressionRatio float64 `json:"compressionRatio"`
	ContractID       string  `json:"contractId,omitempty"`
}

// PreprocessContract 对合约进行预处理，并在数据库可用时自动入库
func (h *ContractHandlers) PreprocessContract(c *gin.Context) {
	var req preprocessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "参数错误",
			"error":   err.Error(),
		})
		return
	}

	// 按文档口径：预处理同时结合“正则 + 语法分析（解析失败自动回退）”
	out := preprocess.RunAST(req.Source)
	res := preprocessResponse{}
	res.Original.Source = req.Source
	res.Original.Lines = preprocess.CountLines(req.Source)
	res.Processed.Source = out
	res.Processed.Lines = preprocess.CountLines(out)
	res.RemovedLines = res.Original.Lines - res.Processed.Lines
	if res.Original.Lines > 0 {
		res.CompressionRatio = float64(res.Processed.Lines) / float64(res.Original.Lines)
	}

	// 如果有数据库，顺便把本次预处理结果存成一条合约记录
	if h.db != nil {
		name := req.Filename
		if name == "" {
			name = "pasted"
		}
		ct := &model.Contract{
			ID:               uuid.NewString(),
			Name:             name,
			Source:           res.Original.Source,
			ProcessedSource:  res.Processed.Source,
			OriginalLines:    res.Original.Lines,
			ProcessedLines:   res.Processed.Lines,
			RemovedLines:     res.RemovedLines,
			CompressionRatio: res.CompressionRatio,
		}
		if err := h.db.Create(ct).Error; err == nil {
			res.ContractID = ct.ID
		}
	}

	c.JSON(http.StatusOK, res)
}

type contractDTO struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	OriginalLines    int       `json:"originalLines"`
	ProcessedLines   int       `json:"processedLines"`
	RemovedLines     int       `json:"removedLines"`
	CompressionRatio float64   `json:"compressionRatio"`
	CreatedAt        time.Time `json:"createdAt"`
}

// ListContracts 返回已保存的合约概要列表
func (h *ContractHandlers) ListContracts(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"message": "数据库未初始化",
		})
		return
	}

	var contracts []model.Contract
	if err := h.db.Order("created_at DESC").Find(&contracts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "查询失败",
			"error":   err.Error(),
		})
		return
	}

	resp := make([]contractDTO, 0, len(contracts))
	for _, ct := range contracts {
		resp = append(resp, contractDTO{
			ID:               ct.ID,
			Name:             ct.Name,
			OriginalLines:    ct.OriginalLines,
			ProcessedLines:   ct.ProcessedLines,
			RemovedLines:     ct.RemovedLines,
			CompressionRatio: ct.CompressionRatio,
			CreatedAt:        ct.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, resp)
}

// GetContract 返回单个合约的完整内容
func (h *ContractHandlers) GetContract(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"message": "数据库未初始化",
		})
		return
	}

	id := c.Param("id")
	var ct model.Contract
	if err := h.db.First(&ct, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"message": "合约不存在",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "查询失败",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, ct)
}

// DeleteContract 删除单个已保存合约
func (h *ContractHandlers) DeleteContract(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"message": "数据库未初始化",
		})
		return
	}

	id := c.Param("id")
	if err := h.db.Delete(&model.Contract{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "删除失败",
			"error":   err.Error(),
		})
		return
	}

	c.Status(http.StatusNoContent)
}


