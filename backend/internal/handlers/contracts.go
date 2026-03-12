package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"sc-vuln-detector/backend/internal/preprocess"
)

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
}

func PreprocessContract(c *gin.Context) {
	var req preprocessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "参数错误",
			"error":   err.Error(),
		})
		return
	}

	out := preprocess.Run(req.Source)
	res := preprocessResponse{}
	res.Original.Source = req.Source
	res.Original.Lines = preprocess.CountLines(req.Source)
	res.Processed.Source = out
	res.Processed.Lines = preprocess.CountLines(out)
	res.RemovedLines = res.Original.Lines - res.Processed.Lines
	if res.Original.Lines > 0 {
		res.CompressionRatio = float64(res.Processed.Lines) / float64(res.Original.Lines)
	}

	c.JSON(http.StatusOK, res)
}
