package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
)

type Detector struct {
	DB *gorm.DB
}

func NewDetector(db *gorm.DB) *Detector {
	return &Detector{DB: db}
}

type DetectRequest struct {
	ContractID string `json:"contractId"`
	PromptID   string `json:"promptId"`
	ModelID    string `json:"modelId"`
}

type TokenScore struct {
	Token string  `json:"token"`
	Score float64 `json:"score"`
}

type DetectOutput struct {
	ContractID   string       `json:"contractId"`
	Label        model.Label  `json:"label"`
	Confidence   float64      `json:"confidence"`
	VulnType     string       `json:"vulnType"`
	MatchedToken string       `json:"matchedToken"`
	TopK         []TokenScore `json:"topK"`
	ElapsedMS    int          `json:"elapsedMs"`
}

func (d *Detector) DetectOne(ctx context.Context, req DetectRequest) (*DetectOutput, string, error) {
	if d.DB == nil {
		return nil, "", gorm.ErrInvalidDB
	}
	if strings.TrimSpace(req.ContractID) == "" || strings.TrimSpace(req.PromptID) == "" {
		return nil, "", fmt.Errorf("contractId 和 promptId 必填")
	}

	modelID, err := d.resolveModelID(ctx, strings.TrimSpace(req.ModelID))
	if err != nil {
		return nil, "", err
	}

	var ct model.Contract
	if err := d.DB.WithContext(ctx).First(&ct, "id = ?", strings.TrimSpace(req.ContractID)).Error; err != nil {
		return nil, "", err
	}
	var prompt model.Prompt
	if err := d.DB.WithContext(ctx).First(&prompt, "id = ?", strings.TrimSpace(req.PromptID)).Error; err != nil {
		return nil, "", err
	}
	var mappings []model.PromptMapping
	if err := d.DB.WithContext(ctx).Where("prompt_id = ?", prompt.ID).Find(&mappings).Error; err != nil {
		return nil, "", err
	}
	if len(mappings) == 0 {
		return nil, "", fmt.Errorf("该模板未配置标签词映射")
	}

	start := time.Now()
	topK, matchedToken, label, confidence, vulnType := inferByHeuristic(ct.ProcessedSource, mappings)
	elapsed := int(time.Since(start).Milliseconds())

	topKJSON, _ := json.Marshal(topK)
	rec := &model.DetectResult{
		ID:           uuid.NewString(),
		ContractID:   ct.ID,
		ModelID:      modelID,
		PromptID:     prompt.ID,
		Label:        label,
		Confidence:   confidence,
		VulnType:     vulnType,
		MatchedToken: matchedToken,
		TopKJSON:     string(topKJSON),
		ElapsedMS:    elapsed,
	}
	if err := d.DB.WithContext(ctx).Create(rec).Error; err != nil {
		return nil, "", err
	}

	return &DetectOutput{
		ContractID:   ct.ID,
		Label:        label,
		Confidence:   confidence,
		VulnType:     vulnType,
		MatchedToken: matchedToken,
		TopK:         topK,
		ElapsedMS:    elapsed,
	}, modelID, nil
}

func (d *Detector) CreateBatchJob(ctx context.Context, promptID, modelID string, contractIDs []string) (*model.DetectJob, error) {
	if d.DB == nil {
		return nil, gorm.ErrInvalidDB
	}
	if promptID == "" || len(contractIDs) == 0 {
		return nil, fmt.Errorf("promptId 和 contractIds 必填")
	}

	resolvedModelID, err := d.resolveModelID(ctx, modelID)
	if err != nil {
		return nil, err
	}

	paramsBytes, _ := json.Marshal(map[string]any{
		"contractIds": contractIDs,
	})
	job := &model.DetectJob{
		ID:         uuid.NewString(),
		Status:     model.DetectJobStatusQueued,
		PromptID:   promptID,
		ModelID:    resolvedModelID,
		ParamsJSON: string(paramsBytes),
	}
	if err := d.DB.WithContext(ctx).Create(job).Error; err != nil {
		return nil, err
	}
	go d.runBatch(job.ID)
	return job, nil
}

func (d *Detector) runBatch(jobID string) {
	ctx := context.Background()
	now := time.Now()
	if err := d.DB.WithContext(ctx).Model(&model.DetectJob{}).Where("id = ?", jobID).
		Updates(map[string]any{"status": model.DetectJobStatusRunning, "started_at": now, "error": ""}).Error; err != nil {
		return
	}

	var job model.DetectJob
	if err := d.DB.WithContext(ctx).First(&job, "id = ?", jobID).Error; err != nil {
		return
	}
	var p struct {
		ContractIDs []string `json:"contractIds"`
	}
	if err := json.Unmarshal([]byte(job.ParamsJSON), &p); err != nil {
		d.failJob(jobID, fmt.Errorf("解析任务参数失败: %w", err))
		return
	}
	var prompt model.Prompt
	if err := d.DB.WithContext(ctx).First(&prompt, "id = ?", job.PromptID).Error; err != nil {
		d.failJob(jobID, err)
		return
	}
	var mappings []model.PromptMapping
	if err := d.DB.WithContext(ctx).Where("prompt_id = ?", prompt.ID).Find(&mappings).Error; err != nil {
		d.failJob(jobID, err)
		return
	}
	if len(mappings) == 0 {
		d.failJob(jobID, fmt.Errorf("该模板未配置标签词映射"))
		return
	}

	var success, failed int
	labelStats := map[model.Label]int{}
	vulnTypeStats := map[string]int{}
	for _, cid := range p.ContractIDs {
		var ct model.Contract
		if err := d.DB.WithContext(ctx).First(&ct, "id = ?", cid).Error; err != nil {
			failed++
			continue
		}
		start := time.Now()
		topK, matchedToken, label, confidence, vulnType := inferByHeuristic(ct.ProcessedSource, mappings)
		elapsed := int(time.Since(start).Milliseconds())
		topKJSON, _ := json.Marshal(topK)
		rec := &model.DetectResult{
			ID:           uuid.NewString(),
			JobID:        jobID,
			ContractID:   ct.ID,
			ModelID:      job.ModelID,
			PromptID:     prompt.ID,
			Label:        label,
			Confidence:   confidence,
			VulnType:     vulnType,
			MatchedToken: matchedToken,
			TopKJSON:     string(topKJSON),
			ElapsedMS:    elapsed,
		}
		if err := d.DB.WithContext(ctx).Create(rec).Error; err != nil {
			failed++
			continue
		}
		labelStats[label]++
		if vulnType != "" {
			vulnTypeStats[vulnType]++
		}
		success++
	}

	resultBytes, _ := json.Marshal(map[string]any{
		"total":        len(p.ContractIDs),
		"success":      success,
		"failed":       failed,
		"labelStats":   labelStats,
		"vulnTypeStats": vulnTypeStats,
	})
	finish := time.Now()
	_ = d.DB.WithContext(ctx).Model(&model.DetectJob{}).Where("id = ?", jobID).
		Updates(map[string]any{
			"status":      model.DetectJobStatusSuccess,
			"result_json": string(resultBytes),
			"finished_at": finish,
		}).Error
}

func (d *Detector) resolveModelID(ctx context.Context, explicitID string) (string, error) {
	if explicitID != "" {
		var m model.TrainedModel
		if err := d.DB.WithContext(ctx).First(&m, "id = ?", explicitID).Error; err != nil {
			return "", fmt.Errorf("模型不存在")
		}
		return m.ID, nil
	}
	var loaded model.TrainedModel
	if err := d.DB.WithContext(ctx).First(&loaded, "is_loaded = ?", true).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", fmt.Errorf("当前没有已加载模型，请先在训练模块加载模型")
		}
		return "", err
	}
	return loaded.ID, nil
}

func (d *Detector) failJob(jobID string, err error) {
	finish := time.Now()
	_ = d.DB.Model(&model.DetectJob{}).Where("id = ?", jobID).Updates(map[string]any{
		"status":      model.DetectJobStatusFailed,
		"error":       err.Error(),
		"finished_at": finish,
	}).Error
}

func inferByHeuristic(source string, mappings []model.PromptMapping) ([]TokenScore, string, model.Label, float64, string) {
	lower := strings.ToLower(source)
	riskKeywords := []string{"call.value", "delegatecall", "tx.origin", "selfdestruct", "reentrancy", "assembly"}
	benignKeywords := []string{"require(", "revert(", "onlyowner", "nonreentrant"}

	var riskCount, benignCount int
	for _, k := range riskKeywords {
		riskCount += strings.Count(lower, k)
	}
	for _, k := range benignKeywords {
		benignCount += strings.Count(lower, k)
	}
	raw := float64(riskCount+1) / float64(riskCount+benignCount+2)
	conf := math.Max(0.5, math.Min(0.99, raw))

	vTokens := make([]string, 0)
	nTokens := make([]string, 0)
	for _, m := range mappings {
		if m.Label == model.LabelVulnerable {
			vTokens = append(vTokens, m.Token)
		}
		if m.Label == model.LabelNonVulnerable {
			nTokens = append(nTokens, m.Token)
		}
	}
	if len(vTokens) == 0 {
		vTokens = append(vTokens, "bad")
	}
	if len(nTokens) == 0 {
		nTokens = append(nTokens, "good")
	}

	label := model.LabelNonVulnerable
	matched := nTokens[0]
	vulnType := ""
	if raw >= 0.5 {
		label = model.LabelVulnerable
		matched = vTokens[0]
		vulnType = guessVulnType(lower)
	}

	topK := []TokenScore{
		{Token: vTokens[0], Score: round4(raw)},
		{Token: nTokens[0], Score: round4(1 - raw)},
	}
	sort.Slice(topK, func(i, j int) bool {
		return topK[i].Score > topK[j].Score
	})
	return topK, matched, label, round4(conf), vulnType
}

func guessVulnType(lowerSource string) string {
	switch {
	case strings.Contains(lowerSource, "delegatecall"):
		return "delegatecall-risk"
	case strings.Contains(lowerSource, "tx.origin"):
		return "tx-origin-risk"
	case strings.Contains(lowerSource, "call.value"):
		return "reentrancy-risk"
	default:
		return ""
	}
}

func round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}
