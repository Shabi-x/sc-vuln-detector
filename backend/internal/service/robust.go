package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
)

type RobustService struct {
	DB       *gorm.DB
	Detector *Detector
}

func NewRobustService(db *gorm.DB, detector *Detector) *RobustService {
	return &RobustService{DB: db, Detector: detector}
}

type RobustEvaluateRequest struct {
	ModelID        string   `json:"modelId"`
	PromptID       string   `json:"promptId"`
	ContractIDs    []string `json:"contractIds"`
	Strategies     []string `json:"strategies"`
	VariantsPerSrc int      `json:"variantsPerSource"`
}

// CreateJob 创建鲁棒性评估任务并异步执行
func (s *RobustService) CreateJob(ctx context.Context, req RobustEvaluateRequest) (*model.RobustJob, error) {
	if s.DB == nil || s.Detector == nil {
		return nil, gorm.ErrInvalidDB
	}
	if strings.TrimSpace(req.ModelID) == "" || strings.TrimSpace(req.PromptID) == "" {
		return nil, fmt.Errorf("modelId 和 promptId 必填")
	}
	if len(req.ContractIDs) == 0 {
		return nil, fmt.Errorf("contractIds 不能为空")
	}
	if len(req.Strategies) == 0 {
		req.Strategies = []string{"rename-identifiers"}
	}
	if req.VariantsPerSrc <= 0 {
		req.VariantsPerSrc = 1
	}

	confBytes, _ := json.Marshal(map[string]any{
		"contractIds":       req.ContractIDs,
		"strategies":        req.Strategies,
		"variantsPerSource": req.VariantsPerSrc,
	})

	job := &model.RobustJob{
		ID:               uuid.NewString(),
		Status:           model.RobustJobStatusQueued,
		ModelID:          req.ModelID,
		PromptID:         req.PromptID,
		AttackConfigJSON: string(confBytes),
	}
	if err := s.DB.WithContext(ctx).Create(job).Error; err != nil {
		return nil, err
	}

	go s.run(job.ID)

	return job, nil
}

func (s *RobustService) run(jobID string) {
	ctx := context.Background()

	var job model.RobustJob
	if err := s.DB.WithContext(ctx).First(&job, "id = ?", jobID).Error; err != nil {
		return
	}

	start := time.Now()
	if err := s.DB.WithContext(ctx).Model(&model.RobustJob{}).
		Where("id = ?", jobID).
		Updates(map[string]any{
			"status":     model.RobustJobStatusRunning,
			"started_at": start,
			"error":      "",
		}).Error; err != nil {
		return
	}

	// 校验模型存在（本版本仍为启发式推理，但保持“模型维度”一致，便于后续替换为真实推理）
	var mdl model.TrainedModel
	if err := s.DB.WithContext(ctx).First(&mdl, "id = ?", job.ModelID).Error; err != nil {
		s.fail(jobID, fmt.Errorf("模型不存在"))
		return
	}

	// 加载 prompt 与映射（verbalizer）
	var prompt model.Prompt
	if err := s.DB.WithContext(ctx).First(&prompt, "id = ?", job.PromptID).Error; err != nil {
		s.fail(jobID, fmt.Errorf("提示模板不存在"))
		return
	}
	var mappings []model.PromptMapping
	if err := s.DB.WithContext(ctx).Where("prompt_id = ?", prompt.ID).Find(&mappings).Error; err != nil {
		s.fail(jobID, err)
		return
	}
	if len(mappings) == 0 {
		s.fail(jobID, fmt.Errorf("该模板未配置标签词映射"))
		return
	}

	var cfg struct {
		ContractIDs       []string `json:"contractIds"`
		Strategies        []string `json:"strategies"`
		VariantsPerSource int      `json:"variantsPerSource"`
	}
	if err := json.Unmarshal([]byte(job.AttackConfigJSON), &cfg); err != nil {
		s.fail(jobID, fmt.Errorf("解析任务配置失败: %w", err))
		return
	}

	// 1) 加载原始合约
	var contracts []model.Contract
	if err := s.DB.WithContext(ctx).Find(&contracts, "id IN ?", cfg.ContractIDs).Error; err != nil {
		s.fail(jobID, fmt.Errorf("加载合约失败: %w", err))
		return
	}
	if len(contracts) == 0 {
		s.fail(jobID, fmt.Errorf("未找到任何合约"))
		return
	}

	// 为避免对抗样本记录无限膨胀：清理本次涉及合约 + 策略 的旧对抗样本。
	// 需求上仍然“记录入库”，但默认只保留最新一轮，便于演示与管理。
	baseIDs := make([]string, 0, len(contracts))
	for _, c := range contracts {
		baseIDs = append(baseIDs, c.ID)
	}
	if len(baseIDs) > 0 && len(cfg.Strategies) > 0 {
		_ = s.DB.WithContext(ctx).
			Where("base_contract_id IN ? AND strategy IN ?", baseIDs, cfg.Strategies).
			Delete(&model.AdversarialSample{}).Error
	}

	// 2) 对原始合约做推理，得到 baseline（不落库 detect_results，避免污染检测数据；后续替换为真实推理也更清晰）
	origResults := map[string]*model.DetectResult{}
	for _, ct := range contracts {
		_, _, label, confidence, vulnType := inferByHeuristic(ct.ProcessedSource, mappings)
		origResults[ct.ID] = &model.DetectResult{
			ContractID: ct.ID,
			Label:      label,
			Confidence: confidence,
			VulnType:   vulnType,
		}
	}
	if len(origResults) == 0 {
		s.fail(jobID, fmt.Errorf("原始检测全部失败"))
		return
	}

	// 3) 生成简单对抗样本并检测
	var totalAdv, flippedCount int
	var totalConfDrop float64

	type perContractAgg struct {
		BaseContractID   string         `json:"baseContractId"`
		ContractName     string         `json:"contractName"`
		OrigLabel        model.Label    `json:"origLabel"`
		OrigConfidence   float64        `json:"origConfidence"`
		AdvTotal         int            `json:"advTotal"`
		Flipped          int            `json:"flipped"`
		AvgAdvConfidence float64        `json:"avgAdvConfidence"`
		AvgConfDrop      float64        `json:"avgConfDrop"`
		ByStrategy       map[string]any `json:"byStrategy"`
	}
	perContract := map[string]*perContractAgg{}
	type stratAgg struct {
		Total       int
		Flipped     int
		ConfDropSum float64
	}
	perStrategy := map[string]*stratAgg{}

	for _, ct := range contracts {
		base := ct
		orig, ok := origResults[base.ID]
		if !ok {
			continue
		}
		if _, ok := perContract[base.ID]; !ok {
			perContract[base.ID] = &perContractAgg{
				BaseContractID:   base.ID,
				ContractName:     base.Name,
				OrigLabel:        orig.Label,
				OrigConfidence:   orig.Confidence,
				ByStrategy:       map[string]any{},
				AvgAdvConfidence: 0,
				AvgConfDrop:      0,
			}
		}
		contractAgg := perContract[base.ID]
		for _, strat := range cfg.Strategies {
			if _, ok := perStrategy[strat]; !ok {
				perStrategy[strat] = &stratAgg{}
			}
			// per-contract per-strategy
			key := strat
			if _, ok := contractAgg.ByStrategy[key]; !ok {
				contractAgg.ByStrategy[key] = map[string]any{
					"total":       0,
					"flipped":     0,
					"avgConfDrop": 0.0,
				}
			}
			for i := 0; i < cfg.VariantsPerSource; i++ {
				advSource := generateSimpleAdversarial(base.Source, strat, i)
				advProcessed := generateSimpleAdversarial(base.ProcessedSource, strat, i)
				sample := &model.AdversarialSample{
					ID:              uuid.NewString(),
					BaseContractID:  base.ID,
					Strategy:        strat,
					Source:          advSource,
					ProcessedSource: advProcessed,
					DiffJSON:        "",
				}
				if err := s.DB.WithContext(ctx).Create(sample).Error; err != nil {
					continue
				}
				// 直接对 processedSource 推理，不写入 contracts 表，避免数据管理列表无限增长
				_, _, advLabel, advConf, _ := inferByHeuristic(advProcessed, mappings)

				totalAdv++
				perStrategy[strat].Total++

				contractAgg.AdvTotal++
				contractAgg.AvgAdvConfidence += advConf
				// update per-strategy in contract
				byStrat := contractAgg.ByStrategy[key].(map[string]any)
				byStrat["total"] = byStrat["total"].(int) + 1

				if orig.Label != advLabel {
					flippedCount++
					perStrategy[strat].Flipped++
					contractAgg.Flipped++
					byStrat["flipped"] = byStrat["flipped"].(int) + 1
				}
				if advConf < orig.Confidence {
					drop := orig.Confidence - advConf
					totalConfDrop += drop
					perStrategy[strat].ConfDropSum += drop
					contractAgg.AvgConfDrop += drop
					byStrat["avgConfDrop"] = byStrat["avgConfDrop"].(float64) + drop
				}
				contractAgg.ByStrategy[key] = byStrat
			}
		}
	}

	if totalAdv == 0 {
		s.fail(jobID, fmt.Errorf("未成功生成任何对抗样本检测结果"))
		return
	}

	flipRate := float64(flippedCount) / float64(totalAdv)
	avgConfDrop := totalConfDrop / float64(totalAdv)

	perStrategyOut := make([]map[string]any, 0, len(perStrategy))
	for strat, a := range perStrategy {
		if a.Total == 0 {
			continue
		}
		perStrategyOut = append(perStrategyOut, map[string]any{
			"strategy":          strat,
			"total":             a.Total,
			"flipped":           a.Flipped,
			"flipRate":          round4(float64(a.Flipped) / float64(a.Total)),
			"avgConfidenceDrop": round4(a.ConfDropSum / float64(a.Total)),
		})
	}

	perContractOut := make([]perContractAgg, 0, len(perContract))
	for _, c := range perContract {
		if c.AdvTotal > 0 {
			c.AvgAdvConfidence = round4(c.AvgAdvConfidence / float64(c.AdvTotal))
			c.AvgConfDrop = round4(c.AvgConfDrop / float64(c.AdvTotal))
			// normalize per-strategy avgConfDrop accumulators
			for k, v := range c.ByStrategy {
				m := v.(map[string]any)
				t := m["total"].(int)
				if t > 0 {
					m["avgConfDrop"] = round4(m["avgConfDrop"].(float64) / float64(t))
				} else {
					m["avgConfDrop"] = 0.0
				}
				c.ByStrategy[k] = m
			}
		}
		perContractOut = append(perContractOut, *c)
	}

	metrics := map[string]any{
		"totalAdversarial":  totalAdv,
		"flipped":           flippedCount,
		"flipRate":          round4(flipRate),
		"avgConfidenceDrop": round4(avgConfDrop),
		"perStrategy":       perStrategyOut,
		"perContract":       perContractOut,
	}
	metricsBytes, _ := json.Marshal(metrics)

	finish := time.Now()
	_ = s.DB.WithContext(ctx).Model(&model.RobustJob{}).Where("id = ?", jobID).
		Updates(map[string]any{
			"status":       model.RobustJobStatusSuccess,
			"metrics_json": string(metricsBytes),
			"finished_at":  finish,
		}).Error
}

func (s *RobustService) fail(jobID string, err error) {
	finish := time.Now()
	_ = s.DB.Model(&model.RobustJob{}).Where("id = ?", jobID).Updates(map[string]any{
		"status":      model.RobustJobStatusFailed,
		"error":       err.Error(),
		"finished_at": finish,
	}).Error
}

// generateSimpleAdversarial 一个非常简单的占位扰动生成器，后续可替换为更强的对抗算法。
func generateSimpleAdversarial(source string, strategy string, idx int) string {
	s := source
	switch strategy {
	case "insert-dead-code":
		// 简单在结尾插入一段不会执行的代码块
		s += "\nif (false) { // dead code " + fmt.Sprint(idx) + "\n}\n"
	case "rename-identifiers":
		// 非严格的占位改名：把常见名字后面拼接后缀
		repls := []struct {
			old string
			new string
		}{
			{"owner", fmt.Sprintf("owner_r%d", idx)},
			{"temp", fmt.Sprintf("temp_r%d", idx)},
		}
		for _, r := range repls {
			s = strings.ReplaceAll(s, r.old, r.new)
		}
	case "trigger-injection":
		// 触发词注入：通过重复插入风险关键词，提高“对 token 扰动敏感性”的可观察性（便于演示翻转与置信度变化）。
		// 当前启发式检测会统计关键词出现次数；若合约中 benignKeywords 数量很高，少量注入可能不足以触发翻转，因此这里重复注入。
		repeat := 30
		var b strings.Builder
		b.WriteString("\n// adversarial trigger ")
		b.WriteString(fmt.Sprint(idx))
		b.WriteString(": ")
		for i := 0; i < repeat; i++ {
			b.WriteString("delegatecall tx.origin call.value selfdestruct ")
		}
		b.WriteString("\n")
		s += b.String()
	default:
	}
	return s
}
