package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
)

const (
	RobustStrategyCallChainHiding = "call-chain-hiding"
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

type robustConfig struct {
	ContractIDs       []string `json:"contractIds"`
	Strategies        []string `json:"strategies"`
	VariantsPerSource int      `json:"variantsPerSource"`
}

type modelArtifactMetadata struct {
	TargetVulnType string         `json:"target_vuln_type"`
	LabelMap       map[string]int `json:"label_map"`
	PromptText     *string        `json:"prompt_text"`
	MaxLength      int            `json:"max_length"`
	RawClassCounts map[string]int `json:"raw_class_counts"`
	TrainCounts    map[string]int `json:"train_counts"`
	ValCounts      map[string]int `json:"val_counts"`
	Extra          map[string]any `json:"-"`
}

type robustCoreFragment struct {
	Index       int     `json:"index"`
	LineNumber  int     `json:"lineNumber"`
	Content     string  `json:"content"`
	Sensitivity float64 `json:"sensitivity"`
	VulnScore   float64 `json:"vulnScore"`
	Label       string  `json:"label"`
}

type robustAttackSample struct {
	VariantIndex    int                  `json:"variantIndex"`
	FragmentsUsed   []robustCoreFragment `json:"fragmentsUsed"`
	OpaqueGuards    []string             `json:"opaqueGuards"`
	WrapperNames    []string             `json:"wrapperNames"`
	AttackSucceeded bool                 `json:"attackSucceeded"`
}

type robustPerContract struct {
	BaseContractID     string               `json:"baseContractId"`
	ContractName       string               `json:"contractName"`
	OrigLabel          model.Label          `json:"origLabel"`
	OrigConfidence     float64              `json:"origConfidence"`
	OrigVulnScore      float64              `json:"origVulnScore"`
	Attackable         bool                 `json:"attackable"`
	SkippedReason      string               `json:"skippedReason"`
	CoreFragments      []robustCoreFragment `json:"coreFragments"`
	AdvTotal           int                  `json:"advTotal"`
	Flipped            int                  `json:"flipped"`
	AvgAdvConfidence   float64              `json:"avgAdvConfidence"`
	AvgConfDrop        float64              `json:"avgConfDrop"`
	BestAttackStrategy string               `json:"bestAttackStrategy"`
	BestAttackSample   *robustAttackSample  `json:"bestAttackSample,omitempty"`
	ByStrategy         map[string]any       `json:"byStrategy"`
}

type robustStrategyAgg struct {
	TotalVariants      int     `json:"totalVariants"`
	AttackSuccesses    int     `json:"attackSuccesses"`
	ConfidenceDropSum  float64 `json:"confidenceDropSum"`
	CoreFragmentsTotal int     `json:"coreFragmentsTotal"`
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
		req.Strategies = []string{RobustStrategyCallChainHiding}
	}
	if req.VariantsPerSrc <= 0 {
		req.VariantsPerSrc = 1
	}
	if req.VariantsPerSrc > 5 {
		req.VariantsPerSrc = 5
	}

	confBytes, _ := json.Marshal(robustConfig{
		ContractIDs:       req.ContractIDs,
		Strategies:        req.Strategies,
		VariantsPerSource: req.VariantsPerSrc,
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

	var trainedModel model.TrainedModel
	if err := s.DB.WithContext(ctx).First(&trainedModel, "id = ?", job.ModelID).Error; err != nil {
		s.fail(jobID, fmt.Errorf("模型不存在"))
		return
	}

	var prompt model.Prompt
	if err := s.DB.WithContext(ctx).First(&prompt, "id = ?", job.PromptID).Error; err != nil {
		s.fail(jobID, fmt.Errorf("提示模板不存在"))
		return
	}

	meta, err := s.loadModelMetadata(trainedModel.Artifact)
	if err != nil {
		s.fail(jobID, err)
		return
	}

	var cfg robustConfig
	if err := json.Unmarshal([]byte(job.AttackConfigJSON), &cfg); err != nil {
		s.fail(jobID, fmt.Errorf("解析任务配置失败: %w", err))
		return
	}
	if len(cfg.Strategies) == 0 {
		cfg.Strategies = []string{RobustStrategyCallChainHiding}
	}

	var contracts []model.Contract
	if err := s.DB.WithContext(ctx).Find(&contracts, "id IN ?", cfg.ContractIDs).Error; err != nil {
		s.fail(jobID, fmt.Errorf("加载合约失败: %w", err))
		return
	}
	if len(contracts) == 0 {
		s.fail(jobID, fmt.Errorf("未找到任何合约"))
		return
	}

	baseIDs := make([]string, 0, len(contracts))
	for _, contract := range contracts {
		baseIDs = append(baseIDs, contract.ID)
	}
	_ = s.DB.WithContext(ctx).
		Where("base_contract_id IN ?", baseIDs).
		Delete(&model.AdversarialSample{}).Error

	perContract := make([]robustPerContract, 0, len(contracts))
	perStrategy := map[string]*robustStrategyAgg{}

	var totalVariants int
	var attackSuccesses int
	var attackableContracts int
	var origCorrect int
	var advCorrect int

	for _, contract := range contracts {
		baseline, err := s.Detector.runModelInference(trainedModel.Artifact, contract.ProcessedSource, prompt.TemplateText)
		if err != nil {
			perContract = append(perContract, robustPerContract{
				BaseContractID: contract.ID,
				ContractName:   contract.Name,
				SkippedReason:  err.Error(),
			})
			continue
		}

		baseVulnScore := scoreForLabel(baseline, "vulnerable")
		row := robustPerContract{
			BaseContractID: contract.ID,
			ContractName:   contract.Name,
			OrigLabel:      model.Label(baseline.Label),
			OrigConfidence: baseline.Confidence,
			OrigVulnScore:  baseVulnScore,
			Attackable:     baseline.Label == string(model.LabelVulnerable),
			ByStrategy:     map[string]any{},
		}
		if !row.Attackable {
			row.SkippedReason = "原始样本未被模型判定为目标漏洞，按论文口径不进入攻击成功率统计"
			perContract = append(perContract, row)
			continue
		}

		attackableContracts++
		origCorrect++

		fragments := s.searchCoreFragments(trainedModel.Artifact, prompt.TemplateText, contract.ProcessedSource, meta.TargetVulnType, baseVulnScore, cfg.VariantsPerSource)
		row.CoreFragments = fragments
		if len(fragments) == 0 {
			row.SkippedReason = "未定位到高敏感核心脆弱代码"
			perContract = append(perContract, row)
			continue
		}

		bestConfidence := 1.0
		bestDrop := 0.0
		bestFlip := false
		var bestSample *robustAttackSample
		row.AdvTotal = 0
		row.Flipped = 0

		for _, strategy := range cfg.Strategies {
			if _, ok := perStrategy[strategy]; !ok {
				perStrategy[strategy] = &robustStrategyAgg{}
			}

			strategyTotal := 0
			strategyFlipped := 0
			strategyDrop := 0.0

			for variantIndex := 1; variantIndex <= cfg.VariantsPerSource; variantIndex++ {
				usedFragments := fragments[:minInt(variantIndex, len(fragments))]
				advSource, advProcessed, sampleDetail, err := buildCallChainHidingAdversarial(contract, usedFragments, variantIndex)
				if err != nil {
					continue
				}

				advResult, err := s.Detector.runModelInference(trainedModel.Artifact, advProcessed, prompt.TemplateText)
				if err != nil {
					continue
				}

				success := advResult.Label == string(model.LabelNonVulnerable)
				drop := math.Max(0, baseVulnScore-scoreForLabel(advResult, "vulnerable"))
				sampleDetail.AttackSucceeded = success

				sample := &model.AdversarialSample{
					ID:              uuid.NewString(),
					BaseContractID:  contract.ID,
					Strategy:        strategy,
					Source:          advSource,
					ProcessedSource: advProcessed,
					DiffJSON:        mustMarshal(sampleDetail),
				}
				if err := s.DB.WithContext(ctx).Create(sample).Error; err != nil {
					continue
				}

				row.AdvTotal++
				row.AvgAdvConfidence += advResult.Confidence
				row.AvgConfDrop += drop
				strategyTotal++
				strategyDrop += drop
				totalVariants++
				perStrategy[strategy].TotalVariants++
				perStrategy[strategy].ConfidenceDropSum += drop
				perStrategy[strategy].CoreFragmentsTotal += len(usedFragments)

				if success {
					row.Flipped++
					strategyFlipped++
					attackSuccesses++
					perStrategy[strategy].AttackSuccesses++
				}

				if !success {
					advCorrect++
				}

				if success && (bestSample == nil || advResult.Confidence < bestConfidence) {
					copySample := sampleDetail
					bestSample = &copySample
					bestConfidence = advResult.Confidence
					bestDrop = drop
					bestFlip = true
					row.BestAttackStrategy = strategy
				}

				if !bestFlip && drop > bestDrop {
					copySample := sampleDetail
					bestSample = &copySample
					bestConfidence = advResult.Confidence
					bestDrop = drop
					row.BestAttackStrategy = strategy
				}
			}

			row.ByStrategy[strategy] = map[string]any{
				"total":                  strategyTotal,
				"attackSuccesses":        strategyFlipped,
				"attackSuccessRate":      safeDiv(float64(strategyFlipped), float64(maxInt(strategyTotal, 1))),
				"avgConfidenceDrop":      safeDiv(strategyDrop, float64(maxInt(strategyTotal, 1))),
				"avgCoreFragmentsHidden": averageFragmentsPerStrategy(strategy, perStrategy),
			}
		}

		if row.AdvTotal > 0 {
			row.AvgAdvConfidence = round4(row.AvgAdvConfidence / float64(row.AdvTotal))
			row.AvgConfDrop = round4(row.AvgConfDrop / float64(row.AdvTotal))
			row.BestAttackSample = bestSample
		}
		perContract = append(perContract, row)
	}

	origAccuracy := safeDiv(float64(origCorrect), float64(maxInt(attackableContracts, 1)))
	advAccuracy := safeDiv(float64(advCorrect), float64(maxInt(totalVariants, 1)))
	attackSuccessRate := safeDiv(float64(attackSuccesses), float64(maxInt(totalVariants, 1)))
	accuracyDropRate := 0.0
	if origAccuracy > 0 {
		accuracyDropRate = (origAccuracy - advAccuracy) / origAccuracy
		if accuracyDropRate < 0 {
			accuracyDropRate = 0
		}
	}

	perStrategyOut := make([]map[string]any, 0, len(perStrategy))
	for strategy, agg := range perStrategy {
		if agg.TotalVariants == 0 {
			continue
		}
		perStrategyOut = append(perStrategyOut, map[string]any{
			"strategy":               strategy,
			"totalVariants":          agg.TotalVariants,
			"attackSuccesses":        agg.AttackSuccesses,
			"attackSuccessRate":      round4(safeDiv(float64(agg.AttackSuccesses), float64(agg.TotalVariants))),
			"avgConfidenceDrop":      round4(safeDiv(agg.ConfidenceDropSum, float64(agg.TotalVariants))),
			"avgCoreFragmentsHidden": round4(safeDiv(float64(agg.CoreFragmentsTotal), float64(agg.TotalVariants))),
		})
	}
	sort.Slice(perStrategyOut, func(i, j int) bool {
		left := perStrategyOut[i]["attackSuccessRate"].(float64)
		right := perStrategyOut[j]["attackSuccessRate"].(float64)
		return left > right
	})

	metrics := map[string]any{
		"targetVulnType":      meta.TargetVulnType,
		"attackPipeline":      []string{"core-fragment-search", "fake-call-chain-replacement", "unreachable-path-hiding"},
		"attackableContracts": attackableContracts,
		"totalAdversarial":    totalVariants,
		"attackSuccesses":     attackSuccesses,
		"attackSuccessRate":   round4(attackSuccessRate),
		"origAccuracy":        round4(origAccuracy),
		"advAccuracy":         round4(advAccuracy),
		"accuracyDropRate":    round4(accuracyDropRate),
		"avgConfidenceDrop":   round4(averageConfidenceDrop(perContract)),
		"perStrategy":         perStrategyOut,
		"perContract":         perContract,
	}

	finish := time.Now()
	_ = s.DB.WithContext(ctx).Model(&model.RobustJob{}).Where("id = ?", jobID).
		Updates(map[string]any{
			"status":       model.RobustJobStatusSuccess,
			"metrics_json": mustMarshal(metrics),
			"finished_at":  finish,
		}).Error
}

func (s *RobustService) loadModelMetadata(artifact string) (*modelArtifactMetadata, error) {
	modelDir, err := resolveArtifactPath(artifact)
	if err != nil {
		return nil, err
	}
	metadataPath := filepath.Join(modelDir, "metadata.json")
	var meta modelArtifactMetadata
	if err := readJSONFile(metadataPath, &meta); err != nil {
		return nil, fmt.Errorf("读取模型元数据失败: %w", err)
	}
	if strings.TrimSpace(meta.TargetVulnType) == "" {
		return nil, fmt.Errorf("模型元数据缺少 target_vuln_type")
	}
	return &meta, nil
}

func (s *RobustService) searchCoreFragments(artifact, promptText, processedSource, targetVulnType string, baseVulnScore float64, maxFragments int) []robustCoreFragment {
	lines := strings.Split(processedSource, "\n")
	candidates := candidateLineIndexes(lines, targetVulnType)
	if len(candidates) == 0 {
		for idx, line := range lines {
			if strings.TrimSpace(line) != "" {
				candidates = append(candidates, idx)
			}
		}
	}

	fragments := make([]robustCoreFragment, 0, len(candidates))
	for _, idx := range candidates {
		line := strings.TrimSpace(lines[idx])
		if line == "" {
			continue
		}
		masked := append([]string(nil), lines...)
		masked[idx] = ""
		result, err := s.Detector.runModelInference(artifact, strings.Join(masked, "\n"), promptText)
		if err != nil {
			continue
		}
		vulnScore := scoreForLabel(result, "vulnerable")
		sensitivity := math.Max(0, baseVulnScore-vulnScore)
		if result.Label == string(model.LabelNonVulnerable) {
			sensitivity += 0.25
		}
		fragments = append(fragments, robustCoreFragment{
			Index:       len(fragments),
			LineNumber:  idx + 1,
			Content:     line,
			Sensitivity: round4(sensitivity),
			VulnScore:   round4(vulnScore),
			Label:       result.Label,
		})
	}

	sort.Slice(fragments, func(i, j int) bool {
		if fragments[i].Sensitivity == fragments[j].Sensitivity {
			return fragments[i].LineNumber < fragments[j].LineNumber
		}
		return fragments[i].Sensitivity > fragments[j].Sensitivity
	})
	if maxFragments > 0 && len(fragments) > maxFragments {
		fragments = fragments[:maxFragments]
	}
	return fragments
}

func candidateLineIndexes(lines []string, targetVulnType string) []int {
	keywords := map[string][]string{
		"reentrancy":     {"call.value", ".call{", ".call(", ".send(", ".transfer(", "delegatecall"},
		"access_control": {"tx.origin", "msg.sender", "onlyowner", "owner", "require("},
		"arithmetic":     {"unchecked", "+", "-", "*", "/", "++", "--"},
	}
	selected := keywords[strings.TrimSpace(targetVulnType)]
	indexes := make([]int, 0)
	for idx, line := range lines {
		trimmed := strings.TrimSpace(strings.ToLower(line))
		if trimmed == "" {
			continue
		}
		for _, keyword := range selected {
			if strings.Contains(trimmed, strings.ToLower(keyword)) {
				indexes = append(indexes, idx)
				break
			}
		}
	}
	return indexes
}

func buildCallChainHidingAdversarial(contract model.Contract, fragments []robustCoreFragment, variantIndex int) (string, string, robustAttackSample, error) {
	if len(fragments) == 0 {
		return "", "", robustAttackSample{}, fmt.Errorf("no fragments selected")
	}

	sourceLines := strings.Split(contract.Source, "\n")
	processedLines := strings.Split(contract.ProcessedSource, "\n")
	opaqueGuards := make([]string, 0, len(fragments))
	wrapperNames := make([]string, 0, len(fragments))
	wrappersSource := make([]string, 0, len(fragments))
	wrappersProcessed := make([]string, 0, len(fragments))

	for i, fragment := range fragments {
		lineIdx := fragment.LineNumber - 1
		if lineIdx < 0 || lineIdx >= len(processedLines) {
			continue
		}
		indent := leadingIndent(processedLines[lineIdx])
		guardName := fmt.Sprintf("__robust_guard_%d_%d", variantIndex, i)
		wrapperName := fmt.Sprintf("__robust_hidden_call_%d_%d", variantIndex, i)
		guardLine := fmt.Sprintf("%suint256 %s = 1; if ((%s + 1) >= 1) { %s(); }", indent, guardName, guardName, wrapperName)
		opaqueGuards = append(opaqueGuards, guardName)
		wrapperNames = append(wrapperNames, wrapperName)

		processedTarget := strings.TrimSpace(processedLines[lineIdx])
		processedLines[lineIdx] = guardLine
		wrappersProcessed = append(wrappersProcessed, buildWrapperFunction(wrapperName, processedTarget))

		sourceLineIdx := findMatchingLine(sourceLines, fragment.Content)
		if sourceLineIdx >= 0 {
			sourceIndent := leadingIndent(sourceLines[sourceLineIdx])
			sourceTarget := strings.TrimSpace(sourceLines[sourceLineIdx])
			sourceLines[sourceLineIdx] = fmt.Sprintf("%suint256 %s = 1; if ((%s + 1) >= 1) { %s(); }", sourceIndent, guardName, guardName, wrapperName)
			wrappersSource = append(wrappersSource, buildWrapperFunction(wrapperName, sourceTarget))
		}
	}

	advProcessed := injectWrappers(strings.Join(processedLines, "\n"), wrappersProcessed)
	advSource := injectWrappers(strings.Join(sourceLines, "\n"), wrappersSource)
	detail := robustAttackSample{
		VariantIndex:  variantIndex,
		FragmentsUsed: fragments,
		OpaqueGuards:  opaqueGuards,
		WrapperNames:  wrapperNames,
	}
	return advSource, advProcessed, detail, nil
}

func buildWrapperFunction(wrapperName, body string) string {
	statement := strings.TrimSpace(body)
	if statement == "" {
		statement = "// empty"
	}
	return fmt.Sprintf("    function %s() private {\n        %s\n    }\n", wrapperName, statement)
}

func injectWrappers(source string, wrappers []string) string {
	if len(wrappers) == 0 {
		return source
	}
	insert := "\n" + strings.Join(wrappers, "\n")
	lastBrace := strings.LastIndex(source, "}")
	if lastBrace == -1 {
		return source + insert
	}
	return source[:lastBrace] + insert + source[lastBrace:]
}

func findMatchingLine(lines []string, content string) int {
	target := strings.TrimSpace(content)
	for idx, line := range lines {
		if strings.TrimSpace(line) == target {
			return idx
		}
	}
	return -1
}

func leadingIndent(line string) string {
	var b strings.Builder
	for _, r := range line {
		if r == ' ' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		break
	}
	return b.String()
}

func scoreForLabel(result *modelInferenceResult, label string) float64 {
	if result == nil {
		return 0
	}
	if result.Scores != nil {
		if v, ok := result.Scores[label]; ok {
			return v
		}
	}
	normalized := strings.ToLower(strings.ReplaceAll(label, "-", "_"))
	for _, item := range result.TopK {
		if strings.ToLower(strings.ReplaceAll(item.Token, "-", "_")) == normalized {
			return item.Score
		}
	}
	return 0
}

func averageConfidenceDrop(rows []robustPerContract) float64 {
	total := 0.0
	count := 0
	for _, row := range rows {
		if row.AdvTotal == 0 {
			continue
		}
		total += row.AvgConfDrop
		count++
	}
	return safeDiv(total, float64(maxInt(count, 1)))
}

func averageFragmentsPerStrategy(strategy string, agg map[string]*robustStrategyAgg) float64 {
	item, ok := agg[strategy]
	if !ok || item.TotalVariants == 0 {
		return 0
	}
	return round4(safeDiv(float64(item.CoreFragmentsTotal), float64(item.TotalVariants)))
}

func mustMarshal(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func readJSONFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func safeDiv(numerator, denominator float64) float64 {
	if denominator == 0 {
		return 0
	}
	return numerator / denominator
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *RobustService) fail(jobID string, err error) {
	finish := time.Now()
	_ = s.DB.Model(&model.RobustJob{}).Where("id = ?", jobID).Updates(map[string]any{
		"status":      model.RobustJobStatusFailed,
		"error":       err.Error(),
		"finished_at": finish,
	}).Error
}
