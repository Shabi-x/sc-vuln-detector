package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
)

const (
	RobustStrategyDIPAttack = "dip-attack"
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
	VictimModels   []string `json:"victimModels"`
	Strategies     []string `json:"strategies"`
	VariantsPerSrc int      `json:"variantsPerSource"`
}

type robustConfig struct {
	ContractIDs       []string `json:"contractIds"`
	VictimModels      []string `json:"victimModels"`
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

type dipInferenceSummary struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	VulnScore  float64 `json:"vulnScore"`
	ElapsedMS  int     `json:"elapsedMs"`
}

type dipAttackVariant struct {
	VariantIndex              int                 `json:"variantIndex"`
	Success                   bool                `json:"success"`
	Queries                   int                 `json:"queries"`
	QueryBudgetHit            bool                `json:"queryBudgetHit"`
	PerturbationTokens        int                 `json:"perturbationTokens"`
	OriginalTokens            int                 `json:"originalTokens"`
	PerturbationRate          float64             `json:"perturbationRate"`
	VisiblePerturbationTokens int                 `json:"visiblePerturbationTokens"`
	VisibleWindowTokens       int                 `json:"visibleWindowTokens"`
	VisiblePerturbationRate   float64             `json:"visiblePerturbationRate"`
	CodeBLEU                  float64             `json:"codebleu"`
	AdvCode                   string              `json:"advCode"`
	Baseline                  dipInferenceSummary `json:"baseline"`
	Adversarial               dipInferenceSummary `json:"adversarial"`
	ConfidenceDrop            float64             `json:"confidenceDrop"`
	VulnScoreDrop             float64             `json:"vulnScoreDrop"`
	VisibleLineEnd            int                 `json:"visibleLineEnd"`
}

type dipAttackResult struct {
	TargetVulnType        string              `json:"targetVulnType"`
	Baseline              dipInferenceSummary `json:"baseline"`
	Variants              []dipAttackVariant  `json:"variants"`
	Attackable            bool                `json:"attackable"`
	MaxLength             int                 `json:"maxLength"`
	VisibleLineEnd        int                 `json:"visibleLineEnd"`
	OriginalVisibleTokens int                 `json:"originalVisibleTokens"`
	OriginalTotalTokens   int                 `json:"originalTotalTokens"`
}

type robustAttackSample struct {
	VariantIndex            int     `json:"variantIndex"`
	Queries                 int     `json:"queries"`
	PerturbationTokens      int     `json:"perturbationTokens"`
	OriginalTokens          int     `json:"originalTokens"`
	PerturbationRate        float64 `json:"perturbationRate"`
	ConfidenceDrop          float64 `json:"confidenceDrop"`
	VulnScoreDrop           float64 `json:"vulnScoreDrop"`
	VisiblePerturbationRate float64 `json:"visiblePerturbationRate"`
	CodeBLEU                float64 `json:"codebleu"`
	QueryBudgetHit          bool    `json:"queryBudgetHit"`
	AttackSucceeded         bool    `json:"attackSucceeded"`
}

type robustPerContract struct {
	BaseContractID             string              `json:"baseContractId"`
	ContractName               string              `json:"contractName"`
	OrigLabel                  model.Label         `json:"origLabel"`
	OrigConfidence             float64             `json:"origConfidence"`
	OrigVulnScore              float64             `json:"origVulnScore"`
	Attackable                 bool                `json:"attackable"`
	SkippedReason              string              `json:"skippedReason"`
	AdvTotal                   int                 `json:"advTotal"`
	Flipped                    int                 `json:"flipped"`
	AvgAdvConfidence           float64             `json:"avgAdvConfidence"`
	AvgConfDrop                float64             `json:"avgConfDrop"`
	AvgQueries                 float64             `json:"avgQueries"`
	AvgPerturbationRate        float64             `json:"avgPerturbationRate"`
	AvgVisiblePerturbationRate float64             `json:"avgVisiblePerturbationRate"`
	AvgCodeBLEU                float64             `json:"avgCodeBLEU"`
	QueryBudgetHits            int                 `json:"queryBudgetHits"`
	BestAttackStrategy         string              `json:"bestAttackStrategy"`
	BestAttackSample           *robustAttackSample `json:"bestAttackSample,omitempty"`
	ByStrategy                 map[string]any      `json:"byStrategy"`
}

type robustStrategyAgg struct {
	TotalVariants              int
	AttackSuccesses            int
	ConfidenceDropSum          float64
	QuerySumAll                float64
	QuerySumSuccess            float64
	SuccessQueryCount          int
	PerturbationRateSumAll     float64
	PerturbationRateSumSuccess float64
	SuccessPerturbationCount   int
	VisiblePerturbationRateSum float64
	CodeBLEUSum                float64
	QueryBudgetHits            int
}

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
		req.Strategies = []string{RobustStrategyDIPAttack}
	}
	if len(req.VictimModels) == 0 {
		req.VictimModels = []string{"codebert", "AME", "GPSCVul", "ConvMHSA", "Clear"}
	}
	if req.VariantsPerSrc <= 0 {
		req.VariantsPerSrc = 1
	}
	if req.VariantsPerSrc > 5 {
		req.VariantsPerSrc = 5
	}

	confBytes, _ := json.Marshal(robustConfig{
		ContractIDs:       req.ContractIDs,
		VictimModels:      req.VictimModels,
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
		cfg.Strategies = []string{RobustStrategyDIPAttack}
	}
	if len(cfg.VictimModels) == 0 {
		cfg.VictimModels = []string{"codebert", "AME", "GPSCVul", "ConvMHSA", "Clear"}
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
	metrics, err := s.runMultiVictimRobustness(trainedModel.Artifact, prompt.TemplateText, meta.TargetVulnType, cfg.VictimModels, cfg.VariantsPerSource, contracts)
	if err != nil {
		s.fail(jobID, err)
		return
	}

	finish := time.Now()
	_ = s.DB.WithContext(ctx).Model(&model.RobustJob{}).Where("id = ?", jobID).
		Updates(map[string]any{
			"status":       model.RobustJobStatusSuccess,
			"metrics_json": mustMarshal(metrics),
			"finished_at":  finish,
		}).Error
}

func (s *RobustService) runDIPAttack(artifactPath, source, promptText string, variantsPerSource int) (*dipAttackResult, error) {
	modelDir, err := resolveArtifactPath(artifactPath)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(
		pythonExecutable(),
		filepath.ToSlash(filepath.Join("..", "python_scripts", "run_dip_attack.py")),
		"--model_dir", modelDir,
		"--variants", fmt.Sprintf("%d", variantsPerSource),
	)
	if strings.TrimSpace(promptText) != "" {
		cmd.Args = append(cmd.Args, "--prompt_text", promptText)
	}
	cmd.Stdin = strings.NewReader(source)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("DIP 攻击执行失败: %w; stderr=%s", err, strings.TrimSpace(stderr.String()))
	}

	var result dipAttackResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("解析 DIP 攻击结果失败: %w; stdout=%s; stderr=%s", err, strings.TrimSpace(string(output)), strings.TrimSpace(stderr.String()))
	}
	return &result, nil
}

func (s *RobustService) runMultiVictimRobustness(
	artifactPath, promptText, targetVulnType string,
	victimModels []string,
	variantsPerSource int,
	contracts []model.Contract,
) (map[string]any, error) {
	modelDir, err := resolveArtifactPath(artifactPath)
	if err != nil {
		return nil, err
	}

	payloadContracts := make([]map[string]string, 0, len(contracts))
	for _, contract := range contracts {
		payloadContracts = append(payloadContracts, map[string]string{
			"id":              contract.ID,
			"name":            contract.Name,
			"processedSource": contract.ProcessedSource,
		})
	}
	input := map[string]any{
		"contracts": payloadContracts,
	}
	inputBytes, _ := json.Marshal(input)

	cmd := exec.Command(
		pythonExecutable(),
		filepath.ToSlash(filepath.Join("..", "python_scripts", "run_multi_victim_robustness.py")),
		"--model_dir", modelDir,
		"--target_vuln_type", targetVulnType,
		"--victim_models", strings.Join(victimModels, ","),
		"--variants", fmt.Sprintf("%d", variantsPerSource),
	)
	if strings.TrimSpace(promptText) != "" {
		cmd.Args = append(cmd.Args, "--prompt_text", promptText)
	}
	cmd.Stdin = bytes.NewReader(inputBytes)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("多受害模型鲁棒性评估失败: %w; stderr=%s", err, strings.TrimSpace(stderr.String()))
	}

	var metrics map[string]any
	if err := json.Unmarshal(output, &metrics); err != nil {
		return nil, fmt.Errorf("解析多受害模型评估结果失败: %w; stdout=%s; stderr=%s", err, strings.TrimSpace(string(output)), strings.TrimSpace(stderr.String()))
	}
	return metrics, nil
}

func normalizeRobustStrategy(strategy string) string {
	if strings.TrimSpace(strategy) == "" {
		return RobustStrategyDIPAttack
	}
	return strings.TrimSpace(strategy)
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

func averageQueries(rows []robustPerContract) float64 {
	total := 0.0
	count := 0
	for _, row := range rows {
		if row.AdvTotal == 0 {
			continue
		}
		total += row.AvgQueries
		count++
	}
	return safeDiv(total, float64(maxInt(count, 1)))
}

func averagePerturbationRate(rows []robustPerContract) float64 {
	total := 0.0
	count := 0
	for _, row := range rows {
		if row.AdvTotal == 0 {
			continue
		}
		total += row.AvgPerturbationRate
		count++
	}
	return safeDiv(total, float64(maxInt(count, 1)))
}

func averageVisiblePerturbationRate(rows []robustPerContract) float64 {
	total := 0.0
	count := 0
	for _, row := range rows {
		if row.AdvTotal == 0 {
			continue
		}
		total += row.AvgVisiblePerturbationRate
		count++
	}
	return safeDiv(total, float64(maxInt(count, 1)))
}

func averageCodeBLEU(rows []robustPerContract) float64 {
	total := 0.0
	count := 0
	for _, row := range rows {
		if row.AdvTotal == 0 {
			continue
		}
		total += row.AvgCodeBLEU
		count++
	}
	return safeDiv(total, float64(maxInt(count, 1)))
}

func totalQueryBudgetHits(rows []robustPerContract) int {
	total := 0
	for _, row := range rows {
		total += row.QueryBudgetHits
	}
	return total
}

func buildVisibilityWarning(rows []robustPerContract) string {
	if len(rows) == 0 {
		return ""
	}
	totalVisible := 0.0
	totalPerturb := 0.0
	count := 0
	for _, row := range rows {
		if row.AdvTotal == 0 {
			continue
		}
		totalVisible += row.AvgVisiblePerturbationRate
		totalPerturb += row.AvgPerturbationRate
		count++
	}
	if count == 0 {
		return ""
	}
	avgVisible := safeDiv(totalVisible, float64(count))
	avgPerturb := safeDiv(totalPerturb, float64(count))
	if avgPerturb >= 0.2 && avgVisible <= 0.02 {
		return "本次攻击的大部分改动未进入模型实际可见的输入窗口，当前 0% 结果更偏向“攻击未有效命中模型输入”，不宜直接解释为模型鲁棒性强。"
	}
	return ""
}

func preferSuccessAverage(successSum float64, successCount int, allSum float64, allCount int) float64 {
	if successCount > 0 {
		return safeDiv(successSum, float64(successCount))
	}
	return safeDiv(allSum, float64(maxInt(allCount, 1)))
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
