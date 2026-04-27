package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
)

// Trainer 负责调度训练任务。当前实现为 Python Demo 版本，用于打通“后端编排 → Python 训练 → 指标/产物落库”的链路。
type Trainer struct {
	DB *gorm.DB
}

func NewTrainer(db *gorm.DB) *Trainer {
	return &Trainer{DB: db}
}

type TrainRequest struct {
	PromptID    string         `json:"promptId"`
	FewshotSize int            `json:"fewshotSize"`
	Params      map[string]any `json:"params"`
	DatasetRef  string         `json:"datasetRef"`
}

// CreateJob 创建训练任务并启动异步模拟训练。
func (t *Trainer) CreateJob(ctx context.Context, req TrainRequest) (*model.TrainJob, error) {
	if t.DB == nil {
		return nil, gorm.ErrInvalidDB
	}
	if req.FewshotSize <= 0 {
		req.FewshotSize = 32
	}
	if req.FewshotSize > 64 {
		req.FewshotSize = 64
	}

	paramsBytes, _ := json.Marshal(req.Params)
	job := &model.TrainJob{
		ID:          uuid.NewString(),
		PromptID:    req.PromptID,
		Status:      model.TrainJobStatusQueued,
		FewshotSize: req.FewshotSize,
		ParamsJSON:  string(paramsBytes),
		DatasetRef:  req.DatasetRef,
	}

	if err := t.DB.WithContext(ctx).Create(job).Error; err != nil {
		return nil, err
	}

	go t.runPython(job.ID)

	return job, nil
}

func (t *Trainer) runPython(jobID string) {
	ctx := context.Background()

	var job model.TrainJob
	if err := t.DB.WithContext(ctx).First(&job, "id = ?", jobID).Error; err != nil {
		log.Printf("load job %s failed: %v", jobID, err)
		return
	}

	var prompt model.Prompt
	_ = t.DB.WithContext(ctx).First(&prompt, "id = ?", job.PromptID).Error

	if err := t.DB.WithContext(ctx).Model(&model.TrainJob{}).
		Where("id = ?", jobID).
		Updates(map[string]any{
			"status":     model.TrainJobStatusRunning,
			"started_at": time.Now(),
			"error":      "",
		}).Error; err != nil {
		log.Printf("start job %s failed: %v", jobID, err)
		return
	}

	epochs, batchSize, lr, baseModel, maxLength, seed, valRatio, targetVulnType := parseParams(job.ParamsJSON)
	datasetPath := datasetRefToPath(job.DatasetRef)
	if datasetPath == "" {
		t.failJob(jobID, fmt.Errorf("无法解析数据集: %s", job.DatasetRef))
		return
	}
	if targetVulnType == "" {
		t.failJob(jobID, fmt.Errorf("未指定目标漏洞类型"))
		return
	}

	cmd := exec.Command(
		pythonExecutable(),
		filepath.ToSlash(filepath.Join("..", "python_scripts", "train_demo.py")),
		"--job_id", jobID,
		"--fewshot_size", strconv.Itoa(job.FewshotSize),
		"--epochs", strconv.Itoa(epochs),
		"--batch_size", strconv.Itoa(batchSize),
		"--learning_rate", fmt.Sprintf("%g", lr),
		"--base_model", baseModel,
		"--max_length", strconv.Itoa(maxLength),
		"--seed", strconv.Itoa(seed),
		"--val_ratio", fmt.Sprintf("%g", valRatio),
		"--target_vuln_type", targetVulnType,
		"--out_dir", filepath.ToSlash(filepath.Join("..", "python_scripts", "demo_outputs")),
	)
	if prompt.TemplateText != "" {
		cmd.Args = append(cmd.Args, "--prompt_text", prompt.TemplateText)
	}
	if datasetPath != "" {
		cmd.Args = append(cmd.Args, "--dataset_path", datasetPath)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.failJob(jobID, fmt.Errorf("stdout pipe: %w", err))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.failJob(jobID, fmt.Errorf("stderr pipe: %w", err))
		return
	}

	if err := cmd.Start(); err != nil {
		t.failJob(jobID, fmt.Errorf("start python: %w", err))
		return
	}

	// 读取 stderr（用于失败诊断）
	errBuf := readAllAsync(stderr)

	// 解析 stdout 的 json 行，落库 metrics
	var summary map[string]any
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Bytes()
		var m map[string]any
		if e := json.Unmarshal(line, &m); e != nil {
			continue
		}
		typ, _ := m["type"].(string)
		if typ == "metric" {
			epoch := toInt(m["epoch"])
			step := epoch
			metric := model.TrainMetric{
				ID:    uuid.NewString(),
				JobID: jobID,
				Step:  step,
				Epoch: epoch,
				Loss:  toFloat(m["loss"]),
				Acc:   toFloat(m["acc"]),
				F1:    toFloat(m["f1"]),
			}
			_ = t.DB.WithContext(ctx).Create(&metric).Error
		}
		if typ == "summary" {
			summary = m
		}
	}

	waitErr := cmd.Wait()
	if waitErr != nil {
		t.failJob(jobID, fmt.Errorf("python failed: %w; stderr=%s", waitErr, <-errBuf))
		return
	}

	artifact := ""
	best := map[string]any{}
	baseModelName := baseModel
	if summary != nil {
		if v, ok := summary["artifact"].(string); ok {
			artifact = v
		}
		if v, ok := summary["best"].(map[string]any); ok {
			best = v
		}
		if v, ok := summary["base_model"].(string); ok && strings.TrimSpace(v) != "" {
			baseModelName = v
		}
	}

	metricsJSON, _ := json.Marshal(best)
	modelRec := &model.TrainedModel{
		ID:          uuid.NewString(),
		TrainJobID:  jobID,
		Name:        buildModelName(baseModelName, targetVulnType, job.FewshotSize, epochs, time.Now()),
		BaseModel:   baseModelName,
		PromptID:    job.PromptID,
		Artifact:    artifact,
		MetricsJSON: string(metricsJSON),
		IsLoaded:    false,
	}

	if err := t.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(modelRec).Error; err != nil {
			return err
		}
		return tx.Model(&model.TrainJob{}).Where("id = ?", jobID).
			Updates(map[string]any{
				"status":      model.TrainJobStatusSuccess,
				"finished_at": time.Now(),
			}).Error
	}); err != nil {
		t.failJob(jobID, err)
		return
	}
}

func parseParams(paramsJSON string) (epochs int, batchSize int, lr float64, baseModel string, maxLength int, seed int, valRatio float64, targetVulnType string) {
	epochs = 10
	batchSize = 8
	lr = 5e-5
	baseModel = "microsoft/codebert-base"
	maxLength = 256
	seed = 42
	valRatio = 0.2
	targetVulnType = "reentrancy"
	if paramsJSON == "" {
		return
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(paramsJSON), &m); err != nil {
		return
	}
	if v, ok := m["epochs"]; ok {
		epochs = toInt(v)
	}
	if v, ok := m["batchSize"]; ok {
		batchSize = toInt(v)
	}
	if v, ok := m["learningRate"]; ok {
		lr = toFloat(v)
	}
	if v, ok := m["baseModel"]; ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			baseModel = strings.TrimSpace(s)
		}
	}
	if v, ok := m["maxLength"]; ok {
		maxLength = toInt(v)
	}
	if v, ok := m["seed"]; ok {
		seed = toInt(v)
	}
	if v, ok := m["valRatio"]; ok {
		valRatio = toFloat(v)
	}
	if v, ok := m["targetVulnType"]; ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			targetVulnType = sanitizeNameToken(s)
		}
	}
	if epochs <= 0 {
		epochs = 10
	}
	if batchSize <= 0 {
		batchSize = 8
	}
	if lr <= 0 {
		lr = 5e-5
	}
	if maxLength <= 0 {
		maxLength = 256
	}
	if seed <= 0 {
		seed = 42
	}
	if valRatio <= 0 || valRatio >= 0.5 {
		valRatio = 0.2
	}
	if targetVulnType == "" {
		targetVulnType = "reentrancy"
	}
	return
}

func datasetRefToPath(ref string) string {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" || trimmed == "demo" {
		return filepath.ToSlash(filepath.Join("..", "python_scripts", "datasets", "demo.jsonl"))
	}
	if trimmed == "smartbugs-curated" || trimmed == "smartbugs-3class" {
		return filepath.ToSlash(filepath.Join("..", "python_scripts", "datasets", "smartbugs-curated"))
	}
	if filepath.IsAbs(trimmed) {
		if _, err := os.Stat(trimmed); err == nil {
			return trimmed
		}
		return ""
	}
	if strings.HasPrefix(trimmed, "local:") {
		p := strings.TrimSpace(strings.TrimPrefix(trimmed, "local:"))
		if filepath.IsAbs(p) {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

func pythonExecutable() string {
	candidates := []string{
		filepath.ToSlash(filepath.Join("..", ".venv", "bin", "python")),
		filepath.ToSlash(filepath.Join(".venv", "bin", "python")),
		"python3",
	}
	for _, candidate := range candidates {
		if candidate == "python3" {
			return candidate
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "python3"
}

func buildModelName(baseModel string, targetVulnType string, fewshotSize int, epochs int, createdAt time.Time) string {
	modelPart := normalizeBaseModelName(baseModel)
	targetPart := sanitizeNameToken(targetVulnType)
	if targetPart == "" {
		targetPart = "vulnerability"
	}
	if fewshotSize <= 0 {
		fewshotSize = 1
	}
	if epochs <= 0 {
		epochs = 1
	}
	return fmt.Sprintf(
		"%s-%s-fs%d-e%d-%s",
		modelPart,
		targetPart,
		fewshotSize,
		epochs,
		createdAt.Format("20060102-150405"),
	)
}

func normalizeBaseModelName(baseModel string) string {
	trimmed := strings.TrimSpace(strings.ToLower(baseModel))
	if trimmed == "" {
		return "model"
	}
	parts := strings.Split(trimmed, "/")
	last := parts[len(parts)-1]
	last = strings.TrimSuffix(last, "-base")
	last = strings.TrimSuffix(last, "-small")
	last = strings.TrimSuffix(last, "-large")
	last = sanitizeNameToken(last)
	if last == "" {
		return "model"
	}
	return last
}

func sanitizeNameToken(value string) string {
	re := regexp.MustCompile(`[^a-z0-9]+`)
	sanitized := re.ReplaceAllString(strings.ToLower(strings.TrimSpace(value)), "-")
	sanitized = strings.Trim(sanitized, "-")
	if sanitized == "" {
		return "item"
	}
	return sanitized
}

func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		i, _ := strconv.Atoi(x)
		return i
	default:
		return 0
	}
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	default:
		return 0
	}
}

func readAllAsync(r interface{ Read([]byte) (int, error) }) <-chan string {
	ch := make(chan string, 1)
	go func() {
		defer close(ch)
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		ch <- string(buf)
	}()
	return ch
}

func (t *Trainer) failJob(jobID string, err error) {
	ctx := context.Background()
	log.Printf("job %s failed: %v", jobID, err)
	_ = t.DB.WithContext(ctx).Model(&model.TrainJob{}).Where("id = ?", jobID).
		Updates(map[string]any{
			"status":      model.TrainJobStatusFailed,
			"finished_at": time.Now(),
			"error":       err.Error(),
		}).Error
}
