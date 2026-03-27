package model

import "time"

type DetectJobStatus string

const (
	DetectJobStatusQueued  DetectJobStatus = "queued"
	DetectJobStatusRunning DetectJobStatus = "running"
	DetectJobStatusSuccess DetectJobStatus = "success"
	DetectJobStatusFailed  DetectJobStatus = "failed"
)

// DetectJob 批量检测任务
type DetectJob struct {
	ID string `gorm:"primaryKey;size:36" json:"id"`

	Status   DetectJobStatus `gorm:"not null;size:16;index" json:"status"`
	PromptID string          `gorm:"not null;size:36;index" json:"promptId"`
	ModelID  string          `gorm:"not null;size:36;index" json:"modelId"`

	ParamsJSON string `gorm:"not null;default:'';type:text" json:"paramsJson"`
	ResultJSON string `gorm:"not null;default:'';type:text" json:"resultJson"`
	Error      string `gorm:"not null;default:'';type:text" json:"error"`

	StartedAt  *time.Time `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	CreatedAt  time.Time  `gorm:"not null;autoCreateTime" json:"createdAt"`
	UpdatedAt  time.Time  `gorm:"not null;autoUpdateTime" json:"updatedAt"`
}

func (DetectJob) TableName() string { return "detect_jobs" }

// DetectResult 单份合约检测结果（单检/批检都落库）
type DetectResult struct {
	ID string `gorm:"primaryKey;size:36" json:"id"`

	JobID        string  `gorm:"not null;default:'';size:36;index" json:"jobId"`
	ContractID   string  `gorm:"not null;size:36;index" json:"contractId"`
	ModelID      string  `gorm:"not null;size:36;index" json:"modelId"`
	PromptID     string  `gorm:"not null;size:36;index" json:"promptId"`
	Label        Label   `gorm:"not null;size:32;index" json:"label"`
	Confidence   float64 `gorm:"not null" json:"confidence"`
	VulnType     string  `gorm:"not null;default:'';size:64" json:"vulnType"`
	MatchedToken string  `gorm:"not null;default:'';size:64" json:"matchedToken"`
	TopKJSON     string  `gorm:"not null;default:'';type:text" json:"topKJson"`
	ElapsedMS    int     `gorm:"not null;default:0" json:"elapsedMs"`

	CreatedAt time.Time `gorm:"not null;autoCreateTime" json:"createdAt"`
}

func (DetectResult) TableName() string { return "detect_results" }
