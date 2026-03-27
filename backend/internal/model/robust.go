package model

import "time"

// AdversarialSample 对抗样本（基于某份原始合约生成的扰动版本）
type AdversarialSample struct {
	ID string `gorm:"primaryKey;size:36" json:"id"`

	BaseContractID string `gorm:"not null;size:36;index" json:"baseContractId"`
	Strategy       string `gorm:"not null;size:64;index" json:"strategy"`

	Source          string `gorm:"not null;type:text" json:"source"`
	ProcessedSource string `gorm:"not null;type:text" json:"processedSource"`

	DiffJSON string `gorm:"not null;default:'';type:text" json:"diffJson"`

	CreatedAt time.Time `gorm:"not null;autoCreateTime" json:"createdAt"`
}

func (AdversarialSample) TableName() string { return "adversarial_samples" }

type RobustJobStatus string

const (
	RobustJobStatusQueued  RobustJobStatus = "queued"
	RobustJobStatusRunning RobustJobStatus = "running"
	RobustJobStatusSuccess RobustJobStatus = "success"
	RobustJobStatusFailed  RobustJobStatus = "failed"
)

// RobustJob 鲁棒性评估任务
type RobustJob struct {
	ID string `gorm:"primaryKey;size:36" json:"id"`

	Status   RobustJobStatus `gorm:"not null;size:16;index" json:"status"`
	ModelID  string          `gorm:"not null;size:36;index" json:"modelId"`
	PromptID string          `gorm:"not null;size:36;index" json:"promptId"`

	AttackConfigJSON string `gorm:"not null;default:'';type:text" json:"attackConfigJson"`
	MetricsJSON      string `gorm:"not null;default:'';type:text" json:"metricsJson"`
	Error            string `gorm:"not null;default:'';type:text" json:"error"`

	StartedAt  *time.Time `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	CreatedAt  time.Time  `gorm:"not null;autoCreateTime" json:"createdAt"`
	UpdatedAt  time.Time  `gorm:"not null;autoUpdateTime" json:"updatedAt"`
}

func (RobustJob) TableName() string { return "robust_jobs" }
