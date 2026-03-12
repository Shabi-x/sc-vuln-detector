package model

import "time"

type TrainJobStatus string

const (
	TrainJobStatusQueued   TrainJobStatus = "queued"
	TrainJobStatusRunning  TrainJobStatus = "running"
	TrainJobStatusSuccess  TrainJobStatus = "success"
	TrainJobStatusFailed   TrainJobStatus = "failed"
	TrainJobStatusCanceled TrainJobStatus = "canceled"
)

// TrainJob 小样本训练任务
type TrainJob struct {
	ID string `gorm:"primaryKey;size:36" json:"id"`

	PromptID    string          `gorm:"not null;size:36;index" json:"promptId"`
	Status      TrainJobStatus  `gorm:"not null;size:16;index" json:"status"`
	FewshotSize int             `gorm:"not null;default:64" json:"fewshotSize"`
	ParamsJSON  string          `gorm:"not null;default:'';type:text" json:"paramsJson"` // 训练超参快照
	Error       string          `gorm:"not null;default:'';type:text" json:"error"`
	DatasetRef  string          `gorm:"not null;default:'';size:256" json:"datasetRef"` // 预留：数据集标识
	StartedAt   *time.Time      `json:"startedAt"`
	FinishedAt  *time.Time      `json:"finishedAt"`
	CreatedAt   time.Time       `gorm:"not null;autoCreateTime" json:"createdAt"`
	UpdatedAt   time.Time       `gorm:"not null;autoUpdateTime" json:"updatedAt"`
	Metrics     []TrainMetric   `gorm:"foreignKey:JobID" json:"-"`
	Models      []TrainedModel  `gorm:"foreignKey:TrainJobID" json:"-"`
}

func (TrainJob) TableName() string { return "train_jobs" }

// TrainMetric 训练过程中的指标点（用于前端画曲线）
type TrainMetric struct {
	ID        string  `gorm:"primaryKey;size:36" json:"id"`
	JobID     string  `gorm:"not null;size:36;index" json:"jobId"`
	Step      int     `gorm:"not null;index" json:"step"`  // 可以表示 step 或 epoch
	Epoch     int     `gorm:"not null;index" json:"epoch"` // 预留更精细控制
	Loss      float64 `gorm:"not null" json:"loss"`
	Acc       float64 `gorm:"not null" json:"acc"`
	F1        float64 `gorm:"not null" json:"f1"`
	CreatedAt time.Time `gorm:"not null;autoCreateTime" json:"createdAt"`
}

func (TrainMetric) TableName() string { return "train_metrics" }

// TrainedModel 训练得到的模型产物登记
type TrainedModel struct {
	ID         string    `gorm:"primaryKey;size:36" json:"id"`
	TrainJobID string    `gorm:"not null;size:36;index" json:"trainJobId"`
	Name       string    `gorm:"not null;size:128" json:"name"`
	BaseModel  string    `gorm:"not null;size:64" json:"baseModel"`    // CodeBERT / CodeT5 等
	PromptID   string    `gorm:"not null;size:36;index" json:"promptId"` // 训练时使用的 prompt
	Artifact   string    `gorm:"not null;size:256" json:"artifact"`    // 模型文件路径占位
	MetricsJSON string   `gorm:"not null;type:text;default:''" json:"metricsJson"` // 最终指标快照
	IsLoaded   bool      `gorm:"not null;default:false;index" json:"isLoaded"`     // 是否为当前加载模型
	CreatedAt  time.Time `gorm:"not null;autoCreateTime" json:"createdAt"`
	UpdatedAt  time.Time `gorm:"not null;autoUpdateTime" json:"updatedAt"`
}

func (TrainedModel) TableName() string { return "models" }

