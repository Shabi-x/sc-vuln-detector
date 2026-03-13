package model

import "time"

// Contract 存储已上传并预处理过的智能合约
type Contract struct {
	ID string `gorm:"primaryKey;size:36" json:"id"`

	Name string `gorm:"not null;size:256" json:"name"` // 文件名或自定义名称

	Source          string `gorm:"not null;type:text" json:"source"`
	ProcessedSource string `gorm:"not null;type:text" json:"processedSource"`

	OriginalLines    int     `gorm:"not null" json:"originalLines"`
	ProcessedLines   int     `gorm:"not null" json:"processedLines"`
	RemovedLines     int     `gorm:"not null" json:"removedLines"`
	CompressionRatio float64 `gorm:"not null" json:"compressionRatio"`

	CreatedAt time.Time `gorm:"not null;autoCreateTime" json:"createdAt"`
	UpdatedAt time.Time `gorm:"not null;autoUpdateTime" json:"updatedAt"`
}

func (Contract) TableName() string { return "contracts" }

