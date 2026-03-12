package model

import "time"

type Label string

const (
	LabelVulnerable   Label = "vulnerable"   // 有漏洞
	LabelNonVulnerable Label = "nonVulnerable" // 无漏洞
)

type PromptMapping struct {
	ID       string `gorm:"primaryKey;size:36" json:"id"`
	PromptID string `gorm:"not null;size:36;index" json:"promptId"`

	Token string `gorm:"not null;size:64" json:"token"` // bad/good 等
	Label Label  `gorm:"not null;size:32;index" json:"label"`

	IsDefault bool `gorm:"not null;default:true;index" json:"isDefault"`

	CreatedAt time.Time `gorm:"not null;autoCreateTime" json:"createdAt"`
	UpdatedAt time.Time `gorm:"not null;autoUpdateTime" json:"updatedAt"`
}

func (PromptMapping) TableName() string { return "prompt_mappings" }

