package model

import "time"

type PromptType string

const (
	PromptTypeHard PromptType = "hard"
	PromptTypeSoft PromptType = "soft"
)

// Prompt 提示模板（硬提示/软提示配置）
// 硬提示：TemplateText 存模板字符串（要求包含 [X]，可选包含 [MASK]）
// 软提示：SoftConfigJSON 存参数配置（JSON 字符串），TemplateText 可为空
type Prompt struct {
	ID          string     `gorm:"primaryKey;size:36" json:"id"`
	Name        string     `gorm:"not null;size:128" json:"name"`
	Type        PromptType `gorm:"not null;size:16;index" json:"type"`
	Description string     `gorm:"not null;default:'';size:512" json:"description"`

	TemplateText   string `gorm:"not null;default:'';type:text" json:"templateText"`
	SoftConfigJSON string `gorm:"not null;default:'';type:text" json:"softConfigJson"`

	IsPreset bool `gorm:"not null;default:false;index" json:"isPreset"`
	IsActive bool `gorm:"not null;default:true;index" json:"isActive"`

	CreatedAt time.Time `gorm:"not null;autoCreateTime" json:"createdAt"`
	UpdatedAt time.Time `gorm:"not null;autoUpdateTime" json:"updatedAt"`
}

func (Prompt) TableName() string { return "prompts" }

