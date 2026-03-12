package store

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
)

// SeedPresetPrompts 初始化预置模板（幂等）
func SeedPresetPrompts(gdb *gorm.DB) error {
	if gdb == nil {
		return fmt.Errorf("db is nil")
	}

	var cnt int64
	if err := gdb.Model(&model.Prompt{}).Where("is_preset = ?", true).Count(&cnt).Error; err != nil {
		return err
	}
	if cnt > 0 {
		return nil
	}

	p := model.Prompt{
		ID:           uuid.NewString(),
		Name:         "Hard Prompt - 基础二分类",
		Type:         model.PromptTypeHard,
		Description:  "课题预设模板：用于有漏洞/无漏洞二分类（示例）。",
		TemplateText: "The code [X] is [MASK].",
		IsPreset:     true,
		IsActive:     true,
	}
	if err := gdb.Create(&p).Error; err != nil {
		return err
	}

	m1 := model.PromptMapping{
		ID:        uuid.NewString(),
		PromptID:  p.ID,
		Token:     "bad",
		Label:     model.LabelVulnerable,
		IsDefault: true,
	}
	m2 := model.PromptMapping{
		ID:        uuid.NewString(),
		PromptID:  p.ID,
		Token:     "good",
		Label:     model.LabelNonVulnerable,
		IsDefault: true,
	}
	if err := gdb.Create(&m1).Error; err != nil {
		return err
	}
	if err := gdb.Create(&m2).Error; err != nil {
		return err
	}

	return nil
}

