package store

import (
	"fmt"

	"gorm.io/gorm"

	"sc-vuln-detector/backend/internal/model"
)

func AutoMigrate(gdb *gorm.DB) error {
	if gdb == nil {
		return fmt.Errorf("db is nil")
	}
	return gdb.AutoMigrate(
		&model.Contract{},
		&model.Prompt{},
		&model.PromptMapping{},
		&model.TrainJob{},
		&model.TrainMetric{},
		&model.TrainedModel{},
		&model.DetectJob{},
		&model.DetectResult{},
	)
}
