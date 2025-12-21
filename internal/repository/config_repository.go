package repository

import (
	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// ConfigRepository handles system config database operations
type ConfigRepository struct {
	db *gorm.DB
}

// NewConfigRepository creates a new ConfigRepository
func NewConfigRepository(db *gorm.DB) *ConfigRepository {
	return &ConfigRepository{db: db}
}

// Get gets a config value by key
func (r *ConfigRepository) Get(key string) (string, error) {
	var config model.SystemConfig
	err := r.db.Where("key = ?", key).First(&config).Error
	if err != nil {
		return "", err
	}
	return config.Value, nil
}

// Set sets a config value
func (r *ConfigRepository) Set(key, value string) error {
	var config model.SystemConfig
	err := r.db.Where("key = ?", key).First(&config).Error
	if err == gorm.ErrRecordNotFound {
		config = model.SystemConfig{Key: key, Value: value}
		return r.db.Create(&config).Error
	}
	if err != nil {
		return err
	}
	config.Value = value
	return r.db.Save(&config).Error
}

// GetAll gets all config values
func (r *ConfigRepository) GetAll() (map[string]string, error) {
	var configs []model.SystemConfig
	err := r.db.Find(&configs).Error
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for _, config := range configs {
		result[config.Key] = config.Value
	}
	return result, nil
}

// Delete deletes a config value
func (r *ConfigRepository) Delete(key string) error {
	return r.db.Where("key = ?", key).Delete(&model.SystemConfig{}).Error
}
