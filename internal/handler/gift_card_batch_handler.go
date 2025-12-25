package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/e54385991/Common-LoginService/internal/repository"
	"github.com/gin-gonic/gin"
)

// Constants for batch gift card processing
const (
	// BatchGiftCardDelay is the delay between distributing each gift card
	BatchGiftCardDelay = 10 * time.Millisecond
	// BatchGiftCardProgressUpdateInterval is how often to update progress
	BatchGiftCardProgressUpdateInterval = 10
)

// GiftCardBatchHandler handles batch gift card distribution requests
type GiftCardBatchHandler struct {
	cfg                *config.Config
	giftCardRepo       *repository.GiftCardRepository
	batchTaskRepo      *repository.GiftCardBatchTaskRepository
	userRepo           *repository.UserRepository
	messageRepo        *repository.MessageRepository

	// Active batch tasks for progress tracking
	batchProgress     map[uint]*GiftCardBatchProgress
	batchProgressLock sync.RWMutex
}

// GiftCardBatchProgress tracks the progress of a batch gift card task
type GiftCardBatchProgress struct {
	TaskID      uint   `json:"task_id"`
	TotalUsers  int    `json:"total_users"`
	SentCount   int    `json:"sent_count"`
	FailedCount int    `json:"failed_count"`
	Status      string `json:"status"`
}

// NewGiftCardBatchHandler creates a new GiftCardBatchHandler
func NewGiftCardBatchHandler(cfg *config.Config, giftCardRepo *repository.GiftCardRepository, batchTaskRepo *repository.GiftCardBatchTaskRepository, userRepo *repository.UserRepository, messageRepo *repository.MessageRepository) *GiftCardBatchHandler {
	return &GiftCardBatchHandler{
		cfg:           cfg,
		giftCardRepo:  giftCardRepo,
		batchTaskRepo: batchTaskRepo,
		userRepo:      userRepo,
		messageRepo:   messageRepo,
		batchProgress: make(map[uint]*GiftCardBatchProgress),
	}
}

// BatchDistributeRequest represents a batch gift card distribution request
type BatchDistributeRequest struct {
	// Gift card configuration
	Amount      float64 `json:"amount"`       // Balance amount
	VIPLevel    int     `json:"vip_level"`    // VIP level
	VIPDays     int     `json:"vip_days"`     // VIP days
	VIPHours    int     `json:"vip_hours"`    // VIP hours
	ExpiresIn   int     `json:"expires_in"`   // Card expiration in days (0 = never)
	Description string  `json:"description"`  // Card description

	// User filter criteria
	RegisteredAfter  string `json:"registered_after"`  // ISO 8601 datetime
	RegisteredBefore string `json:"registered_before"` // ISO 8601 datetime
	UserIDMin        *uint  `json:"user_id_min"`
	UserIDMax        *uint  `json:"user_id_max"`
	VIPLevelOp       string `json:"vip_level_op"`    // "=", ">", "<", ">=", "<="
	VIPLevelValue    *int   `json:"vip_level_value"`
	IsActive         *bool  `json:"is_active"`
}

// UserFilterCriteria stores filter criteria as JSON
type UserFilterCriteria struct {
	RegisteredAfter  string `json:"registered_after,omitempty"`
	RegisteredBefore string `json:"registered_before,omitempty"`
	UserIDMin        *uint  `json:"user_id_min,omitempty"`
	UserIDMax        *uint  `json:"user_id_max,omitempty"`
	VIPLevelOp       string `json:"vip_level_op,omitempty"`
	VIPLevelValue    *int   `json:"vip_level_value,omitempty"`
	IsActive         *bool  `json:"is_active,omitempty"`
}

// AdminGiftCardBatchPage renders the batch gift card distribution page
func (h *GiftCardBatchHandler) AdminGiftCardBatchPage(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_gift_card_batch.html", gin.H{
		"lang":       lang,
		"config":     h.cfg,
		"activeMenu": "gift-card-batch",
	})
}

// PreviewFilteredUsers returns count of users matching the filter criteria
// @Summary Preview filtered users count
// @Description Get the count of users matching filter criteria before batch distribution
// @Tags admin-gift-cards
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body BatchDistributeRequest true "Filter criteria"
// @Success 200 {object} Response "Users count"
// @Failure 400 {object} Response "Bad request"
// @Router /admin/gift-cards/batch/preview [post]
func (h *GiftCardBatchHandler) PreviewFilteredUsers(c *gin.Context) {
	var input BatchDistributeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	filter, err := h.buildUserFilter(input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	count, err := h.userRepo.CountFilteredUsers(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "查询用户数量失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"count": count,
		},
	})
}

// StartBatchDistribute starts a batch gift card distribution task
// @Summary Start batch gift card distribution
// @Description Start a batch task to distribute gift cards to filtered users
// @Tags admin-gift-cards
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body BatchDistributeRequest true "Distribution request"
// @Success 200 {object} Response "Task started"
// @Failure 400 {object} Response "Bad request"
// @Router /admin/gift-cards/batch/start [post]
func (h *GiftCardBatchHandler) StartBatchDistribute(c *gin.Context) {
	var input BatchDistributeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate: either amount or VIP level must be set
	if input.Amount <= 0 && input.VIPLevel <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "金额或VIP等级至少需要设置一项",
		})
		return
	}

	filter, err := h.buildUserFilter(input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	// Get filtered user IDs
	userIDs, err := h.userRepo.FilterUsers(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "查询用户列表失败",
		})
		return
	}

	if len(userIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "没有符合条件的用户",
		})
		return
	}

	// Serialize filter criteria to JSON
	filterCriteria := UserFilterCriteria{
		RegisteredAfter:  input.RegisteredAfter,
		RegisteredBefore: input.RegisteredBefore,
		UserIDMin:        input.UserIDMin,
		UserIDMax:        input.UserIDMax,
		VIPLevelOp:       input.VIPLevelOp,
		VIPLevelValue:    input.VIPLevelValue,
		IsActive:         input.IsActive,
	}
	filterJSON, _ := json.Marshal(filterCriteria)

	// Create batch task record
	task := &model.GiftCardBatchTask{
		Amount:         input.Amount,
		VIPLevel:       input.VIPLevel,
		VIPDays:        input.VIPDays,
		VIPHours:       input.VIPHours,
		ExpiresIn:      input.ExpiresIn,
		Description:    input.Description,
		FilterCriteria: string(filterJSON),
		TotalUsers:     len(userIDs),
		Status:         "pending",
	}

	if err := h.batchTaskRepo.Create(task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建任务失败",
		})
		return
	}

	// Initialize progress tracking
	h.batchProgressLock.Lock()
	h.batchProgress[task.ID] = &GiftCardBatchProgress{
		TaskID:     task.ID,
		TotalUsers: len(userIDs),
		Status:     "running",
	}
	h.batchProgressLock.Unlock()

	// Start async distribution
	go h.processBatchDistribute(task.ID, userIDs, input)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "批量发放任务已启动",
		"data": gin.H{
			"task_id":     task.ID,
			"total_users": len(userIDs),
		},
	})
}

// processBatchDistribute processes batch gift card distribution asynchronously
// Gift cards are created and sent to users' message inbox as system messages
func (h *GiftCardBatchHandler) processBatchDistribute(taskID uint, userIDs []uint, input BatchDistributeRequest) {
	h.batchProgressLock.Lock()
	if progress, exists := h.batchProgress[taskID]; exists {
		progress.Status = "running"
	}
	h.batchProgressLock.Unlock()

	h.batchTaskRepo.UpdateProgress(taskID, 0, 0, "running")

	sentCount := 0
	failedCount := 0

	// Calculate expiration time for gift cards
	var expiresAt *time.Time
	if input.ExpiresIn > 0 {
		t := time.Now().AddDate(0, 0, input.ExpiresIn)
		expiresAt = &t
	}

	for _, userID := range userIDs {
		// Create a gift card for this user (NOT marked as used - user needs to redeem it)
		card := &model.GiftCard{
			Code:        repository.GenerateCode(),
			Amount:      input.Amount,
			VIPLevel:    input.VIPLevel,
			VIPDays:     input.VIPDays,
			VIPHours:    input.VIPHours,
			ExpiresAt:   expiresAt,
			Description: input.Description,
			IsUsed:      false, // User needs to redeem this card
		}

		if err := h.giftCardRepo.Create(card); err != nil {
			failedCount++
		} else {
			// Build message content with gift card details
			messageTitle := "🎁 您收到一张礼品卡"
			messageContent := h.buildGiftCardMessageContent(card, input.Description)

			// Send system message to user with the gift card code
			message := &model.Message{
				UserID:  userID,
				Title:   messageTitle,
				Content: messageContent,
				Type:    "system",
				IsRead:  false,
			}

			// Try to send message, but count as success regardless since card was created
			_ = h.messageRepo.Create(message)
			sentCount++
		}

		// Update progress
		h.batchProgressLock.Lock()
		if progress, exists := h.batchProgress[taskID]; exists {
			progress.SentCount = sentCount
			progress.FailedCount = failedCount
		}
		h.batchProgressLock.Unlock()

		// Update database progress at regular intervals
		if (sentCount+failedCount)%BatchGiftCardProgressUpdateInterval == 0 {
			h.batchTaskRepo.UpdateProgress(taskID, sentCount, failedCount, "running")
		}

		// Small delay to prevent overwhelming the database
		time.Sleep(BatchGiftCardDelay)
	}

	// Final update
	status := "completed"
	if sentCount == 0 && failedCount > 0 {
		status = "failed"
	}

	h.batchTaskRepo.UpdateProgress(taskID, sentCount, failedCount, status)

	h.batchProgressLock.Lock()
	if progress, exists := h.batchProgress[taskID]; exists {
		progress.SentCount = sentCount
		progress.FailedCount = failedCount
		progress.Status = status
	}
	h.batchProgressLock.Unlock()

	// Clean up progress after 1 hour
	go func() {
		time.Sleep(1 * time.Hour)
		h.batchProgressLock.Lock()
		delete(h.batchProgress, taskID)
		h.batchProgressLock.Unlock()
	}()
}

// GetBatchProgress returns the progress of a batch distribution task
// @Summary Get batch task progress
// @Description Get the progress of a batch gift card distribution task
// @Tags admin-gift-cards
// @Produce json
// @Security BearerAuth
// @Param id path int true "Task ID"
// @Success 200 {object} Response "Progress retrieved"
// @Router /admin/gift-cards/batch/progress/{id} [get]
func (h *GiftCardBatchHandler) GetBatchProgress(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的任务ID",
		})
		return
	}

	// First check in-memory progress
	h.batchProgressLock.RLock()
	progress, exists := h.batchProgress[uint(id)]
	h.batchProgressLock.RUnlock()

	if exists {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    progress,
		})
		return
	}

	// Fallback to database
	task, err := h.batchTaskRepo.FindByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "任务不存在",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"task_id":      task.ID,
			"total_users":  task.TotalUsers,
			"sent_count":   task.SentCount,
			"failed_count": task.FailedCount,
			"status":       task.Status,
		},
	})
}

// ListBatchTasks lists all batch gift card distribution tasks
// @Summary List batch tasks
// @Description List all batch gift card distribution tasks
// @Tags admin-gift-cards
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} Response "Tasks retrieved"
// @Router /admin/gift-cards/batch/tasks [get]
func (h *GiftCardBatchHandler) ListBatchTasks(c *gin.Context) {
	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}

	tasks, total, err := h.batchTaskRepo.List(page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取任务列表失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"tasks":     tasks,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// buildUserFilter builds a UserFilter from the request
func (h *GiftCardBatchHandler) buildUserFilter(input BatchDistributeRequest) (repository.UserFilter, error) {
	filter := repository.UserFilter{}

	// Parse registration time filters
	if input.RegisteredAfter != "" {
		t, err := time.Parse(time.RFC3339, input.RegisteredAfter)
		if err != nil {
			// Try alternative format
			t, err = time.Parse("2006-01-02", input.RegisteredAfter)
			if err != nil {
				return filter, err
			}
		}
		filter.RegisteredAfter = &t
	}
	if input.RegisteredBefore != "" {
		t, err := time.Parse(time.RFC3339, input.RegisteredBefore)
		if err != nil {
			// Try alternative format
			t, err = time.Parse("2006-01-02", input.RegisteredBefore)
			if err != nil {
				return filter, err
			}
		}
		filter.RegisteredBefore = &t
	}

	// User ID range filters
	filter.UserIDMin = input.UserIDMin
	filter.UserIDMax = input.UserIDMax

	// VIP level filter
	if input.VIPLevelOp != "" && input.VIPLevelValue != nil {
		// Validate operator
		validOps := map[string]bool{"=": true, ">": true, "<": true, ">=": true, "<=": true}
		if !validOps[input.VIPLevelOp] {
			return filter, nil // Invalid operator, ignore this filter
		}
		filter.VIPLevelOp = input.VIPLevelOp
		filter.VIPLevelValue = input.VIPLevelValue
	}

	// Active status filter
	filter.IsActive = input.IsActive

	return filter, nil
}

// buildGiftCardMessageContent builds the message content for a gift card notification
func (h *GiftCardBatchHandler) buildGiftCardMessageContent(card *model.GiftCard, description string) string {
	var content string

	// Build description of what the card contains
	var benefits []string
	if card.Amount > 0 {
		benefits = append(benefits, fmt.Sprintf("余额 ¥%.2f", card.Amount))
	}
	if card.VIPLevel > 0 {
		vipDuration := "永久"
		if card.VIPHours > 0 {
			vipDuration = fmt.Sprintf("%d小时", card.VIPHours)
		} else if card.VIPDays > 0 {
			vipDuration = fmt.Sprintf("%d天", card.VIPDays)
		}
		benefits = append(benefits, fmt.Sprintf("VIP%d会员（%s）", card.VIPLevel, vipDuration))
	}

	benefitsStr := ""
	for i, b := range benefits {
		if i > 0 {
			benefitsStr += " + "
		}
		benefitsStr += b
	}

	content = fmt.Sprintf(`亲爱的用户，您好！

您收到了一张礼品卡，包含以下福利：
**%s**

`, benefitsStr)

	if description != "" {
		content += fmt.Sprintf("备注：%s\n\n", description)
	}

	content += fmt.Sprintf(`**礼品卡兑换码：**
` + "```" + `
%s
` + "```" + `

**使用方法：**
1. 前往「充值中心」页面
2. 在礼品卡兑换区域输入上方兑换码
3. 点击「兑换」按钮即可领取福利

`, card.Code)

	if card.ExpiresAt != nil {
		content += fmt.Sprintf("⚠️ 请注意：此礼品卡有效期至 %s，请尽快使用！\n", card.ExpiresAt.Format("2006-01-02 15:04"))
	}

	return content
}
