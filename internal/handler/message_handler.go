package handler

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/e54385991/Common-LoginService/internal/repository"
	"github.com/gin-gonic/gin"
)

// Constants for batch message processing
const (
	// BatchSendDelay is the delay between sending each message to prevent database overload
	BatchSendDelay = 5 * time.Millisecond
	// BatchProgressUpdateInterval is how often to update progress in database during batch sending
	BatchProgressUpdateInterval = 10
	// ProgressCleanupInterval is how long to keep completed batch progress in memory
	ProgressCleanupInterval = 1 * time.Hour
	// MaxUsersFetchLimit is the maximum number of users to fetch for batch sending
	MaxUsersFetchLimit = 100000
)

// MessageHandler handles message-related requests
type MessageHandler struct {
	messageRepo   *repository.MessageRepository
	batchTaskRepo *repository.MessageBatchTaskRepository
	userRepo      *repository.UserRepository
	
	// Active batch tasks for progress tracking
	batchProgress     map[uint]*BatchProgress
	batchProgressLock sync.RWMutex
}

// BatchProgress tracks the progress of a batch message task
type BatchProgress struct {
	TaskID      uint   `json:"task_id"`
	TotalUsers  int    `json:"total_users"`
	SentCount   int    `json:"sent_count"`
	FailedCount int    `json:"failed_count"`
	Status      string `json:"status"` // pending, running, completed, failed
}

// NewMessageHandler creates a new MessageHandler
func NewMessageHandler(messageRepo *repository.MessageRepository, batchTaskRepo *repository.MessageBatchTaskRepository, userRepo *repository.UserRepository) *MessageHandler {
	return &MessageHandler{
		messageRepo:   messageRepo,
		batchTaskRepo: batchTaskRepo,
		userRepo:      userRepo,
		batchProgress: make(map[uint]*BatchProgress),
	}
}

// ==================== User API ====================

// GetMessages returns messages for the current user
// @Summary Get user messages
// @Description Get messages for the current user with pagination
// @Tags messages
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} Response "Messages retrieved"
// @Failure 401 {object} Response "Unauthorized"
// @Router /messages [get]
func (h *MessageHandler) GetMessages(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

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

	messages, total, err := h.messageRepo.FindByUserID(userID.(uint), page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取消息失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"messages":  messages,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// GetUnreadCount returns the unread message count for the current user
// @Summary Get unread message count
// @Description Get the count of unread messages for the current user
// @Tags messages
// @Produce json
// @Security BearerAuth
// @Success 200 {object} Response "Unread count retrieved"
// @Failure 401 {object} Response "Unauthorized"
// @Router /messages/unread-count [get]
func (h *MessageHandler) GetUnreadCount(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	count, err := h.messageRepo.CountUnreadByUserID(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取未读消息数量失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"unread_count": count,
		},
	})
}

// GetMessage returns a single message by ID
// @Summary Get a message
// @Description Get a single message by ID
// @Tags messages
// @Produce json
// @Security BearerAuth
// @Param id path int true "Message ID"
// @Success 200 {object} Response "Message retrieved"
// @Failure 401 {object} Response "Unauthorized"
// @Failure 404 {object} Response "Message not found"
// @Router /messages/{id} [get]
func (h *MessageHandler) GetMessage(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的消息ID",
		})
		return
	}

	message, err := h.messageRepo.FindByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "消息不存在",
		})
		return
	}

	// Check if the message belongs to the user
	if message.UserID != userID.(uint) {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "无权访问此消息",
		})
		return
	}

	// Mark as read if not already read
	if !message.IsRead {
		h.messageRepo.MarkAsRead(uint(id), userID.(uint))
		message.IsRead = true
		now := time.Now()
		message.ReadAt = &now
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    message,
	})
}

// MarkAsRead marks a message as read
// @Summary Mark message as read
// @Description Mark a message as read
// @Tags messages
// @Produce json
// @Security BearerAuth
// @Param id path int true "Message ID"
// @Success 200 {object} Response "Message marked as read"
// @Failure 401 {object} Response "Unauthorized"
// @Router /messages/{id}/read [post]
func (h *MessageHandler) MarkAsRead(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的消息ID",
		})
		return
	}

	err = h.messageRepo.MarkAsRead(uint(id), userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "标记失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "已标记为已读",
	})
}

// MarkAllAsRead marks all messages as read for the current user
// @Summary Mark all messages as read
// @Description Mark all messages as read for the current user
// @Tags messages
// @Produce json
// @Security BearerAuth
// @Success 200 {object} Response "All messages marked as read"
// @Failure 401 {object} Response "Unauthorized"
// @Router /messages/read-all [post]
func (h *MessageHandler) MarkAllAsRead(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	err := h.messageRepo.MarkAllAsRead(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "标记失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "已全部标记为已读",
	})
}

// DeleteMessage deletes a message
// @Summary Delete a message
// @Description Delete a message
// @Tags messages
// @Produce json
// @Security BearerAuth
// @Param id path int true "Message ID"
// @Success 200 {object} Response "Message deleted"
// @Failure 401 {object} Response "Unauthorized"
// @Router /messages/{id} [delete]
func (h *MessageHandler) DeleteMessage(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的消息ID",
		})
		return
	}

	err = h.messageRepo.Delete(uint(id), userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "删除失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "消息已删除",
	})
}

// BatchDeleteRequest represents a batch delete request
type BatchDeleteRequest struct {
	IDs []uint `json:"ids" binding:"required" example:"[1,2,3]"`
}

// DeleteMessagesBatch deletes multiple messages
// @Summary Batch delete messages
// @Description Delete multiple messages by their IDs
// @Tags messages
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body BatchDeleteRequest true "Message IDs to delete"
// @Success 200 {object} Response "Messages deleted"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Router /messages/batch-delete [post]
func (h *MessageHandler) DeleteMessagesBatch(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	var input BatchDeleteRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if len(input.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请选择要删除的消息",
		})
		return
	}

	// Limit batch size to prevent abuse
	if len(input.IDs) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "一次最多删除100条消息",
		})
		return
	}

	deleted, err := h.messageRepo.DeleteBatch(input.IDs, userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "删除失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "消息已删除",
		"data": gin.H{
			"deleted_count": deleted,
		},
	})
}

// ==================== Admin API ====================

// SendMessageRequest represents a single message send request
type SendMessageRequest struct {
	UserID  uint   `json:"user_id" binding:"required" example:"1"`
	Title   string `json:"title" binding:"required" example:"Welcome"`
	Content string `json:"content" binding:"required" example:"Welcome to our platform!"`
	Type    string `json:"type" example:"normal"` // normal, system, announcement
}

// AdminSendMessage sends a message to a single user
// @Summary Send message to user
// @Description Send a message to a single user
// @Tags admin-messages
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body SendMessageRequest true "Message to send"
// @Success 200 {object} Response "Message sent"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Router /admin/messages/send [post]
func (h *MessageHandler) AdminSendMessage(c *gin.Context) {
	var input SendMessageRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate user exists
	_, err := h.userRepo.FindByID(input.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}

	msgType := input.Type
	if msgType == "" {
		msgType = "normal"
	}

	message := &model.Message{
		UserID:  input.UserID,
		Title:   input.Title,
		Content: input.Content,
		Type:    msgType,
		IsRead:  false,
	}

	if err := h.messageRepo.Create(message); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "发送消息失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "消息发送成功",
		"data":    message,
	})
}

// BatchSendMessageRequest represents a batch message send request
type BatchSendMessageRequest struct {
	UserIDs []uint `json:"user_ids"` // Specific user IDs to send to (empty means all users)
	Title   string `json:"title" binding:"required" example:"Announcement"`
	Content string `json:"content" binding:"required" example:"System maintenance scheduled."`
	Type    string `json:"type" example:"announcement"` // normal, system, announcement
}

// AdminBatchSendMessage sends messages to multiple users asynchronously
// @Summary Batch send messages
// @Description Send messages to multiple users asynchronously with progress tracking
// @Tags admin-messages
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body BatchSendMessageRequest true "Batch message request"
// @Success 200 {object} Response "Batch task started"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Router /admin/messages/batch-send [post]
func (h *MessageHandler) AdminBatchSendMessage(c *gin.Context) {
	var input BatchSendMessageRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	msgType := input.Type
	if msgType == "" {
		msgType = "normal"
	}

	// Get target user IDs
	var userIDs []uint
	if len(input.UserIDs) > 0 {
		userIDs = input.UserIDs
	} else {
		// Get all user IDs - for large databases, consider implementing GetAllUserIDs in repository
		users, _, err := h.userRepo.List(1, MaxUsersFetchLimit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "获取用户列表失败",
			})
			return
		}
		for _, user := range users {
			userIDs = append(userIDs, user.ID)
		}
	}

	if len(userIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "没有可发送的用户",
		})
		return
	}

	// Create batch task record
	task := &model.MessageBatchTask{
		Title:      input.Title,
		Content:    input.Content,
		Type:       msgType,
		TotalUsers: len(userIDs),
		Status:     "pending",
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
	h.batchProgress[task.ID] = &BatchProgress{
		TaskID:     task.ID,
		TotalUsers: len(userIDs),
		Status:     "running",
	}
	h.batchProgressLock.Unlock()

	// Start async sending
	go h.processBatchSend(task.ID, userIDs, input.Title, input.Content, msgType)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "批量发送任务已启动",
		"data": gin.H{
			"task_id":     task.ID,
			"total_users": len(userIDs),
		},
	})
}

// processBatchSend processes batch message sending asynchronously
func (h *MessageHandler) processBatchSend(taskID uint, userIDs []uint, title, content, msgType string) {
	h.batchProgressLock.Lock()
	if progress, exists := h.batchProgress[taskID]; exists {
		progress.Status = "running"
	}
	h.batchProgressLock.Unlock()

	h.batchTaskRepo.UpdateProgress(taskID, 0, 0, "running")

	sentCount := 0
	failedCount := 0

	for _, userID := range userIDs {
		message := &model.Message{
			UserID:  userID,
			Title:   title,
			Content: content,
			Type:    msgType,
			IsRead:  false,
		}

		if err := h.messageRepo.Create(message); err != nil {
			failedCount++
		} else {
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
		if (sentCount+failedCount)%BatchProgressUpdateInterval == 0 {
			h.batchTaskRepo.UpdateProgress(taskID, sentCount, failedCount, "running")
		}

		// Small delay to prevent overwhelming the database
		time.Sleep(BatchSendDelay)
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

	// Clean up progress after configured interval
	go func() {
		time.Sleep(ProgressCleanupInterval)
		h.batchProgressLock.Lock()
		delete(h.batchProgress, taskID)
		h.batchProgressLock.Unlock()
	}()
}

// AdminGetBatchProgress returns the progress of a batch sending task
// @Summary Get batch task progress
// @Description Get the progress of a batch message sending task
// @Tags admin-messages
// @Produce json
// @Security BearerAuth
// @Param id path int true "Task ID"
// @Success 200 {object} Response "Progress retrieved"
// @Failure 401 {object} Response "Unauthorized"
// @Failure 404 {object} Response "Task not found"
// @Router /admin/messages/batch-progress/{id} [get]
func (h *MessageHandler) AdminGetBatchProgress(c *gin.Context) {
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

// AdminListBatchTasks lists all batch tasks
// @Summary List batch tasks
// @Description List all batch message sending tasks
// @Tags admin-messages
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} Response "Tasks retrieved"
// @Failure 401 {object} Response "Unauthorized"
// @Router /admin/messages/batch-tasks [get]
func (h *MessageHandler) AdminListBatchTasks(c *gin.Context) {
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

// AdminListMessages lists all messages (admin view)
// @Summary List all messages
// @Description List all messages with optional user filter
// @Tags admin-messages
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param user_id query int false "Filter by user ID"
// @Success 200 {object} Response "Messages retrieved"
// @Failure 401 {object} Response "Unauthorized"
// @Router /admin/messages [get]
func (h *MessageHandler) AdminListMessages(c *gin.Context) {
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

	var userID *uint
	if uid := c.Query("user_id"); uid != "" {
		if v, err := strconv.ParseUint(uid, 10, 32); err == nil {
			id := uint(v)
			userID = &id
		}
	}

	messages, total, err := h.messageRepo.List(page, pageSize, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取消息列表失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"messages":  messages,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// AdminMessagesPage renders the admin messages page
func (h *MessageHandler) AdminMessagesPage(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_messages.html", gin.H{
		"lang":       lang,
		"activeMenu": "messages",
	})
}
