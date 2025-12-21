package handler

import (
	"net/http"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/service"
	"github.com/gin-gonic/gin"
)

// CaptchaStatusResponse represents captcha status response
type CaptchaStatusResponse struct {
	Enabled bool `json:"enabled" example:"true"`
}

// CaptchaGenerateResponse represents captcha generate response
type CaptchaGenerateResponse struct {
	Enabled bool   `json:"enabled" example:"true"`
	ID      string `json:"id,omitempty" example:"captcha-abc123"`
	Target  string `json:"target,omitempty" example:"请点击图片中的猫"`
}

// CaptchaVerifyRequest represents captcha verify request
type CaptchaVerifyRequest struct {
	ID       string `json:"id" binding:"required" example:"captcha-abc123"`
	Position int    `json:"position" example:"150"`
}

// CaptchaHandler handles captcha requests
type CaptchaHandler struct {
	captchaService *service.CaptchaService
	cfg            *config.Config
}

// NewCaptchaHandler creates a new CaptchaHandler
func NewCaptchaHandler(captchaService *service.CaptchaService, cfg *config.Config) *CaptchaHandler {
	return &CaptchaHandler{
		captchaService: captchaService,
		cfg:            cfg,
	}
}

// GetStatus returns captcha enabled status
// @Summary Get captcha status
// @Description Check if captcha is enabled
// @Tags captcha
// @Produce json
// @Success 200 {object} Response{data=CaptchaStatusResponse} "Captcha status"
// @Router /captcha/status [get]
func (h *CaptchaHandler) GetStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled": h.cfg.Captcha.Enabled,
		},
	})
}

// Generate creates a new captcha
// @Summary Generate captcha
// @Description Generate a new captcha challenge
// @Tags captcha
// @Produce json
// @Success 200 {object} Response{data=CaptchaGenerateResponse} "Captcha generated"
// @Failure 500 {object} Response "Failed to generate captcha"
// @Router /captcha/generate [post]
func (h *CaptchaHandler) Generate(c *gin.Context) {
	if !h.cfg.Captcha.Enabled {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"enabled": false,
			},
		})
		return
	}

	captcha, err := h.captchaService.Generate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "生成验证码失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled": true,
			"id":      captcha.ID,
			"target":  captcha.Target,
		},
	})
}

// Verify checks if the captcha answer is correct
// @Summary Verify captcha
// @Description Verify the captcha answer
// @Tags captcha
// @Accept json
// @Produce json
// @Param request body CaptchaVerifyRequest true "Captcha verify request"
// @Success 200 {object} Response "Verification successful"
// @Failure 400 {object} Response "Verification failed"
// @Router /captcha/verify [post]
func (h *CaptchaHandler) Verify(c *gin.Context) {
	var input struct {
		ID       string `json:"id" binding:"required"`
		Position int    `json:"position"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if h.captchaService.Verify(input.ID, input.Position) {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "验证成功",
		})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "验证失败，请重试",
		})
	}
}
