package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/e54385991/Common-LoginService/internal/repository"
	"github.com/gin-gonic/gin"
)

// DefaultVIPDurationDays is the default VIP duration in days if not configured
const DefaultVIPDurationDays = 30

// PaymentHandler handles payment requests
type PaymentHandler struct {
	cfg              *config.Config
	paymentOrderRepo *repository.PaymentOrderRepository
	userRepo         *repository.UserRepository
	balanceLogRepo   *repository.BalanceLogRepository
}

// NewPaymentHandler creates a new PaymentHandler
func NewPaymentHandler(cfg *config.Config, paymentOrderRepo *repository.PaymentOrderRepository, userRepo *repository.UserRepository, balanceLogRepo *repository.BalanceLogRepository) *PaymentHandler {
	return &PaymentHandler{
		cfg:              cfg,
		paymentOrderRepo: paymentOrderRepo,
		userRepo:         userRepo,
		balanceLogRepo:   balanceLogRepo,
	}
}

// roundToTwoDecimals rounds a float64 to two decimal places
func roundToTwoDecimals(amount float64) float64 {
	return math.Round(amount*100) / 100
}

// isValidRechargeOption checks if the given amount matches a predefined recharge option
func (h *PaymentHandler) isValidRechargeOption(amount float64) bool {
	roundedAmount := roundToTwoDecimals(amount)
	for _, opt := range h.cfg.Recharge.Options {
		if roundToTwoDecimals(opt.Amount) == roundedAmount {
			return true
		}
	}
	return false
}

// CreatePaymentRequest represents a payment creation request
type CreatePaymentRequest struct {
	ProductType   string  `json:"product_type" binding:"required"` // "vip" or "recharge"
	ProductID     int     `json:"product_id"`                       // VIP level (for vip type)
	Duration      int     `json:"duration"`                         // VIP duration in days (for vip type, 0 = use default)
	Amount        float64 `json:"amount" binding:"required"`        // Payment amount
	PaymentMethod string  `json:"payment_method" binding:"required"` // "alipay" or "wechat"
}

// CreatePaymentResponse represents a payment creation response
type CreatePaymentResponse struct {
	OrderID    string `json:"order_id"`
	PaymentURL string `json:"payment_url"`
	Amount     float64 `json:"amount"`
}

// CreatePayment creates a payment order and returns the PyPay redirect URL
// @Summary Create payment order
// @Description Create a payment order and get PyPay redirect URL
// @Tags payment
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreatePaymentRequest true "Payment request"
// @Success 200 {object} Response{data=CreatePaymentResponse} "Payment order created"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Failure 503 {object} Response "Payment service unavailable"
// @Router /payment/create [post]
func (h *PaymentHandler) CreatePayment(c *gin.Context) {
	var input CreatePaymentRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate payment method
	if input.PaymentMethod != "alipay" && input.PaymentMethod != "wechat" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的支付方式，仅支持 alipay 或 wechat",
		})
		return
	}

	// Validate product type
	if input.ProductType != "vip" && input.ProductType != "recharge" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的产品类型",
		})
		return
	}

	// Validate amount
	if input.Amount <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "支付金额必须大于0",
		})
		return
	}

	// Validate recharge amount limits
	if input.ProductType == "recharge" {
		if h.cfg.Recharge.MinAmount > 0 && input.Amount < h.cfg.Recharge.MinAmount {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": fmt.Sprintf("充值金额不能小于 %.2f 元", h.cfg.Recharge.MinAmount),
			})
			return
		}
		if h.cfg.Recharge.MaxAmount > 0 && input.Amount > h.cfg.Recharge.MaxAmount {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": fmt.Sprintf("充值金额不能大于 %.2f 元", h.cfg.Recharge.MaxAmount),
			})
			return
		}
		// If custom amount is disabled, validate against predefined options
		if !h.cfg.Recharge.CustomAmountEnable && len(h.cfg.Recharge.Options) > 0 {
			if !h.isValidRechargeOption(input.Amount) {
				c.JSON(http.StatusBadRequest, gin.H{
					"success": false,
					"message": "自定义充值金额未启用，请选择预设金额",
				})
				return
			}
		}
	}

	// Check if payment is enabled
	if !h.cfg.Payment.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"message": "支付功能未启用",
		})
		return
	}

	// Check if in demo mode
	if h.cfg.Payment.DemoMode {
		c.JSON(http.StatusOK, gin.H{
			"success":   true,
			"demo_mode": true,
			"message":   "当前为演示模式，支付将模拟进行",
			"data": gin.H{
				"order_id":    generateOrderID(),
				"payment_url": "",
				"amount":      input.Amount,
			},
		})
		return
	}

	// Validate payment configuration
	if h.cfg.Payment.MerchantID == "" || h.cfg.Payment.ApiKey == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"message": "支付网关未正确配置，请联系管理员",
		})
		return
	}

	// Validate NotifyURL and ReturnURL
	if h.cfg.Payment.NotifyURL == "" || h.cfg.Payment.ReturnURL == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"message": "支付回调URL未配置，请联系管理员",
		})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	// Convert userID to uint
	var userIDUint uint
	switch v := userID.(type) {
	case uint:
		userIDUint = v
	case int:
		userIDUint = uint(v)
	case float64:
		userIDUint = uint(v)
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "用户ID格式错误",
		})
		return
	}

	// For VIP purchases, validate that user is not trying to purchase a lower level
	// Allow same-level purchase if renewal is enabled for that level
	// Also recalculate price with discounts for online payment
	if input.ProductType == "vip" {
		currentUser, err := h.userRepo.FindByID(userIDUint)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "获取用户信息失败",
			})
			return
		}

		// Check if trying to purchase a lower level (always blocked)
		if input.ProductID < currentUser.VIPLevel {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "您已是更高等级的VIP，无法购买更低等级",
				"data": gin.H{
					"current_level":   currentUser.VIPLevel,
					"requested_level": input.ProductID,
				},
			})
			return
		}

		// Find the VIP level config
		var vipConfig *config.VIPLevelConfig
		for _, v := range h.cfg.VIPLevels {
			if v.Level == input.ProductID {
				vipConfig = &v
				break
			}
		}

		if vipConfig == nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "VIP等级不存在",
			})
			return
		}

		// Validate price against backend configuration
		expectedPrice := vipConfig.Price
		expectedDuration := vipConfig.Duration

		// If duration is specified, find matching specification
		if input.Duration > 0 && len(vipConfig.Specifications) > 0 {
			found := false
			for _, spec := range vipConfig.Specifications {
				if spec.Duration == input.Duration {
					expectedPrice = spec.Price
					expectedDuration = spec.Duration
					found = true
					break
				}
			}
			if !found {
				c.JSON(http.StatusBadRequest, gin.H{
					"success": false,
					"message": "指定的VIP时长规格不存在",
					"data": gin.H{
						"requested_duration": input.Duration,
					},
				})
				return
			}
		} else if input.Duration == 0 && len(vipConfig.Specifications) > 0 {
			// Find default duration in specifications
			for _, spec := range vipConfig.Specifications {
				if spec.Duration == vipConfig.Duration {
					expectedPrice = spec.Price
					expectedDuration = spec.Duration
					break
				}
			}
		}

		// Check if trying to purchase same level (renewal)
		if input.ProductID == currentUser.VIPLevel {
			if !vipConfig.AllowRenewal {
				c.JSON(http.StatusBadRequest, gin.H{
					"success": false,
					"message": "您已是该等级的VIP，该等级不支持续期",
					"data": gin.H{
						"current_level":   currentUser.VIPLevel,
						"requested_level": input.ProductID,
					},
				})
				return
			}
			
			// Apply renewal discount for online payment - use expected price from backend
			if vipConfig.RenewalDiscount > 0 && vipConfig.RenewalDiscount < 1 {
				expectedPrice = roundToTwoDecimals(expectedPrice * (1 - vipConfig.RenewalDiscount))
			}
			input.Amount = expectedPrice
			input.Duration = expectedDuration
		} else if input.ProductID > currentUser.VIPLevel && currentUser.VIPLevel > 0 {
			// Upgrade scenario: Apply upgrade coefficient discount for online payment
			// Use backend expected price instead of client provided amount
			if vipConfig.UpgradeCoefficient > 0 && vipConfig.UpgradeCoefficient <= 1 {
				// Find old VIP config
				var oldVIPConfig *config.VIPLevelConfig
				for _, v := range h.cfg.VIPLevels {
					if v.Level == currentUser.VIPLevel {
						oldVIPConfig = &v
						break
					}
				}
				
				if oldVIPConfig != nil {
					// Calculate remaining days from current VIP
					remainingDays := 0.0
					if currentUser.VIPExpireAt != nil && currentUser.VIPExpireAt.After(time.Now()) {
						remainingDuration := currentUser.VIPExpireAt.Sub(time.Now())
						remainingDays = remainingDuration.Hours() / 24
					}
					
					if remainingDays > 0 {
						// Calculate old VIP's daily price
						oldDuration := float64(oldVIPConfig.Duration)
						if oldDuration <= 0 {
							oldDuration = DefaultVIPDurationDays
						}
						oldDailyPrice := oldVIPConfig.Price / oldDuration
						
						// Prorated upgrade price = new price - (remaining days * old daily price * coefficient)
						credit := remainingDays * oldDailyPrice * vipConfig.UpgradeCoefficient
						expectedPrice = expectedPrice - credit
						if expectedPrice < 0 {
							expectedPrice = 0
						}
					}
				}
			}
			input.Amount = roundToTwoDecimals(expectedPrice)
			input.Duration = expectedDuration
		} else {
			// New VIP purchase - use backend prices
			input.Amount = expectedPrice
			input.Duration = expectedDuration
		}

		// Ensure minimum payment amount is 1 for online payment (if amount > 0 but < 1)
		if input.Amount > 0 && input.Amount < 1 {
			input.Amount = 1
		}
	}

	// Generate order ID
	orderID := generateOrderID()

	// Build product name
	var productName string
	switch input.ProductType {
	case "vip":
		productName = fmt.Sprintf("VIP%d会员", input.ProductID)
	case "recharge":
		productName = "账户充值"
	default:
		productName = "订单支付"
	}

	// Save order to database
	order := &model.PaymentOrder{
		OrderID:     orderID,
		UserID:      userIDUint,
		Amount:      input.Amount,
		ProductType: input.ProductType,
		ProductID:   input.ProductID,
		Duration:    input.Duration, // Store the selected VIP duration
		Status:      "pending",
	}
	if err := h.paymentOrderRepo.Create(order); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建订单失败",
		})
		return
	}

	// Map payment method to PyPay type
	var payType string
	switch input.PaymentMethod {
	case "alipay":
		payType = "alipay"
	case "wechat":
		payType = "wxpay"
	default:
		payType = "alipay"
	}

	// Build PyPay request parameters according to PyPay API docs
	// Required: pid, type, out_trade_no, notify_url, return_url, name, money, sign
	params := map[string]string{
		"pid":          h.cfg.Payment.MerchantID,
		"type":         payType,
		"out_trade_no": orderID,
		"notify_url":   h.cfg.Payment.NotifyURL,
		"return_url":   h.cfg.Payment.ReturnURL,
		"name":         productName,
		"money":        fmt.Sprintf("%.2f", input.Amount),
	}

	// Generate HMAC-SHA256 signature (generateSign internally uses only core params: pid, type, out_trade_no)
	sign := generateSign(params, h.cfg.Payment.ApiKey)
	params["sign"] = sign

	// Call PyPay API to create order
	apiURL := strings.TrimRight(h.cfg.Payment.ApiURL, "/") + "/create_order"
	paymentURL, err := callPyPayCreateOrder(apiURL, params)
	if err != nil {
		log.Printf("Payment create: failed to call PyPay API: %v", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"message": "支付服务暂时不可用，请稍后重试",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"demo_mode": false,
		"data": gin.H{
			"order_id":    orderID,
			"payment_url": paymentURL,
			"amount":      input.Amount,
		},
	})
}

// GetPaymentStatus returns the payment status
// @Summary Get payment status
// @Description Check if payment is enabled and in demo mode
// @Tags payment
// @Produce json
// @Success 200 {object} Response "Payment status"
// @Router /payment/status [get]
func (h *PaymentHandler) GetPaymentStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled":   h.cfg.Payment.Enabled,
			"demo_mode": h.cfg.Payment.DemoMode,
		},
	})
}

// generateOrderID generates a unique order ID
func generateOrderID() string {
	timestamp := time.Now().Format("20060102150405")
	random := fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	return fmt.Sprintf("ORDER%s%s", timestamp, random)
}

// generateSign generates HMAC-SHA256 signature for PyPay API
// According to PyPay docs, only uses core params: pid, type, out_trade_no
func generateSign(params map[string]string, apiKey string) string {
	// Only use core parameters for signature as per PyPay documentation
	requiredParams := []string{"pid", "type", "out_trade_no"}
	filteredParams := make(map[string]string)

	for _, param := range requiredParams {
		if val, ok := params[param]; ok && val != "" {
			filteredParams[param] = val
		}
	}

	// Sort keys alphabetically
	var keys []string
	for k := range filteredParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build sign string: key1=value1&key2=value2...
	var pairs []string
	for _, k := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, filteredParams[k]))
	}
	signStr := strings.Join(pairs, "&")

	// HMAC-SHA256 hash
	h := hmac.New(sha256.New, []byte(apiKey))
	h.Write([]byte(signStr))
	return hex.EncodeToString(h.Sum(nil))
}

// PyPayCreateOrderResponse represents the response from PyPay create_order API
type PyPayCreateOrderResponse struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	TradeNo string `json:"trade_no"`
	PayURL  string `json:"payurl"`
}

// callPyPayCreateOrder calls the PyPay /api/create_order endpoint
func callPyPayCreateOrder(apiURL string, params map[string]string) (string, error) {
	// Build form data
	formData := url.Values{}
	for k, v := range params {
		formData.Set(k, v)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request with timeout
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var result PyPayCreateOrderResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w, body: %s", err, string(body))
	}

	// Check if order creation was successful
	if result.Code != 1 {
		return "", fmt.Errorf("PyPay API error: %s", result.Msg)
	}

	if result.PayURL == "" {
		return "", fmt.Errorf("PyPay API returned empty payment URL")
	}

	return result.PayURL, nil
}

// PaymentNotify handles asynchronous payment notification from PyPay
// @Summary Payment notification callback
// @Description Receive asynchronous payment notification from PyPay payment system
// @Tags payment
// @Accept x-www-form-urlencoded
// @Produce plain
// @Param pid formData string true "Merchant ID"
// @Param trade_no formData string true "System trade number"
// @Param out_trade_no formData string true "Merchant order ID"
// @Param type formData string true "Payment type (alipay/wxpay)"
// @Param name formData string true "Product name"
// @Param money formData string true "Payment amount"
// @Param trade_status formData string true "Trade status (TRADE_SUCCESS)"
// @Param sign formData string true "Signature for verification"
// @Success 200 {string} string "success"
// @Failure 400 {string} string "fail"
// @Router /api/payment/notify [post]
func (h *PaymentHandler) PaymentNotify(c *gin.Context) {
	// Get PyPay notification parameters according to PyPay docs
	pid := c.PostForm("pid")
	tradeNo := c.PostForm("trade_no")
	outTradeNo := c.PostForm("out_trade_no")
	payType := c.PostForm("type")
	name := c.PostForm("name")
	money := c.PostForm("money")
	tradeStatus := c.PostForm("trade_status")
	sign := c.PostForm("sign")

	// Validate required parameters
	if pid == "" || outTradeNo == "" || payType == "" || tradeStatus == "" || sign == "" {
		log.Printf("Payment notify: missing required parameters - pid: %s, out_trade_no: %s, type: %s, trade_status: %s",
			pid, outTradeNo, payType, tradeStatus)
		c.String(http.StatusBadRequest, "fail")
		return
	}

	// Verify signature using only core params: pid, type, out_trade_no
	params := map[string]string{
		"pid":          pid,
		"type":         payType,
		"out_trade_no": outTradeNo,
	}
	expectedSign := generateSign(params, h.cfg.Payment.ApiKey)
	if sign != expectedSign {
		log.Printf("Payment notify: signature mismatch for order %s - expected: %s, received: %s",
			outTradeNo, expectedSign, sign)
		c.String(http.StatusBadRequest, "fail")
		return
	}

	log.Printf("Payment notify: received notification for order %s - trade_no: %s, name: %s, money: %s, status: %s",
		outTradeNo, tradeNo, name, money, tradeStatus)

	// Process payment result
	if tradeStatus == "TRADE_SUCCESS" {
		// Try to mark order as success (atomic operation to prevent duplicate processing)
		updated, order, err := h.paymentOrderRepo.MarkAsSuccess(outTradeNo)
		if err != nil {
			log.Printf("Payment notify: failed to process order %s: %v", outTradeNo, err)
			c.String(http.StatusBadRequest, "fail")
			return
		}

		// If order was not updated, it means it was already processed or doesn't exist
		if !updated {
			if order != nil && order.Status == repository.PaymentStatusSuccess {
				// Order already processed successfully, return success to prevent retries
				log.Printf("Payment notify: order %s already processed, ignoring duplicate notification", outTradeNo)
				c.String(http.StatusOK, "success")
				return
			}
			// Order doesn't exist or has other status
			log.Printf("Payment notify: order %s not found or invalid status", outTradeNo)
			c.String(http.StatusBadRequest, "fail")
			return
		}

		// Order marked as success, now update user balance or VIP level
		var processErr error
		switch order.ProductType {
		case "recharge":
			// Get user's balance before update for logging
			userBefore, _ := h.userRepo.FindByID(order.UserID)
			var balanceBefore float64
			if userBefore != nil {
				balanceBefore = userBefore.Balance
			}

			// Calculate bonus amount based on recharge options
			// Use tolerance-based comparison for floating-point values
			var bonusAmount float64
			const tolerance = 0.001 // 0.1 cent tolerance for floating-point comparison
			for _, option := range h.cfg.Recharge.Options {
				if math.Abs(option.Amount-order.Amount) < tolerance && option.Bonus > 0 {
					bonusAmount = option.Bonus
					break
				}
			}

			// Total amount to add = recharge amount + bonus
			totalAmount := order.Amount + bonusAmount

			// Update user balance with total amount (including bonus)
			updatedUser, processErr := h.userRepo.UpdateBalance(order.UserID, totalAmount)
			if processErr != nil {
				log.Printf("Payment notify: failed to update balance for user %d, order %s: %v", order.UserID, outTradeNo, processErr)
			} else {
				if bonusAmount > 0 {
					log.Printf("Payment notify: successfully recharged %.2f (bonus: %.2f, total: %.2f) for user %d, order %s", order.Amount, bonusAmount, totalAmount, order.UserID, outTradeNo)
				} else {
					log.Printf("Payment notify: successfully recharged %.2f for user %d, order %s", order.Amount, order.UserID, outTradeNo)
				}
				
				// Create balance log for payment recharge
				if h.balanceLogRepo != nil && updatedUser != nil {
					relatedID := order.ID
					reason := "在线充值"
					if bonusAmount > 0 {
						reason = fmt.Sprintf("在线充值 (赠送 %.2f)", bonusAmount)
					}
					balanceLog := &model.BalanceLog{
						UserID:        order.UserID,
						Amount:        totalAmount,
						BalanceBefore: balanceBefore,
						BalanceAfter:  updatedUser.Balance,
						Type:          "payment",
						Reason:        reason,
						OperatorType:  "system",
						RelatedID:     &relatedID,
					}
					h.balanceLogRepo.Create(balanceLog)
				}
			}
		case "vip":
			// Update user VIP level
			currentUser, findErr := h.userRepo.FindByID(order.UserID)
			if findErr != nil {
				log.Printf("Payment notify: failed to find user %d for order %s: %v", order.UserID, outTradeNo, findErr)
				processErr = findErr
			} else if currentUser.VIPLevel > order.ProductID {
				// User already has higher VIP level - cannot downgrade
				log.Printf("Payment notify: user %d already has VIP level %d (> requested %d), skipping for order %s", 
					order.UserID, currentUser.VIPLevel, order.ProductID, outTradeNo)
				// No error - order is successful but no change needed (should not happen normally)
			} else if currentUser.VIPLevel == order.ProductID {
				// Same level - check if renewal is allowed and process renewal
				var vipConfig *config.VIPLevelConfig
				for i := range h.cfg.VIPLevels {
					if h.cfg.VIPLevels[i].Level == order.ProductID {
						vipConfig = &h.cfg.VIPLevels[i]
						break
					}
				}

				if vipConfig == nil || !vipConfig.AllowRenewal {
					// Renewal not allowed - just log it
					log.Printf("Payment notify: user %d already has VIP level %d and renewal not allowed, skipping for order %s", 
						order.UserID, currentUser.VIPLevel, outTradeNo)
				} else {
					// Renewal is allowed - extend VIP duration
					// Use the duration stored in the order first, then fall back to config
					duration := order.Duration
					if duration <= 0 {
						// Fall back to VIP config duration
						duration = vipConfig.Duration
					}
					if duration <= 0 {
						duration = DefaultVIPDurationDays // Default to 30 days if still not set
					}
					_, processErr = h.userRepo.RenewVIPLevel(order.UserID, order.ProductID, duration)
					if processErr != nil {
						log.Printf("Payment notify: failed to renew VIP level %d for user %d, order %s: %v", order.ProductID, order.UserID, outTradeNo, processErr)
					} else {
						log.Printf("Payment notify: successfully renewed VIP level %d for user %d (duration: %d days), order %s", order.ProductID, order.UserID, duration, outTradeNo)
					}
				}
			} else {
				// Proceed with VIP upgrade or new purchase
				// Use the duration stored in the order first, then fall back to config
				duration := order.Duration
				if duration <= 0 {
					// Fall back to VIP config duration
					for i := range h.cfg.VIPLevels {
						if h.cfg.VIPLevels[i].Level == order.ProductID {
							duration = h.cfg.VIPLevels[i].Duration
							break
						}
					}
				}
				if duration <= 0 {
					duration = DefaultVIPDurationDays // Default to 30 days if still not set
				}
				_, processErr = h.userRepo.SetVIPLevelWithDuration(order.UserID, order.ProductID, duration)
				if processErr != nil {
					log.Printf("Payment notify: failed to set VIP level %d for user %d, order %s: %v", order.ProductID, order.UserID, outTradeNo, processErr)
				} else {
					log.Printf("Payment notify: successfully upgraded user %d from VIP level %d to %d (duration: %d days), order %s", order.UserID, currentUser.VIPLevel, order.ProductID, duration, outTradeNo)
				}
			}
		default:
			log.Printf("Payment notify: unknown product type %s for order %s", order.ProductType, outTradeNo)
		}

		// If processing failed, revert order status to pending so it can be retried
		if processErr != nil {
			if revertErr := h.paymentOrderRepo.RevertToPending(outTradeNo); revertErr != nil {
				log.Printf("Payment notify: failed to revert order %s to pending: %v", outTradeNo, revertErr)
			} else {
				log.Printf("Payment notify: reverted order %s to pending for retry", outTradeNo)
			}
			// Return fail to trigger retry from payment system
			c.String(http.StatusBadRequest, "fail")
			return
		}
	} else {
		// Mark order as failed for non-success status
		log.Printf("Payment notify: order %s has status %s, marking as failed", outTradeNo, tradeStatus)
		if err := h.paymentOrderRepo.MarkAsFail(outTradeNo); err != nil {
			log.Printf("Payment notify: failed to mark order %s as failed: %v", outTradeNo, err)
		}
	}

	// Return success to PyPay
	c.String(http.StatusOK, "success")
}
