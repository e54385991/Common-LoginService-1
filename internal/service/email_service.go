package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime"
	"net/smtp"
	"strings"

	"github.com/e54385991/Common-LoginService/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// Email provider constants
const (
	EmailProviderGmailAPI = "gmail_api"
	EmailProviderSMTP     = "smtp"
)

// EmailService handles email operations
type EmailService struct {
	cfg *config.Config
}

// NewEmailService creates a new EmailService
func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{cfg: cfg}
}

// sanitizeEmailHeader sanitizes an email address to prevent header injection
// by removing any characters that could be used for injection (newlines, carriage returns)
func sanitizeEmailHeader(s string) string {
	// Remove any characters that could be used for header injection
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	return s
}

// isEmailEnabled checks if any email provider is enabled
func (s *EmailService) isEmailEnabled() bool {
	provider := s.cfg.Email.Provider
	if provider == EmailProviderSMTP {
		return s.cfg.SMTP.Enabled
	}
	// Default to Gmail API
	return s.cfg.GmailAPI.Enabled
}

// getSenderEmail returns the configured sender email address
func (s *EmailService) getSenderEmail() string {
	provider := s.cfg.Email.Provider
	if provider == EmailProviderSMTP {
		return s.cfg.SMTP.SenderEmail
	}
	return s.cfg.GmailAPI.SenderEmail
}

// SendPasswordResetEmail sends a password reset email
func (s *EmailService) SendPasswordResetEmail(toEmail, resetToken, baseURL string) error {
	if !s.isEmailEnabled() {
		return fmt.Errorf("邮件服务未启用")
	}

	resetLink := fmt.Sprintf("%s/auth/reset-password?token=%s", baseURL, resetToken)

	subject := "密码重置请求 - Common Login Service"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>密码重置</h1>
        </div>
        <div class="content">
            <p>您好，</p>
            <p>我们收到了您的密码重置请求。请点击下方按钮重置您的密码：</p>
            <p style="text-align: center;">
                <a href="%s" class="button">重置密码</a>
            </p>
            <p>如果按钮无法点击，请复制以下链接到浏览器：</p>
            <p style="word-break: break-all; color: #667eea;">%s</p>
            <p>此链接将在1小时后失效。</p>
            <p>如果您没有请求重置密码，请忽略此邮件。</p>
        </div>
        <div class="footer">
            <p>此邮件由 Common Login Service 自动发送，请勿回复。</p>
        </div>
    </div>
</body>
</html>
`, resetLink, resetLink)

	return s.sendEmail(toEmail, subject, body)
}

// getGmailService creates a Gmail service using OAuth2 credentials or credentials file
func (s *EmailService) getGmailService(ctx context.Context) (*gmail.Service, error) {
	// Try OAuth2 credentials first (client_id, client_secret, refresh_token)
	if s.cfg.GmailAPI.ClientID != "" && s.cfg.GmailAPI.ClientSecret != "" && s.cfg.GmailAPI.RefreshToken != "" {
		oauthConfig := &oauth2.Config{
			ClientID:     s.cfg.GmailAPI.ClientID,
			ClientSecret: s.cfg.GmailAPI.ClientSecret,
			Endpoint:     google.Endpoint,
			Scopes:       []string{gmail.GmailSendScope},
		}

		token := &oauth2.Token{
			RefreshToken: s.cfg.GmailAPI.RefreshToken,
		}

		tokenSource := oauthConfig.TokenSource(ctx, token)
		srv, err := gmail.NewService(ctx, option.WithTokenSource(tokenSource))
		if err != nil {
			return nil, fmt.Errorf("无法使用OAuth2创建Gmail服务: %v", err)
		}
		return srv, nil
	}

	// Fall back to credentials file (service account or downloaded credentials)
	if s.cfg.GmailAPI.CredentialsFile != "" {
		srv, err := gmail.NewService(ctx, option.WithCredentialsFile(s.cfg.GmailAPI.CredentialsFile))
		if err != nil {
			return nil, fmt.Errorf("无法使用凭据文件创建Gmail服务: %v", err)
		}
		return srv, nil
	}

	return nil, fmt.Errorf("未配置Gmail API凭据")
}

// sendEmail sends an email using the configured provider (Gmail API or SMTP)
func (s *EmailService) sendEmail(to, subject, htmlBody string) error {
	provider := s.cfg.Email.Provider
	if provider == EmailProviderSMTP {
		return s.sendEmailViaSMTP(to, subject, htmlBody)
	}
	// Default to Gmail API
	return s.sendEmailViaGmailAPI(to, subject, htmlBody)
}

// sendEmailViaGmailAPI sends an email using Gmail API
func (s *EmailService) sendEmailViaGmailAPI(to, subject, htmlBody string) error {
	ctx := context.Background()

	// Create Gmail service
	srv, err := s.getGmailService(ctx)
	if err != nil {
		return err
	}

	// Create message with RFC 2047 encoded subject for non-ASCII characters
	// Sanitize email addresses to prevent header injection
	from := sanitizeEmailHeader(s.cfg.GmailAPI.SenderEmail)
	sanitizedTo := sanitizeEmailHeader(to)
	encodedSubject := mime.QEncoding.Encode("UTF-8", subject)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, sanitizedTo, encodedSubject, htmlBody)

	// Encode to base64
	encodedMsg := base64.URLEncoding.EncodeToString([]byte(msg))

	// Send email
	message := &gmail.Message{
		Raw: encodedMsg,
	}

	_, err = srv.Users.Messages.Send("me", message).Do()
	if err != nil {
		return fmt.Errorf("发送邮件失败: %v", err)
	}

	return nil
}

// sendEmailViaSMTP sends an email using SMTP
func (s *EmailService) sendEmailViaSMTP(to, subject, htmlBody string) error {
	cfg := s.cfg.SMTP

	// Sanitize email addresses to prevent header injection
	from := sanitizeEmailHeader(cfg.SenderEmail)
	sanitizedTo := sanitizeEmailHeader(to)
	encodedSubject := mime.QEncoding.Encode("UTF-8", subject)

	// Build message headers
	fromHeader := from
	if cfg.SenderName != "" {
		fromHeader = fmt.Sprintf("%s <%s>", sanitizeEmailHeader(cfg.SenderName), from)
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		fromHeader, sanitizedTo, encodedSubject, htmlBody)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	// Configure authentication
	var auth smtp.Auth
	if cfg.Username != "" && cfg.Password != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	// Send email with SSL (port 465) - takes priority if both are enabled
	if cfg.UseSSL {
		return s.sendEmailViaSMTPSSL(addr, auth, from, sanitizedTo, []byte(msg))
	}

	// Send email with TLS (STARTTLS on port 587)
	if cfg.UseTLS {
		return s.sendEmailViaSMTPTLS(addr, auth, from, sanitizedTo, []byte(msg))
	}

	// Require encryption - no insecure fallback
	return fmt.Errorf("SMTP 必须启用 TLS 或 SSL 加密")
}

// sendEmailViaSMTPTLS sends email using STARTTLS
func (s *EmailService) sendEmailViaSMTPTLS(addr string, auth smtp.Auth, from, to string, msg []byte) error {
	cfg := s.cfg.SMTP

	// Connect to the SMTP server
	conn, err := smtp.Dial(addr)
	if err != nil {
		// Check if error suggests SSL connection is needed
		if strings.Contains(err.Error(), "short response") || strings.Contains(err.Error(), "EOF") {
			return fmt.Errorf("连接 SMTP 服务器失败 (可能需要使用 SSL 而非 TLS): %v", err)
		}
		return fmt.Errorf("连接 SMTP 服务器失败: %v", err)
	}
	defer conn.Close()

	// Start TLS
	tlsConfig := &tls.Config{
		ServerName: cfg.Host,
	}
	if err := conn.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("启动 TLS 失败 (服务器可能需要 SSL 而非 STARTTLS): %v", err)
	}

	// Authenticate
	if auth != nil {
		if err := conn.Auth(auth); err != nil {
			return fmt.Errorf("SMTP 认证失败: %v", err)
		}
	}

	// Set sender
	if err := conn.Mail(from); err != nil {
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// Set recipient
	if err := conn.Rcpt(to); err != nil {
		return fmt.Errorf("设置收件人失败: %v", err)
	}

	// Send message body
	w, err := conn.Data()
	if err != nil {
		return fmt.Errorf("打开数据通道失败: %v", err)
	}
	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("关闭数据通道失败: %v", err)
	}

	// Quit gracefully - ignore errors since email was already sent successfully
	// Some SMTP servers may close connection before responding to QUIT
	_ = conn.Quit()
	return nil
}

// sendEmailViaSMTPSSL sends email using implicit SSL (port 465)
func (s *EmailService) sendEmailViaSMTPSSL(addr string, auth smtp.Auth, from, to string, msg []byte) error {
	cfg := s.cfg.SMTP

	// TLS config
	tlsConfig := &tls.Config{
		ServerName: cfg.Host,
	}

	// Connect with TLS
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		// Check if error suggests TLS/STARTTLS connection is needed instead
		if strings.Contains(err.Error(), "handshake") || strings.Contains(err.Error(), "protocol") {
			return fmt.Errorf("连接 SMTP SSL 服务器失败 (可能需要使用 TLS/STARTTLS 而非 SSL): %v", err)
		}
		return fmt.Errorf("连接 SMTP SSL 服务器失败: %v", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("创建 SMTP 客户端失败: %v", err)
	}
	defer client.Close()

	// Authenticate
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP 认证失败: %v", err)
		}
	}

	// Set sender
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// Set recipient
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("设置收件人失败: %v", err)
	}

	// Send message body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("打开数据通道失败: %v", err)
	}
	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("关闭数据通道失败: %v", err)
	}

	// Quit gracefully - ignore errors since email was already sent successfully
	// Some SMTP servers (like QQ mail) may close connection before responding to QUIT
	_ = client.Quit()
	return nil
}

// TestEmailResult represents the result of a test email operation
type TestEmailResult struct {
	Success     bool                   `json:"success"`
	Message     string                 `json:"message"`
	Provider    string                 `json:"provider,omitempty"`
	APIResponse map[string]interface{} `json:"api_response,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// SendTestEmail sends a test email and returns the result for debugging
func (s *EmailService) SendTestEmail(toEmail string) *TestEmailResult {
	provider := s.cfg.Email.Provider
	if provider == EmailProviderSMTP {
		return s.sendTestEmailViaSMTP(toEmail)
	}
	// Default to Gmail API
	return s.sendTestEmailViaGmailAPI(toEmail)
}

// sendTestEmailViaGmailAPI sends a test email via Gmail API
func (s *EmailService) sendTestEmailViaGmailAPI(toEmail string) *TestEmailResult {
	result := &TestEmailResult{
		Success:     false,
		Provider:    EmailProviderGmailAPI,
		APIResponse: make(map[string]interface{}),
	}

	// Check if Gmail API is enabled
	if !s.cfg.GmailAPI.Enabled {
		result.Error = "Gmail API 未启用"
		result.Message = "请先启用 Gmail API"
		return result
	}

	// Check if sender email is configured
	if s.cfg.GmailAPI.SenderEmail == "" {
		result.Error = "发送邮箱未配置"
		result.Message = "请配置发送邮箱地址"
		return result
	}

	ctx := context.Background()

	// Create Gmail service - this validates credentials internally
	srv, err := s.getGmailService(ctx)
	if err != nil {
		result.Error = err.Error()
		result.Message = "创建 Gmail 服务失败"
		return result
	}

	// Create test email content
	subject := "测试邮件 - Common Login Service"
	htmlBody := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 8px 8px; }
        .success { color: #28a745; font-size: 48px; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Gmail API 测试</h1>
        </div>
        <div class="content">
            <p style="text-align: center;"><span class="success">✓</span></p>
            <h2 style="text-align: center;">配置成功！</h2>
            <p>这是一封测试邮件，用于验证您的 Gmail API 配置是否正确。</p>
            <p>如果您收到此邮件，说明您的 Gmail API 已正确配置，可以正常发送邮件。</p>
        </div>
        <div class="footer">
            <p>此邮件由 Common Login Service 自动发送，请勿回复。</p>
        </div>
    </div>
</body>
</html>`

	// Create message with RFC 2047 encoded subject for non-ASCII characters
	// Sanitize email addresses to prevent header injection
	from := sanitizeEmailHeader(s.cfg.GmailAPI.SenderEmail)
	sanitizedTo := sanitizeEmailHeader(toEmail)
	encodedSubject := mime.QEncoding.Encode("UTF-8", subject)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, sanitizedTo, encodedSubject, htmlBody)

	// Encode to base64
	encodedMsg := base64.URLEncoding.EncodeToString([]byte(msg))

	// Send email
	message := &gmail.Message{
		Raw: encodedMsg,
	}

	// Send and capture the full response
	response, err := srv.Users.Messages.Send("me", message).Do()
	if err != nil {
		result.Error = err.Error()
		result.Message = "发送邮件失败"
		return result
	}

	// Populate API response details
	result.Success = true
	result.Message = "测试邮件发送成功"
	result.APIResponse["id"] = response.Id
	result.APIResponse["threadId"] = response.ThreadId
	result.APIResponse["labelIds"] = response.LabelIds
	result.APIResponse["snippet"] = response.Snippet
	result.APIResponse["historyId"] = response.HistoryId
	result.APIResponse["internalDate"] = response.InternalDate
	result.APIResponse["sizeEstimate"] = response.SizeEstimate

	return result
}

// sendTestEmailViaSMTP sends a test email via SMTP
func (s *EmailService) sendTestEmailViaSMTP(toEmail string) *TestEmailResult {
	result := &TestEmailResult{
		Success:     false,
		Provider:    EmailProviderSMTP,
		APIResponse: make(map[string]interface{}),
	}

	cfg := s.cfg.SMTP

	// Check if SMTP is enabled
	if !cfg.Enabled {
		result.Error = "SMTP 未启用"
		result.Message = "请先启用 SMTP"
		return result
	}

	// Check if required fields are configured
	if cfg.Host == "" {
		result.Error = "SMTP 服务器未配置"
		result.Message = "请配置 SMTP 服务器地址"
		return result
	}

	if cfg.SenderEmail == "" {
		result.Error = "发送邮箱未配置"
		result.Message = "请配置发送邮箱地址"
		return result
	}

	// Add connection info to response for debugging
	result.APIResponse["host"] = cfg.Host
	result.APIResponse["port"] = cfg.Port
	result.APIResponse["sender"] = cfg.SenderEmail
	result.APIResponse["recipient"] = toEmail
	result.APIResponse["use_tls"] = cfg.UseTLS
	result.APIResponse["use_ssl"] = cfg.UseSSL
	result.APIResponse["has_username"] = cfg.Username != ""
	result.APIResponse["has_password"] = cfg.Password != ""

	// Add encryption mode hint
	if cfg.UseSSL {
		result.APIResponse["encryption_mode"] = "SSL (隐式, 端口通常为 465)"
	} else if cfg.UseTLS {
		result.APIResponse["encryption_mode"] = "TLS/STARTTLS (端口通常为 587)"
	} else {
		result.APIResponse["encryption_mode"] = "无加密 (不推荐)"
	}

	// Create test email content
	subject := "测试邮件 - Common Login Service"
	htmlBody := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 8px 8px; }
        .success { color: #28a745; font-size: 48px; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SMTP 邮件测试</h1>
        </div>
        <div class="content">
            <p style="text-align: center;"><span class="success">✓</span></p>
            <h2 style="text-align: center;">配置成功！</h2>
            <p>这是一封测试邮件，用于验证您的 SMTP 配置是否正确。</p>
            <p>如果您收到此邮件，说明您的 SMTP 已正确配置，可以正常发送邮件。</p>
        </div>
        <div class="footer">
            <p>此邮件由 Common Login Service 自动发送，请勿回复。</p>
        </div>
    </div>
</body>
</html>`

	// Send email via SMTP
	err := s.sendEmailViaSMTP(toEmail, subject, htmlBody)
	if err != nil {
		result.Error = err.Error()
		result.Message = "发送邮件失败"
		
		// Add helpful hints based on error
		errStr := err.Error()
		if strings.Contains(errStr, "short response") || strings.Contains(errStr, "EOF") {
			result.APIResponse["hint"] = "错误提示: 'short response' 通常表示加密方式不匹配。如果使用端口 465，请启用 SSL；如果使用端口 587，请启用 TLS。"
		} else if strings.Contains(errStr, "认证失败") {
			result.APIResponse["hint"] = "错误提示: 认证失败，请检查用户名和密码是否正确。如果使用 Gmail，需要使用应用专用密码。"
		} else if strings.Contains(errStr, "connection refused") {
			result.APIResponse["hint"] = "错误提示: 连接被拒绝，请检查服务器地址和端口是否正确。"
		}
		return result
	}

	// Success
	result.Success = true
	result.Message = "测试邮件发送成功"

	return result
}

// SendWelcomeEmail sends a welcome email to new users
func (s *EmailService) SendWelcomeEmail(toEmail, username, baseURL string) error {
	if !s.isEmailEnabled() {
		return nil // Silent return if not enabled
	}

	subject := "欢迎加入 - Common Login Service"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>欢迎加入！</h1>
        </div>
        <div class="content">
            <p>亲爱的 %s，</p>
            <p>欢迎加入 Common Login Service！您的账户已成功创建。</p>
            <p style="text-align: center;">
                <a href="%s/auth/login" class="button">立即登录</a>
            </p>
            <p>感谢您的注册！</p>
        </div>
        <div class="footer">
            <p>此邮件由 Common Login Service 自动发送，请勿回复。</p>
        </div>
    </div>
</body>
</html>
`, username, baseURL)

	return s.sendEmail(toEmail, subject, body)
}

// SendEmailVerificationEmail sends an email verification email with 6-digit code
func (s *EmailService) SendEmailVerificationEmail(toEmail, verificationCode, baseURL string) error {
	if !s.isEmailEnabled() {
		return fmt.Errorf("邮件服务未启用")
	}

	subject := "邮箱验证码 - Common Login Service"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 8px 8px; }
        .code-box { background: #fff; border: 2px dashed #667eea; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px; }
        .code { font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 8px; font-family: monospace; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>邮箱验证</h1>
        </div>
        <div class="content">
            <p>您好，</p>
            <p>您的邮箱验证码是：</p>
            <div class="code-box">
                <span class="code">%s</span>
            </div>
            <p>请在30分钟内使用此验证码完成邮箱验证。</p>
            <p>如果您没有请求验证邮箱，请忽略此邮件。</p>
        </div>
        <div class="footer">
            <p>此邮件由 Common Login Service 自动发送，请勿回复。</p>
        </div>
    </div>
</body>
</html>
`, verificationCode)

	return s.sendEmail(toEmail, subject, body)
}
