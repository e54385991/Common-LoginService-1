package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"mime"

	"github.com/e54385991/Common-LoginService/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// EmailService handles email operations
type EmailService struct {
	cfg *config.Config
}

// NewEmailService creates a new EmailService
func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{cfg: cfg}
}

// SendPasswordResetEmail sends a password reset email
func (s *EmailService) SendPasswordResetEmail(toEmail, resetToken, baseURL string) error {
	if !s.cfg.GmailAPI.Enabled {
		return fmt.Errorf("Gmail API 未启用")
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

// sendEmail sends an email using Gmail API
func (s *EmailService) sendEmail(to, subject, htmlBody string) error {
	ctx := context.Background()

	// Create Gmail service
	srv, err := s.getGmailService(ctx)
	if err != nil {
		return err
	}

	// Create message with RFC 2047 encoded subject for non-ASCII characters
	from := s.cfg.GmailAPI.SenderEmail
	encodedSubject := mime.QEncoding.Encode("UTF-8", subject)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, to, encodedSubject, htmlBody)

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

// SendWelcomeEmail sends a welcome email to new users
func (s *EmailService) SendWelcomeEmail(toEmail, username, baseURL string) error {
	if !s.cfg.GmailAPI.Enabled {
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
	if !s.cfg.GmailAPI.Enabled {
		return fmt.Errorf("Gmail API 未启用")
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
