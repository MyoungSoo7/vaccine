// Package notify pushes findings to external channels. Telegram only for now
// (zero-dep, just an HTTPS POST to the Bot API).
package notify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Telegram struct {
	BotToken string
	ChatID   string
	client   *http.Client
}

func NewTelegram(botToken, chatID string) *Telegram {
	return &Telegram{
		BotToken: botToken,
		ChatID:   chatID,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Send delivers a message to the configured chat. No-op if not configured.
func (t *Telegram) Send(ctx context.Context, text string) error {
	if t == nil || t.BotToken == "" || t.ChatID == "" {
		return nil
	}
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.BotToken)

	form := url.Values{}
	form.Set("chat_id", t.ChatID)
	form.Set("text", text)
	form.Set("parse_mode", "HTML")
	form.Set("disable_web_page_preview", "true")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram status %d", resp.StatusCode)
	}
	return nil
}

// Enabled reports whether the channel is fully configured.
func (t *Telegram) Enabled() bool {
	return t != nil && t.BotToken != "" && t.ChatID != ""
}

// ErrDisabled is returned by callers that require an enabled notifier.
var ErrDisabled = errors.New("telegram notifier disabled (token or chat_id missing)")
