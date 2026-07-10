// Package passive содержит источники пассивной разведки поддоменов.
package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// crtshEntry — один элемент JSON-ответа crt.sh.
// Нас интересует только name_value — он может содержать несколько
// доменов через перенос строки (например, SAN-сертификат).
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// CrtshConfig задаёт таймаут и число повторных попыток запроса.
// crt.sh известен тем, что часто подвисает под нагрузкой — поэтому
// retry с экспоненциальной паузой включён по умолчанию.
type CrtshConfig struct {
	Timeout    time.Duration
	MaxRetries int
	BackoffBase time.Duration
}

func DefaultCrtshConfig() CrtshConfig {
	return CrtshConfig{
		Timeout:     60 * time.Second,
		MaxRetries:  3,
		BackoffBase: 2 * time.Second,
	}
}

// Crtsh запрашивает Certificate Transparency логи через crt.sh и
// возвращает множество поддоменов, принадлежащих указанному домену.
func Crtsh(ctx context.Context, domain string, cfg CrtshConfig) (map[string]struct{}, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	client := &http.Client{Timeout: cfg.Timeout}

	var lastErr error
	for attempt := 1; attempt <= cfg.MaxRetries; attempt++ {
		entries, err := fetchCrtsh(ctx, client, url)
		if err == nil {
			return extractSubdomains(entries, domain), nil
		}
		lastErr = err

		if attempt < cfg.MaxRetries {
			wait := cfg.BackoffBase * time.Duration(attempt)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return nil, fmt.Errorf("crt.sh недоступен после %d попыток: %w", cfg.MaxRetries, lastErr)
}

func fetchCrtsh(ctx context.Context, client *http.Client, url string) ([]crtshEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh вернул статус %d", resp.StatusCode)
	}

	var entries []crtshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("не удалось распарсить ответ crt.sh: %w", err)
	}
	return entries, nil
}

func extractSubdomains(entries []crtshEntry, domain string) map[string]struct{} {
	found := make(map[string]struct{})
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if strings.HasSuffix(name, domain) {
				found[name] = struct{}{}
			}
		}
	}
	return found
}
