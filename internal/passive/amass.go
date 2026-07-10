package passive

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Amass запускает внешний бинарник amass в пассивном режиме
// (`amass enum -passive`) и возвращает множество поддоменов.
//
// У amass есть внутренние Go-пакеты (github.com/owasp-amass/amass/v4/...),
// но они рассчитаны на встраивание в собственный движок enum-графа
// (ASN/netblock-корреляция) и требуют заметно больше кода для
// интеграции, чем колбэк subfinder/httpx. os/exec здесь — прагматичный
// выбор: та же логика, что и в Python-версии проекта.
//
// amass особенно часто завершается с ненулевым кодом выхода при
// отсутствии части API-ключей (для платных источников), даже если
// найденные через бесплатные источники поддомены уже есть в stdout —
// поэтому здесь важно не терять stdout при *exec.ExitError.
func Amass(ctx context.Context, domain string) (map[string]struct{}, error) {
	cmd := exec.CommandContext(ctx, "amass", "enum", "-passive", "-d", domain, "-silent")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, fmt.Errorf("amass: %w", err)
		}
		if stderr.Len() > 0 {
			fmt.Printf("[!] amass завершился с предупреждением: %s\n", strings.TrimSpace(stderr.String()))
		}
	}

	found := make(map[string]struct{})
	for _, line := range strings.Split(stdout.String(), "\n") {
		d := strings.ToLower(strings.TrimSpace(line))
		if d != "" {
			found[d] = struct{}{}
		}
	}
	return found, nil
}
