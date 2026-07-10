// Package probe делает HTTP-пробинг живых доменов: статус-код, тайтл,
// определение технологий. Не ищет поддомены — только проверяет уже найденные.
package probe

import (
	"fmt"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
)

// Result — упрощённая проекция runner.Result httpx (полная структура
// содержит десятки полей, нам достаточно этих).
type Result struct {
	URL          string
	StatusCode   int
	Title        string
	Technologies []string
}

// Probe запускает httpx как библиотеку (через New + RunEnumeration) и
// собирает результаты синхронно через колбэк Options.OnResult
// (подтверждено: пакет runner, v1.3.7, поле используется в runner.go:747).
func Probe(domains []string) ([]Result, error) {
	var results []Result

	options := runner.Options{
		InputTargetHost: goflags.StringSlice(domains),
		StatusCode:      true,
		ExtractTitle:    true,
		TechDetect:      true,
		Silent:          true,
		OnResult: func(r runner.Result) {
			if r.Err != nil {
				return
			}
			results = append(results, Result{
				URL:          r.URL,
				StatusCode:   r.StatusCode,
				Title:        r.Title,
				Technologies: r.Technologies,
			})
		},
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать httpx runner: %w", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	return results, nil
}
