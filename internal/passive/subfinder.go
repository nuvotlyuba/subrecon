package passive

import (
	"fmt"
	"io"
	"sync"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Subfinder встраивает subfinder как библиотеку — без запуска внешнего
// процесса. Используется runner.Options.ResultCallback (подтверждено в
// pkg/runner/enumerate.go v2.6.6), который вызывается синхронно для
// каждого найденного поддомена — то есть результат идёт напрямую в
// память, без парсинга текстового вывода дочернего процесса.
//
// ВАЖНО: subfinder v2.6.6 требует Go >= 1.21 и тянет транзитивные
// зависимости через golang.org/x/*. Перед первым запуском:
//
//	go mod tidy
//
// потребует доступ в интернет (обычный, без ограничений корпоративной
// песочницы) — модули резолвятся через vanity-домены golang.org и т.п.
func Subfinder(domain string) (map[string]struct{}, error) {
	found := make(map[string]struct{})
	var mu sync.Mutex

	options := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Silent:             true,
		RemoveWildcard:     false,
		ResultCallback: func(entry *resolve.HostEntry) {
			mu.Lock()
			found[entry.Host] = struct{}{}
			mu.Unlock()
		},
	}

	subfinderRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать subfinder runner: %w", err)
	}

	// EnumerateSingleDomain пишет и в Output (io.Writer), и дёргает
	// ResultCallback. Output нам не нужен, поэтому передаём пустой слайс.
	if err := subfinderRunner.EnumerateSingleDomain(domain, []io.Writer{}); err != nil {
		return found, fmt.Errorf("subfinder enumeration завершился с ошибкой: %w", err)
	}

	return found, nil
}
