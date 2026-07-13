package passive

import (
	"fmt"
	"io"
	"sync"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

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

	if err := subfinderRunner.EnumerateSingleDomain(domain, []io.Writer{}); err != nil {
		return found, fmt.Errorf("subfinder enumeration завершился с ошибкой: %w", err)
	}

	return found, nil
}
