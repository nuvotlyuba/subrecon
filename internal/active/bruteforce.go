package active

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
)

type BruteforceConfig struct {
	Workers int
}

func DefaultBruteforceConfig() BruteforceConfig {
	return BruteforceConfig{Workers: 50}
}

func Bruteforce(ctx context.Context, domain, wordlistPath string, cfg BruteforceConfig) (map[string]struct{}, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть словарь %s: %w", wordlistPath, err)
	}
	defer file.Close()

	jobs := make(chan string)
	found := make(map[string]struct{})
	var mu sync.Mutex
	var wg sync.WaitGroup

	resolver := net.DefaultResolver

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				candidate := word + "." + domain
				if _, err := resolver.LookupHost(ctx, candidate); err == nil {
					mu.Lock()
					found[candidate] = struct{}{}
					mu.Unlock()
				}
			}
		}()
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := scanner.Text()
		if word == "" {
			continue
		}
		select {
		case jobs <- word:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return found, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		return found, fmt.Errorf("ошибка чтения словаря: %w", err)
	}
	return found, nil
}
