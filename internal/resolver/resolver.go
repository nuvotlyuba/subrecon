// Package resolver проверяет, действительно ли найденные поддомены
// резолвятся в DNS — отсеивает "мёртвые" записи из CT-логов.
package resolver

import (
	"context"
	"net"
	"sync"
)

// ResolveOne возвращает true, если у домена есть хотя бы одна A/AAAA запись.
func ResolveOne(ctx context.Context, resolver *net.Resolver, domain string) bool {
	_, err := resolver.LookupHost(ctx, domain)
	return err == nil
}

// FilterAlive параллельно резолвит множество доменов и возвращает только живые.
// maxWorkers ограничивает число одновременных DNS-запросов, чтобы не устроить
// самому себе (или, что хуже, чужому DNS-серверу) непреднамеренный флуд.
func FilterAlive(ctx context.Context, domains map[string]struct{}, maxWorkers int) map[string]struct{} {
	resolver := net.DefaultResolver

	type result struct {
		domain string
		alive  bool
	}

	jobs := make(chan string)
	results := make(chan result)

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				results <- result{domain: d, alive: ResolveOne(ctx, resolver, d)}
			}
		}()
	}

	go func() {
		for d := range domains {
			jobs <- d
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	alive := make(map[string]struct{})
	for r := range results {
		if r.alive {
			alive[r.domain] = struct{}{}
		}
	}
	return alive
}
