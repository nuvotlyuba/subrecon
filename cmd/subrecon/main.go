// Command subrecon — оркестратор пассивной и активной разведки поддоменов.
//
//	subrecon example.com
//	subrecon example.com --active --wordlist wordlists/subdomains-top5000.txt
//	subrecon example.com --active --http-probe
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/yourname/subrecon-go/internal/active"
	"github.com/yourname/subrecon-go/internal/passive"
	"github.com/yourname/subrecon-go/internal/probe"
	"github.com/yourname/subrecon-go/internal/resolver"
)

func main() {
	domain := flag.String("domain", "", "целевой домен (можно позиционным аргументом)")
	activeFlag := flag.Bool("active", false, "добавить активный DNS-брутфорс")
	wordlist := flag.String("wordlist", "wordlists/subdomains-top5000.txt", "путь к словарю для брутфорса")
	noResolve := flag.Bool("no-resolve", false, "не фильтровать мёртвые DNS-записи")
	httpProbe := flag.Bool("http-probe", false, "прогнать живые домены через httpx")
	output := flag.String("output", "subdomains.json", "файл для результатов")
	flag.Parse()

	target := *domain
	if target == "" && flag.NArg() > 0 {
		target = flag.Arg(0)
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "использование: subrecon <domain> [флаги]")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	found := runPassive(ctx, target)

	if *activeFlag {
		bruteResults, err := active.Bruteforce(ctx, target, *wordlist, active.DefaultBruteforceConfig())
		if err != nil {
			log.Printf("[!] Ошибка брутфорса: %v", err)
		}
		for d := range bruteResults {
			found[d] = struct{}{}
		}
		log.Printf("    gobuster-style brute: найдено %d", len(bruteResults))
	}

	log.Printf("[+] Всего уникальных поддоменов (до фильтрации): %d", len(found))

	if !*noResolve {
		found = resolver.FilterAlive(ctx, found, 30)
	}

	sorted := make([]string, 0, len(found))
	for d := range found {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)

	data, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		log.Fatalf("не удалось сериализовать результат: %v", err)
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		log.Fatalf("не удалось записать файл %s: %v", *output, err)
	}
	log.Printf("[+] Результат сохранён в %s", *output)

	if *httpProbe {
		results, err := probe.Probe(sorted)
		if err != nil {
			log.Printf("[!] Ошибка httpx-пробинга: %v", err)
		} else {
			probeData, _ := json.MarshalIndent(results, "", "  ")
			os.WriteFile("httpx_results.json", probeData, 0o644)
			log.Printf("[+] HTTP-пробы сохранены в httpx_results.json")
		}
	}
}

func runPassive(ctx context.Context, domain string) map[string]struct{} {
	log.Printf("[*] Пассивная разведка для %s...", domain)

	found := make(map[string]struct{})
	var mu sync.Mutex
	var wg sync.WaitGroup

	merge := func(name string, subs map[string]struct{}, err error) {
		defer wg.Done()
		if err != nil {
			log.Printf("[!] %s: %v", name, err)
			return
		}
		log.Printf("    %s: найдено %d", name, len(subs))
		mu.Lock()
		for d := range subs {
			found[d] = struct{}{}
		}
		mu.Unlock()
	}

	wg.Add(4)
	go func() {
		subs, err := passive.Subfinder(domain)
		merge("subfinder", subs, err)
	}()
	go func() {
		subs, err := passive.Assetfinder(ctx, domain)
		merge("assetfinder", subs, err)
	}()
	go func() {
		subs, err := passive.Amass(ctx, domain)
		merge("amass", subs, err)
	}()
	go func() {
		subs, err := passive.Crtsh(ctx, domain, passive.DefaultCrtshConfig())
		merge("crt.sh", subs, err)
	}()
	wg.Wait()

	return found
}
