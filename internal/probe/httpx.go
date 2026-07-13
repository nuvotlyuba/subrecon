package probe

import (
	"fmt"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
)

type Result struct {
	URL          string
	StatusCode   int
	Title        string
	Technologies []string
}

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
