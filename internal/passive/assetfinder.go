package passive

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func Assetfinder(ctx context.Context, domain string) (map[string]struct{}, error) {
	cmd := exec.CommandContext(ctx, "assetfinder", "--subs-only", domain)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, fmt.Errorf("assetfinder: %w", err)
		}
		if stderr.Len() > 0 {
			fmt.Printf("[!] assetfinder завершился с предупреждением: %s\n", strings.TrimSpace(stderr.String()))
		}
	}

	found := make(map[string]struct{})
	for _, line := range strings.Split(stdout.String(), "\n") {
		d := strings.ToLower(strings.TrimSpace(line))
		if d == "" {
			continue
		}
		if strings.HasSuffix(d, domain) {
			found[d] = struct{}{}
		}
	}
	return found, nil
}
