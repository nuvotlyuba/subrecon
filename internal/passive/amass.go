package passive

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

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
