package passive

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Assetfinder запускает внешний бинарник assetfinder и возвращает
// множество поддоменов. У assetfinder нет библиотечного API (только
// CLI), поэтому, в отличие от subfinder/httpx, здесь используется
// os/exec — как и в Python-версии проекта.
func Assetfinder(ctx context.Context, domain string) (map[string]struct{}, error) {
	cmd := exec.CommandContext(ctx, "assetfinder", "--subs-only", domain)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			// Не "процесс завершился с ошибкой", а что-то более фатальное —
			// например, бинарник не найден в PATH. Тут падать оправдано.
			return nil, fmt.Errorf("assetfinder: %w", err)
		}
		// *exec.ExitError: процесс завершился с ненулевым кодом, но stdout
		// мог успеть накопить валидные данные — не выбрасываем их.
		// stderr логируем как диагностику, но не как фатальную ошибку.
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
		// assetfinder иногда отдаёт поддомены сторонних доменов — фильтруем,
		// как и в Python-версии.
		if strings.HasSuffix(d, domain) {
			found[d] = struct{}{}
		}
	}
	return found, nil
}
