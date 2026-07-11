# subrecon

Оркестратор разведки поддоменов. Опрашивает четыре пассивных источника
(`subfinder`, `assetfinder`, `amass`, `crt.sh`) параллельно, умеет
активный DNS-брутфорс по словарю, фильтрует мёртвые записи и прогоняет
живые хосты через `httpx`.

`subfinder` и `httpx` подключены как библиотеки (через колбэки
`ResultCallback`/`OnResult`), а не через `os/exec` — результат идёт
напрямую в память, без парсинга текстового вывода дочернего процесса.
У `assetfinder` и `amass` такого API нет, поэтому они запускаются как
внешние процессы. Брутфорс — свой, на `net.LookupHost` + горутинах, без
зависимости от `gobuster`.

## Установка

```bash
git clone git@github.com:nuvotlyuba/subrecon.git
cd subrecon
go mod tidy
go build -o subrecon ./cmd/subrecon
```

Для `assetfinder` и `amass` бинарники должны быть доступны в `PATH`:

```bash
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
```

## Использование

```bash
./subrecon example.com
./subrecon example.com --active --wordlist wordlists/subdomains-top5000.txt
./subrecon example.com --active --http-probe
```

## Структура

```
subrecon-go/
├── cmd/subrecon/main.go     # CLI entrypoint
├── internal/
│   ├── passive/
│   │   ├── subfinder.go     # subfinder как библиотека
│   │   ├── assetfinder.go   # через os/exec
│   │   ├── amass.go         # через os/exec
│   │   └── crtsh.go         # запрос к crt.sh, чистый net/http
│   ├── active/
│   │   └── bruteforce.go    # DNS-брутфорс по словарю
│   ├── resolver/
│   │   └── resolver.go      # фильтрация мёртвых записей
│   └── probe/
│       └── httpx.go         # httpx как библиотека
```
