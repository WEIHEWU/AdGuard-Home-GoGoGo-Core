module github.com/AdguardTeam/dnsproxy

go 1.26.8

require (
	github.com/AdguardTeam/dnscrypt v0.0.2
	github.com/AdguardTeam/golibs v0.35.13
	github.com/ameshkov/dnsstamps v1.0.3
	github.com/beefsack/go-rate v0.0.0-20220214233405-116f4ca011a0
	github.com/bluele/gcache v0.0.2
	github.com/miekg/dns v1.1.72
	github.com/quic-go/quic-go v0.60.0
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/net v0.57.0
	golang.org/x/sys v0.47.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
)

// NOTE:  Keep in sync with .gitignore.
ignore (
	./bin/
	./test-reports/
	./tmp/
)
