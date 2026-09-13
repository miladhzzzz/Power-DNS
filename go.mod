module github.com/miladhzzzz/power-dns

go 1.22

require (
	github.com/BurntSushi/toml v1.3.2
	github.com/miekg/dns v1.1.58
	golang.org/x/sync v0.6.0
)

require (
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/tools v0.17.0 // indirect
)

replace (
	golang.org/x/arch => github.com/golang/arch v0.5.0
	golang.org/x/crypto => github.com/golang/crypto v0.18.0
	golang.org/x/mod => github.com/golang/mod v0.14.0
	golang.org/x/net => github.com/golang/net v0.20.0
	golang.org/x/sync => github.com/golang/sync v0.6.0
	golang.org/x/sys => github.com/golang/sys v0.16.0
	golang.org/x/text => github.com/golang/text v0.14.0
	golang.org/x/tools => github.com/golang/tools v0.17.0
)
