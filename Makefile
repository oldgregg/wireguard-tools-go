wgg-fips:
	GOFIPS140=v1.0.0 CGO_ENABLED=0 go build -o "$@" -trimpath ./cmd/wgg/
