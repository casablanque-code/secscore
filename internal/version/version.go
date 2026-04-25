package version

// Version is set at build time:
//   go build -ldflags "-X secscore/internal/version.Version=v0.2.0" ./cmd/secscore
var Version = "dev"
