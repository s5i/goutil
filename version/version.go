package version

import (
	"fmt"
	"runtime/debug"
	"strings"
	"time"
)

// Can be filled in via ldflags, eg.
// $ go build -ldflags "-X 'github.com/s5i/goutil/version.External=${{ github.ref }}'"
var External string

// Get returns a version string.
func Get() string {
	if External != "" {
		return External
	}

	bi, ok := debug.ReadBuildInfo()
	if ok {
		settings := map[string]string{}
		for _, s := range bi.Settings {
			settings[s.Key] = s.Value
		}

		rev := settings["vcs.revision"]
		if rev != "" {
			var extra []string
			if revTime, revErr := time.Parse(time.RFC3339, settings["vcs.time"]); revErr == nil {
				extra = append(extra, revTime.UTC().Format("2006-01-02 15:04:05 UTC"))
			}
			if settings["vcs.modified"] == "true" {
				extra = append(extra, "modified")
			}
			if len(extra) != 0 {
				return fmt.Sprintf("%s (%s)", rev, strings.Join(extra, "; "))
			}
			return rev
		}
	}

	return "unknown"
}
