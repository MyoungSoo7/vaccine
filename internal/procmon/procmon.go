// Package procmon lists running processes and flags command-lines that match
// well-known suspicious patterns. This is a passive, point-in-time check —
// real EDR needs ES (macOS) / fanotify+audit (Linux) which is Phase 3.
package procmon

import (
	"context"
	"regexp"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
)

type Process struct {
	PID     int32
	Name    string
	Cmdline string
	Username string
}

type Finding struct {
	Process Process
	Reason  string
	Pattern string
}

var suspicious = []struct {
	name string
	re   *regexp.Regexp
}{
	{"curl-piped-to-shell", regexp.MustCompile(`(?i)curl[^|]+\|\s*(bash|sh|zsh)`)},
	{"wget-piped-to-shell", regexp.MustCompile(`(?i)wget[^|]+\|\s*(bash|sh|zsh)`)},
	{"base64-decode-pipe-shell", regexp.MustCompile(`(?i)base64\s+(--decode|-d)[^|]*\|\s*(bash|sh|zsh)`)},
	{"powershell-encoded", regexp.MustCompile(`(?i)powershell.*-(e|enc|encodedcommand)\b`)},
	{"reverse-shell-bash-tcp", regexp.MustCompile(`bash\s+-i\s*>&?\s*/dev/tcp/`)},
	{"netcat-listener", regexp.MustCompile(`\b(nc|ncat|netcat)\b[^a-zA-Z]*-l[vp]*\s+`)},
	{"hidden-binary-tmp", regexp.MustCompile(`^/(tmp|var/tmp|dev/shm)/\.[A-Za-z0-9_-]+`)},
	{"miner-pool-stratum", regexp.MustCompile(`stratum\+tcp://`)},
}

// List returns all running processes (best-effort).
func List(ctx context.Context) ([]Process, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Process, 0, len(procs))
	for _, p := range procs {
		name, _ := p.NameWithContext(ctx)
		cmd, _ := p.CmdlineWithContext(ctx)
		user, _ := p.UsernameWithContext(ctx)
		out = append(out, Process{
			PID:      p.Pid,
			Name:     name,
			Cmdline:  cmd,
			Username: user,
		})
	}
	return out, nil
}

// Scan returns findings for processes whose cmdline matches a suspicious pattern.
func Scan(procs []Process) []Finding {
	var findings []Finding
	for _, p := range procs {
		cmd := strings.TrimSpace(p.Cmdline)
		if cmd == "" {
			continue
		}
		for _, pat := range suspicious {
			if pat.re.MatchString(cmd) {
				findings = append(findings, Finding{
					Process: p,
					Reason:  "suspicious cmdline pattern",
					Pattern: pat.name,
				})
				break
			}
		}
	}
	return findings
}
