// Package netmon enumerates active TCP/UDP connections and matches them
// against threat-intel feeds (currently URLhaus).
//
// Cross-platform via gopsutil. No root needed for own-process connections
// on macOS / Linux; system-wide may require elevated privileges on macOS.
package netmon

import (
	"context"
	"fmt"
	"net"

	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/MyoungSoo7/vaccine/internal/intel"
)

type Connection struct {
	PID         int32
	ProcessName string
	LocalAddr   string
	LocalPort   uint32
	RemoteAddr  string
	RemotePort  uint32
	Status      string
}

type Finding struct {
	Conn  Connection
	Entry intel.URLhausEntry
}

// List returns active, established outbound connections.
func List(ctx context.Context) ([]Connection, error) {
	conns, err := psnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, fmt.Errorf("psnet connections: %w", err)
	}

	out := make([]Connection, 0, len(conns))
	for _, c := range conns {
		// We only care about ESTABLISHED outbound connections with a real remote IP.
		if c.Status != "ESTABLISHED" {
			continue
		}
		if c.Raddr.IP == "" || c.Raddr.IP == "0.0.0.0" || c.Raddr.IP == "::" {
			continue
		}
		if isLoopback(c.Raddr.IP) {
			continue
		}
		name := ""
		if c.Pid > 0 {
			if p, err := process.NewProcessWithContext(ctx, c.Pid); err == nil {
				if n, err := p.NameWithContext(ctx); err == nil {
					name = n
				}
			}
		}
		out = append(out, Connection{
			PID:         c.Pid,
			ProcessName: name,
			LocalAddr:   c.Laddr.IP,
			LocalPort:   c.Laddr.Port,
			RemoteAddr:  c.Raddr.IP,
			RemotePort:  c.Raddr.Port,
			Status:      c.Status,
		})
	}
	return out, nil
}

// MatchAgainst returns findings where the remote IP's reverse-resolved hostname
// (best-effort) appears in URLhaus.  Since URLhaus is URL/host-indexed and we
// only have IPs here, we also accept the bare IP as a host key — many URLhaus
// entries use IP literals.
func MatchAgainst(ctx context.Context, conns []Connection, feed *intel.URLhausFeed) []Finding {
	var findings []Finding
	for _, c := range conns {
		// 1) bare IP host
		if entries, ok := feed.MatchHost(c.RemoteAddr); ok && len(entries) > 0 {
			findings = append(findings, Finding{Conn: c, Entry: entries[0]})
			continue
		}
		// 2) reverse DNS (best-effort, may be slow)
		names, err := net.DefaultResolver.LookupAddr(ctx, c.RemoteAddr)
		if err != nil {
			continue
		}
		for _, n := range names {
			n = trimTrailingDot(n)
			if entries, ok := feed.MatchHost(n); ok && len(entries) > 0 {
				findings = append(findings, Finding{Conn: c, Entry: entries[0]})
				break
			}
		}
	}
	return findings
}

func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

func trimTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
