package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/MyoungSoo7/vaccine/internal/blocklist"
	"github.com/MyoungSoo7/vaccine/internal/cache"
	"github.com/MyoungSoo7/vaccine/internal/config"
	"github.com/MyoungSoo7/vaccine/internal/intel"
	"github.com/MyoungSoo7/vaccine/internal/netmon"
	"github.com/MyoungSoo7/vaccine/internal/notify"
	"github.com/MyoungSoo7/vaccine/internal/procmon"
	"github.com/MyoungSoo7/vaccine/internal/scanner"
	"github.com/MyoungSoo7/vaccine/internal/virustotal"
)

const version = "0.2.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "netscan":
		cmdNetscan(os.Args[2:])
	case "procscan":
		cmdProcscan(os.Args[2:])
	case "intel-sync":
		cmdIntelSync(os.Args[2:])
	case "watch":
		cmdWatch(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("vaccine %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`vaccine — lightweight endpoint threat detector for macOS / Linux

Usage:
  vaccine scan       [flags] <path>   Scan a file or directory (VT + blocklist)
  vaccine netscan    [flags]          List active connections, match URLhaus
  vaccine procscan   [flags]          List processes, flag suspicious cmdlines
  vaccine intel-sync [flags]          Refresh threat-intel feeds (URLhaus)
  vaccine watch      [flags] <path>   Run scan + netscan + procscan periodically
  vaccine version                     Show version
  vaccine help                        Show this help

Scan flags:
  -r, --recursive       Recurse into subdirectories (default: true)
      --format=<fmt>    Output: table | json (default: table)
      --only-bad        Print only suspicious/malicious

Watch flags:
      --interval=<min>  Loop interval in minutes (default 60)
      --no-net          Skip netscan
      --no-proc         Skip procscan

Environment:
  VACCINE_VT_API_KEY              VirusTotal API key
  VACCINE_TELEGRAM_BOT_TOKEN      Optional: push findings to Telegram
  VACCINE_TELEGRAM_CHAT_ID        Optional: chat id for Telegram

Config:
  ~/.vaccine/config.json   (optional, env overrides)

Examples:
  vaccine intel-sync
  vaccine scan ~/Downloads --only-bad
  vaccine netscan
  vaccine procscan
  vaccine watch ~/Downloads --interval 30
`)
}

// ── helpers ────────────────────────────────────────────────────────────────

func loadConfigOrExit(needVT bool) *config.Config {
	cfg, err := config.Load()
	if err != nil {
		if err == config.ErrNoVTKey && !needVT {
			return cfg
		}
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}
	return cfg
}

func buildScanner(cfg *config.Config) *scanner.Scanner {
	vt := virustotal.New(cfg.VTAPIKey)
	c := cache.New(cfg.CacheDir, cfg.CacheTTLHours)
	bl := blocklist.New()
	if errs := bl.LoadAll(cfg.BlocklistPaths); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "blocklist load: %v\n", e)
		}
	}
	return scanner.New(vt,
		scanner.WithCache(c),
		scanner.WithBlocklist(bl),
		scanner.WithWhitelist(cfg.WhitelistPaths),
		scanner.WithMaxFileMB(cfg.MaxFileMB),
		scanner.WithRateSeconds(cfg.VTRateSeconds),
	)
}

func newSignalCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// ── scan ───────────────────────────────────────────────────────────────────

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	recursive := fs.Bool("recursive", true, "recurse into subdirectories")
	fs.BoolVar(recursive, "r", true, "recurse into subdirectories (shorthand)")
	format := fs.String("format", "table", "output format: table | json")
	onlyBad := fs.Bool("only-bad", false, "show only suspicious/malicious results")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "scan: target path required")
		os.Exit(1)
	}
	target := fs.Arg(0)

	cfg := loadConfigOrExit(true)
	sc := buildScanner(cfg)

	ctx, cancel := newSignalCtx()
	defer cancel()

	results, err := sc.ScanPath(ctx, target, *recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
	}
	if *onlyBad {
		results = filterBadScan(results)
	}
	if *format == "json" {
		printScanJSON(results)
	} else {
		printScanTable(results)
	}
	if hasBadScan(results) {
		os.Exit(3)
	}
}

func filterBadScan(in []scanner.ScanResult) []scanner.ScanResult {
	out := in[:0]
	for _, r := range in {
		if r.Verdict == "malicious" || r.Verdict == "suspicious" {
			out = append(out, r)
		}
	}
	return out
}

func hasBadScan(in []scanner.ScanResult) bool {
	for _, r := range in {
		if r.Verdict == "malicious" || r.Verdict == "suspicious" {
			return true
		}
	}
	return false
}

func printScanTable(results []scanner.ScanResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERDICT\tMALICIOUS\tSOURCE\tSHA256\tPATH")
	for _, r := range results {
		sha, src, mal := "", "", "-"
		if r.Hashes != nil {
			sha = short(r.Hashes.SHA256)
		}
		switch {
		case r.BlockHit != "":
			src = "blocklist"
		case r.CacheHit:
			src = "cache"
		case r.VT != nil:
			src = "virustotal"
		}
		if r.VT != nil && r.VT.Found {
			mal = fmt.Sprintf("%d", r.VT.Malicious)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Verdict, mal, src, sha, r.Path)
	}
	w.Flush()
}

type scanJSON struct {
	Path       string `json:"path"`
	Verdict    string `json:"verdict"`
	SHA256     string `json:"sha256,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Malicious  int    `json:"malicious,omitempty"`
	Suspicious int    `json:"suspicious,omitempty"`
	Harmless   int    `json:"harmless,omitempty"`
	Undetected int    `json:"undetected,omitempty"`
	Source     string `json:"source"`
	BlockHit   string `json:"block_hit,omitempty"`
	Error      string `json:"error,omitempty"`
}

func printScanJSON(results []scanner.ScanResult) {
	out := make([]scanJSON, 0, len(results))
	for _, r := range results {
		j := scanJSON{Path: r.Path, Verdict: r.Verdict, BlockHit: r.BlockHit}
		switch {
		case r.BlockHit != "":
			j.Source = "blocklist"
		case r.CacheHit:
			j.Source = "cache"
		case r.VT != nil:
			j.Source = "virustotal"
		default:
			j.Source = "n/a"
		}
		if r.Error != nil {
			j.Error = r.Error.Error()
		}
		if r.Hashes != nil {
			j.SHA256 = r.Hashes.SHA256
			j.Size = r.Hashes.Size
		}
		if r.VT != nil {
			j.Malicious = r.VT.Malicious
			j.Suspicious = r.VT.Suspicious
			j.Harmless = r.VT.Harmless
			j.Undetected = r.VT.Undetected
		}
		out = append(out, j)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// ── intel-sync ─────────────────────────────────────────────────────────────

func cmdIntelSync(args []string) {
	fs := flag.NewFlagSet("intel-sync", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	cfg := loadConfigOrExit(false)

	ctx, cancel := newSignalCtx()
	defer cancel()

	feed := intel.NewURLhaus(cfg.URLhausFeedURL)
	fmt.Printf("Downloading URLhaus feed: %s\n", cfg.URLhausFeedURL)
	if err := feed.Refresh(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "urlhaus refresh: %v\n", err)
		os.Exit(2)
	}
	if err := saveFeedSnapshot(cfg.CacheDir, feed); err != nil {
		fmt.Fprintf(os.Stderr, "save snapshot: %v\n", err)
	}
	urls, hosts := feed.Size()
	fmt.Printf("URLhaus loaded: %d URLs, %d unique hosts (at %s)\n",
		urls, hosts, feed.LastLoaded().Format(time.RFC3339))
}

// saveFeedSnapshot persists per-host JSON for offline use by netscan.
// On a fresh box without `intel-sync`, netscan won't crash — it just
// won't have anything to match.
func saveFeedSnapshot(cacheDir string, feed *intel.URLhausFeed) error {
	snapDir := filepath.Join(cacheDir, "intel")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		return err
	}
	urls, hosts := feed.Size()
	meta := map[string]any{
		"urls":      urls,
		"hosts":     hosts,
		"loaded_at": feed.LastLoaded(),
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	return os.WriteFile(filepath.Join(snapDir, "urlhaus.meta.json"), data, 0o600)
}

// ── netscan ────────────────────────────────────────────────────────────────

func cmdNetscan(args []string) {
	fs := flag.NewFlagSet("netscan", flag.ExitOnError)
	format := fs.String("format", "table", "output format: table | json")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	cfg := loadConfigOrExit(false)

	ctx, cancel := newSignalCtx()
	defer cancel()

	conns, err := netmon.List(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netmon: %v\n", err)
		os.Exit(2)
	}

	feed := intel.NewURLhaus(cfg.URLhausFeedURL)
	if err := feed.Refresh(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "urlhaus refresh: %v (matching will be empty)\n", err)
	}
	findings := netmon.MatchAgainst(ctx, conns, feed)

	if *format == "json" {
		out := map[string]any{
			"connections": conns,
			"findings":    findings,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "PID\tPROCESS\tREMOTE\tSTATUS\n")
		for _, c := range conns {
			fmt.Fprintf(w, "%d\t%s\t%s:%d\t%s\n", c.PID, c.ProcessName, c.RemoteAddr, c.RemotePort, c.Status)
		}
		w.Flush()
		if len(findings) > 0 {
			fmt.Println("\n⚠ URLhaus matches:")
			for _, f := range findings {
				fmt.Printf("  %s:%d (pid %d %s) ↔ %s [%s]\n",
					f.Conn.RemoteAddr, f.Conn.RemotePort,
					f.Conn.PID, f.Conn.ProcessName,
					f.Entry.URL, f.Entry.Threat)
			}
		}
	}
	if len(findings) > 0 {
		os.Exit(3)
	}
}

// ── procscan ───────────────────────────────────────────────────────────────

func cmdProcscan(args []string) {
	fs := flag.NewFlagSet("procscan", flag.ExitOnError)
	format := fs.String("format", "table", "output format: table | json")
	onlyBad := fs.Bool("only-bad", false, "show only flagged processes")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	_ = loadConfigOrExit(false) // currently doesn't need VT, but uses cache dir for future

	ctx, cancel := newSignalCtx()
	defer cancel()

	procs, err := procmon.List(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "procmon: %v\n", err)
		os.Exit(2)
	}
	findings := procmon.Scan(procs)

	if *format == "json" {
		out := map[string]any{
			"process_count": len(procs),
			"findings":      findings,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		if !*onlyBad {
			fmt.Printf("Scanned %d processes\n", len(procs))
		}
		if len(findings) == 0 {
			fmt.Println("No suspicious cmdlines detected.")
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PID\tUSER\tPATTERN\tCMDLINE")
			for _, f := range findings {
				cmd := f.Process.Cmdline
				if len(cmd) > 80 {
					cmd = cmd[:77] + "..."
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", f.Process.PID, f.Process.Username, f.Pattern, cmd)
			}
			w.Flush()
		}
	}
	if len(findings) > 0 {
		os.Exit(3)
	}
}

// ── watch ──────────────────────────────────────────────────────────────────

func cmdWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Int("interval", 60, "loop interval in minutes")
	noNet := fs.Bool("no-net", false, "skip netscan")
	noProc := fs.Bool("no-proc", false, "skip procscan")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	target := ""
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	cfg := loadConfigOrExit(target != "")
	tg := notify.NewTelegram(cfg.TelegramBotToken, cfg.TelegramChatID)

	ctx, cancel := newSignalCtx()
	defer cancel()

	feed := intel.NewURLhaus(cfg.URLhausFeedURL)
	var sc *scanner.Scanner
	if target != "" {
		sc = buildScanner(cfg)
	}

	tick := time.NewTicker(time.Duration(*interval) * time.Minute)
	defer tick.Stop()

	fmt.Printf("vaccine watch — every %d min (target=%q, net=%v, proc=%v)\n",
		*interval, target, !*noNet, !*noProc)
	for {
		runWatchCycle(ctx, cfg, sc, feed, tg, target, *noNet, *noProc)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func runWatchCycle(ctx context.Context, cfg *config.Config, sc *scanner.Scanner,
	feed *intel.URLhausFeed, tg *notify.Telegram, target string, noNet, noProc bool) {
	var summary []string

	if !noNet {
		if err := feed.Refresh(ctx); err == nil {
			conns, err := netmon.List(ctx)
			if err == nil {
				findings := netmon.MatchAgainst(ctx, conns, feed)
				if len(findings) > 0 {
					summary = append(summary, fmt.Sprintf("⚠ %d malicious net conn(s)", len(findings)))
					for _, f := range findings {
						summary = append(summary, fmt.Sprintf(" • %s ↔ %s", f.Conn.RemoteAddr, f.Entry.URL))
					}
				}
			}
		}
	}

	if !noProc {
		procs, err := procmon.List(ctx)
		if err == nil {
			findings := procmon.Scan(procs)
			if len(findings) > 0 {
				summary = append(summary, fmt.Sprintf("⚠ %d suspicious process(es)", len(findings)))
				for _, f := range findings {
					summary = append(summary, fmt.Sprintf(" • pid=%d %s [%s]", f.Process.PID, f.Process.Name, f.Pattern))
				}
			}
		}
	}

	if target != "" && sc != nil {
		results, _ := sc.ScanPath(ctx, target, true)
		bad := 0
		for _, r := range results {
			if r.Verdict == "malicious" || r.Verdict == "suspicious" {
				bad++
				summary = append(summary, fmt.Sprintf(" • file %s (%s)", r.Path, r.Verdict))
			}
		}
		if bad > 0 {
			summary = append([]string{fmt.Sprintf("⚠ %d bad file(s) in %s", bad, target)}, summary...)
		}
	}

	if len(summary) == 0 {
		fmt.Printf("[%s] all clean\n", time.Now().Format(time.RFC3339))
		return
	}
	msg := strings.Join(summary, "\n")
	fmt.Printf("[%s] findings:\n%s\n", time.Now().Format(time.RFC3339), msg)
	if tg.Enabled() {
		_ = tg.Send(ctx, "<b>vaccine</b>\n"+msg)
	}
	_ = cfg
}

// ── shared util ────────────────────────────────────────────────────────────

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
