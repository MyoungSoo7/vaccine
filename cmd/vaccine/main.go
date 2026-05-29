package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"

	"github.com/MyoungSoo7/vaccine/internal/config"
	"github.com/MyoungSoo7/vaccine/internal/scanner"
	"github.com/MyoungSoo7/vaccine/internal/virustotal"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
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
  vaccine scan [flags] <path>     Scan a file or directory
  vaccine version                  Show version
  vaccine help                     Show this help

Scan flags:
  -r, --recursive       Recurse into subdirectories (default: true for directories)
      --format=<fmt>    Output format: table | json (default: table)
      --only-bad        Print only suspicious/malicious results

Environment:
  VACCINE_VT_API_KEY    VirusTotal API key (required)

Examples:
  vaccine scan /path/to/file
  vaccine scan ~/Downloads --format json
  VACCINE_VT_API_KEY=xxx vaccine scan ~/Downloads --only-bad
`)
}

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
		fmt.Fprintln(os.Stderr, "usage: vaccine scan [flags] <path>")
		os.Exit(1)
	}
	target := fs.Arg(0)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}

	vt := virustotal.New(cfg.VTAPIKey)
	sc := scanner.New(vt)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	results, err := sc.ScanPath(ctx, target, *recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
	}

	if *onlyBad {
		results = filterBad(results)
	}

	switch *format {
	case "json":
		printJSON(results)
	default:
		printTable(results)
	}

	if hasBad(results) {
		os.Exit(3)
	}
}

func filterBad(results []scanner.ScanResult) []scanner.ScanResult {
	out := make([]scanner.ScanResult, 0, len(results))
	for _, r := range results {
		if r.Verdict == "malicious" || r.Verdict == "suspicious" {
			out = append(out, r)
		}
	}
	return out
}

func hasBad(results []scanner.ScanResult) bool {
	for _, r := range results {
		if r.Verdict == "malicious" || r.Verdict == "suspicious" {
			return true
		}
	}
	return false
}

func printTable(results []scanner.ScanResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERDICT\tMALICIOUS\tSHA256\tPATH")
	for _, r := range results {
		sha := ""
		mal := "-"
		if r.Hashes != nil {
			sha = shortHash(r.Hashes.SHA256)
		}
		if r.VT != nil && r.VT.Found {
			mal = fmt.Sprintf("%d", r.VT.Malicious)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Verdict, mal, sha, r.Path)
	}
	w.Flush()
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

type jsonResult struct {
	Path     string `json:"path"`
	Verdict  string `json:"verdict"`
	SHA256   string `json:"sha256,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Malicious  int   `json:"malicious,omitempty"`
	Suspicious int   `json:"suspicious,omitempty"`
	Harmless   int   `json:"harmless,omitempty"`
	Undetected int   `json:"undetected,omitempty"`
	Found    bool   `json:"vt_found"`
	Error    string `json:"error,omitempty"`
}

func printJSON(results []scanner.ScanResult) {
	out := make([]jsonResult, 0, len(results))
	for _, r := range results {
		j := jsonResult{Path: r.Path, Verdict: r.Verdict}
		if r.Error != nil {
			j.Error = r.Error.Error()
		}
		if r.Hashes != nil {
			j.SHA256 = r.Hashes.SHA256
			j.Size = r.Hashes.Size
		}
		if r.VT != nil {
			j.Found = r.VT.Found
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
