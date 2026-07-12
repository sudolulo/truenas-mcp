package truenas

import "testing"

// Upstream discarded any port supplied with the host and hardcoded 443. TrueNAS
// exposes the UI port as ui_httpsport, and a reverse proxy on the NAS commonly
// claims 443, so a fixed 443 makes the server unusable on such a host.
func TestBuildConnectionURLsHonoursExplicitPort(t *testing.T) {
	cases := []struct {
		endpoint string
		want     string
	}{
		{"192.168.50.1:444", "wss://192.168.50.1:444/websocket"},
		{"192.168.50.1", "wss://192.168.50.1:443/websocket"},
		{"truenas.local:8443", "wss://truenas.local:8443/websocket"},
		{"truenas.local", "wss://truenas.local:443/websocket"},
		{"[fd00::1]:444", "wss://[fd00::1]:444/websocket"},
		{"wss://host:9999/websocket", "wss://host:9999/websocket"}, // full URL passes through
	}
	for _, tc := range cases {
		c := &Client{endpoint: tc.endpoint}
		urls, err := c.buildConnectionURLs()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.endpoint, err)
		}
		if len(urls) != 1 || urls[0] != tc.want {
			t.Errorf("%s -> %v, want %q", tc.endpoint, urls, tc.want)
		}
	}
}

// TrueNAS revokes an API key that is used over plaintext, so ws:// must be a hard
// error rather than something we silently upgrade.
func TestBuildConnectionURLsRejectsPlaintext(t *testing.T) {
	c := &Client{endpoint: "ws://192.168.50.1/websocket"}
	if _, err := c.buildConnectionURLs(); err == nil {
		t.Error("ws:// was accepted; it must be refused")
	}
}
