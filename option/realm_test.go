package option

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// TestTUICOutboundRealmParse proves the realm config surface added to the five
// non-Hy2 outbounds round-trips through JSON: a tuic outbound with a realm block
// unmarshals into RealmOptions with the expected fields. This is the config-level
// regression guard for OTun's realm wiring (route A).
func TestTUICOutboundRealmParse(t *testing.T) {
	t.Parallel()
	var options TUICOutboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"uuid": "00000000-0000-0000-0000-000000000000",
		"password": "pw",
		"tls": {"enabled": true},
		"realm": {
			"server_url": "https://rv.example.com/realm",
			"token": "tok",
			"realm_id": "egress-fra",
			"stun_servers": ["1.2.3.4:3478"]
		}
	}`), &options)
	require.NoError(t, err)
	require.NotNil(t, options.Realm)
	require.Equal(t, "https://rv.example.com/realm", options.Realm.ServerURL)
	require.Equal(t, "tok", options.Realm.Token)
	require.Equal(t, "egress-fra", options.Realm.RealmID)
	require.Equal(t, []string{"1.2.3.4:3478"}, []string(options.Realm.STUNServers))
}

// TestTUICOutboundNoRealm proves the non-realm path is untouched: omitting realm
// leaves options.Realm nil (the outbound then behaves exactly as upstream).
func TestTUICOutboundNoRealm(t *testing.T) {
	t.Parallel()
	var options TUICOutboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"server": "1.2.3.4",
		"server_port": 443,
		"uuid": "00000000-0000-0000-0000-000000000000",
		"tls": {"enabled": true}
	}`), &options)
	require.NoError(t, err)
	require.Nil(t, options.Realm)
}

// realmBlock is the shared realm config snippet embedded in each protocol test.
const realmBlock = `"realm": {
	"server_url": "https://rv.example.com/realm",
	"token": "tok",
	"realm_id": "egress-fra",
	"stun_servers": ["1.2.3.4:3478"]
}`

func requireRealm(t *testing.T, realm *RealmOptions) {
	t.Helper()
	require.NotNil(t, realm)
	require.Equal(t, "https://rv.example.com/realm", realm.ServerURL)
	require.Equal(t, "egress-fra", realm.RealmID)
	require.Equal(t, []string{"1.2.3.4:3478"}, []string(realm.STUNServers))
}

// TestTrojanOutboundRealmParse proves Trojan's realm config surface parses.
func TestTrojanOutboundRealmParse(t *testing.T) {
	t.Parallel()
	var options TrojanOutboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"password": "pw",
		"tls": {"enabled": true},
		`+realmBlock+`
	}`), &options)
	require.NoError(t, err)
	requireRealm(t, options.Realm)
}

// TestShadowsocksOutboundRealmParse proves SS's realm config surface parses,
// including the tls block added for the outer WrapStream.
func TestShadowsocksOutboundRealmParse(t *testing.T) {
	t.Parallel()
	var options ShadowsocksOutboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"method": "aes-128-gcm",
		"password": "pw",
		"tls": {"enabled": true},
		`+realmBlock+`
	}`), &options)
	require.NoError(t, err)
	requireRealm(t, options.Realm)
}

// TestVMessOutboundRealmParse proves VMess's realm config surface parses.
func TestVMessOutboundRealmParse(t *testing.T) {
	t.Parallel()
	var options VMessOutboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"uuid": "00000000-0000-0000-0000-000000000000",
		"security": "auto",
		"tls": {"enabled": true},
		`+realmBlock+`
	}`), &options)
	require.NoError(t, err)
	requireRealm(t, options.Realm)
}

// TestVLESSRealityRealmParse proves the two-TLS Reality surface parses: the
// inner Reality lives in tls.reality, the outer WrapStream TLS in realm.wrap_tls.
func TestVLESSRealityRealmParse(t *testing.T) {
	t.Parallel()
	var options VLESSOutboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"uuid": "00000000-0000-0000-0000-000000000000",
		"flow": "xtls-rprx-vision",
		"tls": {
			"enabled": true,
			"server_name": "www.example-handshake.com",
			"reality": {"enabled": true, "public_key": "pk", "short_id": "ab"}
		},
		"realm": {
			"server_url": "https://rv.example.com/realm",
			"token": "tok",
			"realm_id": "egress-fra",
			"stun_servers": ["1.2.3.4:3478"],
			"wrap_tls": {"enabled": true, "alpn": ["h3"]}
		}
	}`), &options)
	require.NoError(t, err)
	requireRealm(t, options.Realm)
	require.NotNil(t, options.Realm.WrapTLS)
	require.True(t, options.Realm.WrapTLS.Enabled)
	require.NotNil(t, options.TLS.Reality)
	require.True(t, options.TLS.Reality.Enabled)
}
