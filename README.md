# Crowsi Credential Agent

`crowsi-local-control-bridge`の認証・認可と
`crowsi-credential-broker`の秘密値保管を、credential enrollmentだけに限定して
同一プロセス・同一Unix stream上で合成するpurpose-specific agentです。

## 境界

- Browser、HTTP、loopback API、Bearer token、Cookieを認可根拠にしない
- `SO_PEERCRED`、実行file digest、PA署名、sender proofを同じUnix streamで検証
- `EnrollCredential`かつ`credential-enrollment`だけをbrokerへ渡す
- V2 envelopeの`service:crowsi` pairwise Subject、端末固有proof key、posture
  revision、4段階revocation epochを検証し、Subject、Device、Workload、
  Reservation、Resource、Action、Body digestを
  `LeaseBinding`と`VerifiedAuthorization`へ再構成する
- 秘密値は認可消費後にだけ最大64 KiBの専用frameで受け、metadata-only receiptを返す
- Socketはowner-only canonical directory下のmode 0600とし、I/Oは30秒以下に制限
- BridgeのSQLite replay/revocation/rate/audit stateとcredential storeは分離する

このcrateは秘密鍵、PA private key、汎用command runner、Web UIを持ちません。
Coela画面から秘密値を受ける場合も、same-originの短命Sessionを通った値を
ローカルnative clientが標準入力で受け取るだけです。BrowserやHTTPは権限を付与せず、
PA認可を同じUnix streamで消費できた場合だけAgentがplatform custodyへ保存します。

本番runtimeはowner-only agent configとcanonical custody configからのみ構成します。
config、PA authorization envelope、metadata draft、秘密ファイルはいずれも絶対path、
所有者UID、mode 0600、非symlink inodeを検証し、親directoryもowner-only 0700とします。

```json
{
  "schema": "crowsi://credential-agent/runtime-config/v4",
  "pa_public_key_hex": "<64 lowercase hex>",
  "allowed_uid": 1000,
  "allowed_gid": 1000,
  "workload_id": "spiffe://crowsi/local/credential-agent",
  "caller_executable_sha256": "sha256:<64 lowercase hex>",
  "socket_path": "/absolute/private/credential-agent.sock",
  "state_path": "/absolute/private/security-state.sqlite3",
  "custody_path": "/absolute/private/platform-custody.json",
  "identity_status": {
    "public_key_hex": "<64 lowercase hex; PA keyとは別鍵>",
    "key_id": "ihat-status-key:credential-agent:1",
    "issuer": "ihat://identity-authority",
    "audience": "crowsi://credential-agent/current-status",
    "service_id": "service:crowsi",
    "path": "/absolute/private/current-device-status.json",
    "pairwise_subject": "pairwise:crowsi:credential-agent",
    "device_id": "device:workstation-a",
    "device_proof_key_ref": "keyref:workstation-a",
    "session_ref": "sref_<64 lowercase hex>"
  },
  "rate_limit_per_minute": 20,
  "request_timeout_ms": 5000
}
```

Agentと一回限りのclientは次のように起動します。

```bash
cargo build --locked --offline
target/debug/crowsi-credential-agent serve \
  --config /absolute/private/runtime.json
target/debug/crowsi-credential-agent credential enroll \
  --config /absolute/private/runtime.json \
  --draft /absolute/private/coela-credential-draft.json \
  --authorization /absolute/private/pa-envelope.json \
  --secret-file /absolute/private/credential.secret
target/debug/crowsi-credential-agent credential enroll-stdin \
  --config /absolute/private/runtime.json \
  --draft /absolute/private/coela-credential-draft.json \
  --authorization /absolute/private/pa-envelope.json
```

`serve-one`は一回のenrollment後に終了します。強制終了でsocket inodeだけが残った場合は、
次回起動が同一UID・0600・接続拒否・inode不変を確認してから回収します。active socket、
symlink、regular file、差替え、公開permissionは削除しません。
`serve`はSIGINTまたはSIGTERMでsocket所有inodeだけを除去して終了します。
PA envelopeがないclientは秘密ファイルを読む前に
拒否され、pin留めされたplatform custody providerが利用できないserverはexit 78で
socketを公開しません。秘密値をargv、env、browser、receipt、logへ渡すfallbackは
ありません。`enroll-stdin`は対話TTYを拒否し、最大64 KiBの値だけをzeroizing
memoryへ読みます。clientは認可Envelope、request、秘密frameを同一Unix streamへ
送ります。

起動ごとにiHATから30秒以下の新しい`CurrentDeviceStatusV1`を取得し、上記owner-only
status pathへatomic配置してからAgentを起動します。AgentはPA鍵とは別のstatus鍵、
issuer/audience/serviceとpairwise Subject・Device・proof keyを完全照合し、SQLiteへ
nonceと4 scopeのcurrent epochを同一transactionで反映してからsocketを公開します。
同じstatusの再利用、未配備、端末Bを端末Aとして使う構成は起動失敗です。

## 利用

配備側は0700のstate/socket directory、専用非root UID、PA public key、許可する
client executable digestとcanonical custody documentを用意します。`PrivateUnixListener`、
`DurableSecurityStore`、`BridgeTrust`、`LocalControlBridge`、
`CredentialAgent`の順に構築します。本番credential storeは診断に成功した
`PlatformCustodyStore`だけで、testでのみ`MemoryStore`を使用します。

Sibling crateへのpath dependencyはWonderland内の検証用です。GitHubへ分離する際は
承認済みprivate Cargo registryの厳密なversion依存へ置換し、lockfileと
artifact digestを検証します。Git tagや固定revisionはrelease依存に使用しません。

```bash
# WONDERLAND_ROOT is the workspace checkout root.
"$WONDERLAND_ROOT/bin/verify-repositories" --rust --tier standard
cargo run --quiet -- sample-readiness
node ${WONDERLAND_ROOT}/tools/check-source-layout.mjs .
```

`sample-readiness`は配備attestationを行わないため、常に`unavailable`かつ
`external_actions=false`です。
