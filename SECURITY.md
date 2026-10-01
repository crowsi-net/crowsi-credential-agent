# Security policy

このrepositoryはcredential enrollmentのローカルPEPです。

- Web、HTTP、環境変数、command-line引数、runtime configへ秘密値を置かない
- 秘密値は`--secret-file`でowner-only絶対pathだけを渡し、値をshellへ展開しない
- Authorizationとenrollmentを別socket、別connection、別processへ分離しない
- PA private keyやsender private keyをagentへ配置しない
- `MemoryStore`を本番に使わず、pin留めされたplatform custody providerを使用する
- Socket directoryとBridge SQLite directoryは0700、file/socketは0600とする
- Client executable、専用UID/GID、Workload ID、PA public keyを起動時にpin留めする
- PA鍵と別のiHAT status鍵、issuer/audience/service、pairwise Subject・Device・proof keyを
  runtime config v3へpin留めし、owner-onlyの短命statusを起動ごとに一回適用する
- Authorization timeoutを30秒以下にし、reservationを成功・失敗にかかわらず再利用しない
- Receipt、status、log、panic、Debug出力へ秘密値やauthorization envelopeを含めない
- platform custody providerの診断が失敗した状態でsocketやready表示を公開しない
- stale socketは同一UID・0600・接続拒否・inode再照合を満たす場合だけ起動時に回収する

侵害時はagentを停止してsocketを閉じ、影響範囲に応じた
subject/service/device/session revocation epochを進め、影響するcredentialを
provider側で失効し、Bridgeのhash-chain auditとcustody metadataを照合します。
SQLite stateの削除・rollback、socket path差替え、clock異常、peer attestation失敗は
復旧を推測せず運用停止として扱います。

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
