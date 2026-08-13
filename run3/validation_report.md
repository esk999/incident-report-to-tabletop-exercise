# validation_report

## 検証の目的

この検証は、攻撃内容の妥当性や教育的効果を判定するものではありません。
目的は、`network.json`、`pcap_design.json`、`answer_key.json`、`training.pcap` の間に矛盾がないかを確認することです。

## 検証種別

PCAP本検証

## 結果概要

- エラー数: 0
- 警告数: 0
- OK項目数: 3

## 問題なし

- PCAPを読み込めました。パケット数: 1176
- pcap_design.json の検証可能な通信設計はPCAP内で確認できました。
- answer_key.json の検証可能なfindingはPCAP内で確認できました。

## サマリ

- packet_count: `1176`
- duration_seconds: `5881.998`
- unique_ip_count: `11`
### unique_ips

- `192.168.10.1`
- `192.168.10.3`
- `192.168.100.1`
- `192.168.100.2`
- `192.168.20.3`
- `192.168.30.3`
- `192.168.40.1`
- `192.168.50.7`
- `198.51.100.23`
- `198.51.100.24`
- `203.0.113.11`

### top_pairs

- `{'src': '192.168.40.1', 'dst': '192.168.100.2', 'count': 125}`
- `{'src': '192.168.40.1', 'dst': '192.168.100.1', 'count': 90}`
- `{'src': '198.51.100.23', 'dst': '203.0.113.11', 'count': 84}`
- `{'src': '192.168.50.7', 'dst': '192.168.100.2', 'count': 72}`
- `{'src': '192.168.100.2', 'dst': '192.168.40.1', 'count': 71}`
- `{'src': '192.168.30.3', 'dst': '192.168.100.2', 'count': 65}`
- `{'src': '192.168.20.3', 'dst': '192.168.100.2', 'count': 60}`
- `{'src': '203.0.113.11', 'dst': '198.51.100.23', 'count': 56}`
- `{'src': '192.168.10.3', 'dst': '192.168.100.2', 'count': 55}`
- `{'src': '192.168.40.1', 'dst': '192.168.20.3', 'count': 54}`
- `{'src': '192.168.100.1', 'dst': '192.168.40.1', 'count': 50}`
- `{'src': '192.168.40.1', 'dst': '192.168.50.7', 'count': 42}`
- `{'src': '192.168.100.2', 'dst': '192.168.50.7', 'count': 40}`
- `{'src': '192.168.100.2', 'dst': '192.168.30.3', 'count': 37}`
- `{'src': '192.168.100.2', 'dst': '192.168.20.3', 'count': 36}`
- `{'src': '192.168.100.2', 'dst': '192.168.10.3', 'count': 33}`
- `{'src': '192.168.20.3', 'dst': '192.168.100.1', 'count': 32}`
- `{'src': '192.168.20.3', 'dst': '192.168.40.1', 'count': 30}`
- `{'src': '192.168.50.7', 'dst': '192.168.40.1', 'count': 28}`
- `{'src': '198.51.100.24', 'dst': '203.0.113.11', 'count': 18}`

- protocols: `{'TCP': 1166, 'UDP': 10}`
### external_ips_from_external_hosts

- `198.51.100.23`
- `198.51.100.24`

### external_names_from_external_hosts

- `external-baseline-01.example.invalid`
- `external-probe-01.example.invalid`

- traffic_total: `23`
- traffic_success: `23`
- traffic_failed: `0`
- traffic_unverified: `0`
- finding_total: `23`
- finding_success: `23`
- finding_failed: `0`
- finding_unverified: `0`

## 通信設計検証結果

### 成功

- TR-INJ01-001: 84 packets / UTM(VPN)公開側への短時間に複数回のHTTPS/TCP 443接続。認証内容や脆弱性悪用を含まない通信として扱う。
- TR-INJ01-002: 18 packets / UTM(VPN)公開側への低頻度のHTTPS/TCP 443接続。比較用の通常相当トラフィック。
- TR-INJ02-001: 40 packets / IT-PC-01からAD-SRV-01へのKerberos関連通信の増加。
- TR-INJ02-002: 25 packets / IT-PC-01からAD-SRV-01へのLDAP通信。
- TR-INJ02-003: 25 packets / IT-PC-01からAD-SRV-01へのSMB通信。
- TR-INJ02-004: 125 packets / IT-PC-01からFILE-SRV-01へのSMB通信。
- TR-INJ02-005: 30 packets / IT-PC-01からAccounting端末へのSMB通信。
- TR-INJ02-006: 42 packets / IT-PC-01からDevelopment端末へのRDP通信。
- TR-INJ02-007: 24 packets / IT-PC-01からAccounting端末のTCP/135への通信。
- TR-INJ02-008: 12 packets / 一般端末からAD-SRV-01への通常相当のKerberos通信。
- TR-INJ02-009: 15 packets / 一般端末からFILE-SRV-01への通常相当のSMB通信。
- TR-INJ03-001: 55 packets / General Affairs端末からFILE-SRV-01へのSMB通信増加。
- TR-INJ03-002: 60 packets / Accounting端末からFILE-SRV-01へのSMB通信増加。
- TR-INJ03-003: 65 packets / Sales端末からFILE-SRV-01へのSMB通信増加。
- TR-INJ03-004: 72 packets / Development端末からFILE-SRV-01へのSMB通信増加。
- TR-INJ03-005: 125 packets / IT-PC-01からFILE-SRV-01への継続的なSMB通信。
- TR-INJ03-006: 12 packets / General Affairs端末からAD-SRV-01への認証関連通信。
- TR-INJ04-001: 125 packets / IT-PC-01からFILE-SRV-01のTCP/445への接続再試行と一部リセットを含む通信。
- TR-INJ04-002: 32 packets / Accounting端末からAD-SRV-01への短い間隔で繰り返されるKerberos通信。
- TR-INJ04-003: 65 packets / Sales端末からFILE-SRV-01のTCP/445への接続再試行を含む通信。
- TR-INJ04-004: 72 packets / Development端末からFILE-SRV-01のTCP/445への接続再試行を含む通信。
- TR-INJ04-005: 42 packets / IT-PC-01からDEV-PC-07へのRDP通信の継続。
- TR-INJ04-006: 5 packets / Sales端末からAD-SRV-01への通常相当のDNS問い合わせ。

### 失敗


### 未検証


## Finding検証結果

### 成功

- F-001: 84 packets / external-probe-01.example.invalidからUTM-VPN-01へのHTTPS/443通信が観測される。
- F-002: 18 packets / external-baseline-01.example.invalidからUTM-VPN-01へのHTTPS/443通信が観測される。
- F-003: 40 packets / IT-PC-01からAD-SRV-01へのKerberos/88通信が観測される。
- F-004: 25 packets / IT-PC-01からAD-SRV-01へのLDAP/389通信が観測される。
- F-005: 25 packets / IT-PC-01からAD-SRV-01へのSMB/445通信が観測される。
- F-006: 125 packets / IT-PC-01からFILE-SRV-01へのSMB/445通信が観測される。
- F-007: 30 packets / IT-PC-01からACC-PC-03へのSMB/445通信が観測される。
- F-008: 42 packets / IT-PC-01からDEV-PC-07へのRDP/3389通信が観測される。
- F-009: 24 packets / IT-PC-01からACC-PC-03へのTCP/135通信が観測される。
- F-010: 12 packets / GA-PC-01からAD-SRV-01へのKerberos/88通信が観測される。
- F-011: 15 packets / GA-PC-01からFILE-SRV-01へのSMB/445通信が観測される。
- F-012: 55 packets / GA-PC-03からFILE-SRV-01へのSMB/445通信が観測される。
- F-013: 60 packets / ACC-PC-03からFILE-SRV-01へのSMB/445通信が観測される。
- F-014: 65 packets / SALES-PC-03からFILE-SRV-01へのSMB/445通信が観測される。
- F-015: 72 packets / DEV-PC-07からFILE-SRV-01へのSMB/445通信が観測される。
- F-016: 125 packets / IT-PC-01からFILE-SRV-01へのSMB/445通信が観測される。
- F-017: 12 packets / GA-PC-03からAD-SRV-01へのKerberos/88通信が観測される。
- F-018: 125 packets / IT-PC-01からFILE-SRV-01へのTCP/445通信が観測される。
- F-019: 32 packets / ACC-PC-03からAD-SRV-01へのKerberos/88通信が観測される。
- F-020: 65 packets / SALES-PC-03からFILE-SRV-01へのTCP/445通信が観測される。
- F-021: 72 packets / DEV-PC-07からFILE-SRV-01へのTCP/445通信が観測される。
- F-022: 42 packets / IT-PC-01からDEV-PC-07へのRDP/3389通信が観測される。
- F-023: 5 packets / SALES-PC-03からAD-SRV-01へのDNS/53通信が観測される。

### 失敗


### 未検証


## 判定

JSONとPCAPの間に重大な矛盾は確認されませんでした。次Stepへ進めます。