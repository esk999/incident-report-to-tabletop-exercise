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

- PCAPを読み込めました。パケット数: 1654
- pcap_design.json の検証可能な通信設計はPCAP内で確認できました。
- answer_key.json の検証可能なfindingはPCAP内で確認できました。

## サマリ

- packet_count: `1654`
- duration_seconds: `7155.171`
- unique_ip_count: `18`
### unique_ips

- `192.0.2.11`
- `192.0.2.12`
- `192.168.10.1`
- `192.168.10.2`
- `192.168.10.254`
- `192.168.100.1`
- `192.168.100.2`
- `192.168.100.254`
- `192.168.20.1`
- `192.168.20.254`
- `192.168.30.1`
- `192.168.40.1`
- `192.168.50.1`
- `192.168.50.254`
- `192.168.50.3`
- `198.51.100.23`
- `203.0.113.50`
- `203.0.113.77`

### top_pairs

- `{'src': '192.168.50.3', 'dst': '192.168.100.2', 'count': 190}`
- `{'src': '192.168.100.2', 'dst': '192.168.50.3', 'count': 152}`
- `{'src': '198.51.100.23', 'dst': '192.0.2.11', 'count': 120}`
- `{'src': '192.0.2.11', 'dst': '198.51.100.23', 'count': 96}`
- `{'src': '192.168.50.1', 'dst': '192.168.100.2', 'count': 80}`
- `{'src': '192.168.100.254', 'dst': '192.168.100.1', 'count': 72}`
- `{'src': '192.168.10.1', 'dst': '192.168.100.2', 'count': 70}`
- `{'src': '192.168.30.1', 'dst': '192.0.2.12', 'count': 65}`
- `{'src': '192.168.100.2', 'dst': '192.168.50.1', 'count': 64}`
- `{'src': '192.168.100.1', 'dst': '192.168.100.254', 'count': 57}`
- `{'src': '192.168.100.2', 'dst': '192.168.10.1', 'count': 56}`
- `{'src': '192.0.2.12', 'dst': '192.168.30.1', 'count': 52}`
- `{'src': '192.168.50.3', 'dst': '192.168.10.1', 'count': 48}`
- `{'src': '192.168.50.3', 'dst': '203.0.113.77', 'count': 45}`
- `{'src': '192.168.10.2', 'dst': '192.168.100.2', 'count': 40}`
- `{'src': '192.168.100.254', 'dst': '192.168.100.2', 'count': 40}`
- `{'src': '192.168.10.1', 'dst': '192.168.50.3', 'count': 36}`
- `{'src': '203.0.113.77', 'dst': '192.168.50.3', 'count': 36}`
- `{'src': '192.168.100.2', 'dst': '192.168.10.2', 'count': 32}`
- `{'src': '192.168.100.2', 'dst': '192.168.100.254', 'count': 32}`

- protocols: `{'UDP': 124, 'TCP': 1530}`
### external_ips_from_external_hosts

- `198.51.100.23`
- `203.0.113.50`
- `203.0.113.77`

### external_names_from_external_hosts

- `external-maintenance-01.example.invalid`
- `external-observer-01.example.invalid`
- `external-probe-01.example.invalid`

- traffic_total: `18`
- traffic_success: `18`
- traffic_failed: `0`
- traffic_unverified: `0`
- finding_total: `18`
- finding_success: `18`
- finding_failed: `0`
- finding_unverified: `0`

## 通信設計検証結果

### 成功

- TR-INJ01-001: 120 packets / UTM(VPN)公開側へのTCP/443接続が短時間に複数回観測される通信。
- TR-CMP01-001: 25 packets / 比較用として、別の外部ホストからUTM(VPN)公開側へ低頻度で行われるTCP/443通信。
- TR-INJ02-001: 12 packets / UTM(VPN)内側からAD-SRV-01へのDNS通信。
- TR-INJ02-002: 32 packets / UTM(VPN)内側からAD-SRV-01へのKerberos関連通信。
- TR-INJ02-003: 28 packets / UTM(VPN)内側からAD-SRV-01へのLDAP通信。
- TR-INJ02-004: 40 packets / UTM(VPN)内側からFILE-SRV-01へのSMB通信。
- TR-INJ02-005: 24 packets / UTM(VPN)内側からGeneral Affairs端末へのTCP/445接続。
- TR-INJ02-006: 24 packets / UTM(VPN)内側からAccounting端末へのTCP/445接続。
- TR-INJ02-007: 24 packets / UTM(VPN)内側からDevelopment端末へのTCP/445接続。
- TR-CMP02-001: 30 packets / 比較用の通常DNS通信。
- TR-INJ03-001: 190 packets / DEV-PC-03からFILE-SRV-01へのSMB通信が短時間に集中して観測される通信。
- TR-CMP03-001: 40 packets / 比較用として低頻度で継続する通常のSMB通信。
- TR-INJ04-001: 70 packets / General Affairsからの利用不可申告前後に観測されるFILE-SRV-01へのSMB通信。
- TR-INJ04-002: 80 packets / Developmentからの利用不可申告前後に観測されるFILE-SRV-01へのSMB通信。
- TR-INJ04-003: 48 packets / 関連端末候補から別部署端末へのTCP/445接続。
- TR-CMP04-001: 20 packets / 比較用の通常DNS通信。
- TR-INJ05-001: 45 packets / 内部端末候補から演習用外部ホストへのHTTPS通信。
- TR-CMP05-001: 65 packets / 比較用として自組織DMZのWebサービスへ行われる通常HTTPS通信。

### 失敗


### 未検証


## Finding検証結果

### 成功

- F-001: 120 packets / external-probe-01.example.invalidからUTM-VPN-01へのTCP/443通信が短時間に複数回観測される。
- F-002: 25 packets / external-maintenance-01.example.invalidからUTM-VPN-01へのTCP/443通信が比較的低頻度で観測される。
- F-003: 12 packets / UTM-VPN-01のVLAN100側ゲートウェイからAD-SRV-01へのDNS通信が観測される。
- F-004: 32 packets / UTM-VPN-01のVLAN100側ゲートウェイからAD-SRV-01へのKerberos関連通信が観測される。
- F-005: 28 packets / UTM-VPN-01のVLAN100側ゲートウェイからAD-SRV-01へのLDAP通信が観測される。
- F-006: 40 packets / UTM-VPN-01のVLAN100側ゲートウェイからFILE-SRV-01へのSMB通信が観測される。
- F-007: 24 packets / UTM-VPN-01のVLAN10側ゲートウェイからGA-PC-01へのTCP/445通信が観測される。
- F-008: 24 packets / UTM-VPN-01のVLAN20側ゲートウェイからACC-PC-01へのTCP/445通信が観測される。
- F-009: 24 packets / UTM-VPN-01のVLAN50側ゲートウェイからDEV-PC-01へのTCP/445通信が観測される。
- F-010: 30 packets / GA-PC-01からAD-SRV-01への比較用のDNS通信が観測される。
- F-011: 190 packets / DEV-PC-03からFILE-SRV-01へのSMB通信が短時間に集中して観測される。
- F-012: 40 packets / GA-PC-02からFILE-SRV-01への比較用の低頻度SMB通信が観測される。
- F-013: 70 packets / GA-PC-01からFILE-SRV-01へのSMB通信が利用不可申告前後に観測される。
- F-014: 80 packets / DEV-PC-01からFILE-SRV-01へのSMB通信が利用不可申告前後に観測される。
- F-015: 48 packets / DEV-PC-03からGA-PC-01へのTCP/445通信が観測される。
- F-016: 20 packets / IT-PC-01からAD-SRV-01への比較用のDNS通信が観測される。
- F-017: 45 packets / DEV-PC-03からexternal-observer-01.example.invalidへのHTTPS通信が観測される。
- F-018: 65 packets / SALES-PC-01から自組織DMZのWEB-SRV-01への比較用HTTPS通信が観測される。

### 失敗


### 未検証


## 判定

JSONとPCAPの間に重大な矛盾は確認されませんでした。次Stepへ進めます。