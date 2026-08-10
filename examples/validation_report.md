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

- PCAPを読み込めました。パケット数: 1582
- pcap_design.json の検証可能な通信設計はPCAP内で確認できました。
- answer_key.json の検証可能なfindingはPCAP内で確認できました。

## サマリ

- packet_count: `1582`
- duration_seconds: `5934.182`
- unique_ip_count: `18`
### unique_ips

- `192.168.10.1`
- `192.168.10.2`
- `192.168.100.1`
- `192.168.100.2`
- `192.168.100.254`
- `192.168.20.1`
- `192.168.20.2`
- `192.168.30.2`
- `192.168.40.2`
- `192.168.40.3`
- `192.168.50.1`
- `192.168.50.3`
- `192.168.50.4`
- `198.51.100.11`
- `203.0.113.20`
- `203.0.113.45`
- `203.0.113.46`
- `203.0.113.77`

### top_pairs

- `{'src': '192.168.50.3', 'dst': '192.168.100.2', 'count': 116}`
- `{'src': '192.168.40.2', 'dst': '192.168.100.2', 'count': 116}`
- `{'src': '192.168.100.2', 'dst': '192.168.50.3', 'count': 87}`
- `{'src': '192.168.100.2', 'dst': '192.168.40.2', 'count': 87}`
- `{'src': '192.168.10.1', 'dst': '192.168.100.2', 'count': 84}`
- `{'src': '192.168.50.3', 'dst': '192.168.100.1', 'count': 74}`
- `{'src': '192.168.100.2', 'dst': '192.168.10.1', 'count': 63}`
- `{'src': '192.168.100.1', 'dst': '192.168.50.3', 'count': 57}`
- `{'src': '203.0.113.45', 'dst': '198.51.100.11', 'count': 50}`
- `{'src': '203.0.113.46', 'dst': '198.51.100.11', 'count': 50}`
- `{'src': '192.168.20.1', 'dst': '192.168.100.2', 'count': 44}`
- `{'src': '192.168.50.1', 'dst': '192.168.100.2', 'count': 44}`
- `{'src': '203.0.113.20', 'dst': '198.51.100.11', 'count': 40}`
- `{'src': '198.51.100.11', 'dst': '203.0.113.45', 'count': 40}`
- `{'src': '198.51.100.11', 'dst': '203.0.113.46', 'count': 40}`
- `{'src': '192.168.100.254', 'dst': '192.168.100.1', 'count': 35}`
- `{'src': '192.168.50.3', 'dst': '203.0.113.77', 'count': 35}`
- `{'src': '192.168.40.2', 'dst': '203.0.113.77', 'count': 35}`
- `{'src': '192.168.100.2', 'dst': '192.168.20.1', 'count': 33}`
- `{'src': '192.168.100.2', 'dst': '192.168.50.1', 'count': 33}`

- protocols: `{'TCP': 1498, 'UDP': 84}`
### external_ips_from_external_hosts

- `203.0.113.20`
- `203.0.113.45`
- `203.0.113.46`
- `203.0.113.77`

### external_names_from_external_hosts

- `external-comparison-01.example.invalid`
- `external-egress-01.example.invalid`
- `external-probe-01.example.invalid`
- `external-probe-02.example.invalid`

- traffic_total: `31`
- traffic_success: `31`
- traffic_failed: `0`
- traffic_unverified: `0`
- finding_total: `31`
- finding_success: `31`
- finding_failed: `0`
- finding_unverified: `0`

## 通信設計検証結果

### 成功

- TR-INJ01-001: 50 packets / UTM(VPN)公開側への短時間の反復接続。
- TR-INJ01-002: 50 packets / UTM(VPN)公開側への短時間の反復接続。
- TR-INJ01-003: 40 packets / 比較用の低頻度なUTM(VPN)公開側接続。
- TR-INJ01-004: 5 packets / 外部接続増加の後に観測されるVLAN100内の名前解決関連通信。
- TR-INJ01-005: 6 packets / 外部接続増加の後に観測される認証関連ポートへの通信。
- TR-INJ01-006: 24 packets / 外部接続増加の後に観測されるディレクトリサービス関連通信。
- TR-INJ01-007: 24 packets / 外部接続増加の後に観測されるファイル共有関連通信。
- TR-INJ02-001: 14 packets / IT-PC-02からAD-SRV-01への名前解決関連通信の増加。
- TR-INJ02-002: 8 packets / IT-PC-02からAD-SRV-01への認証関連通信の増加。
- TR-INJ02-003: 32 packets / DEV-PC-03からAD-SRV-01へのディレクトリサービス関連通信の増加。
- TR-INJ02-004: 36 packets / DEV-PC-03からAD-SRV-01へのSMB通信の増加。
- TR-INJ02-005: 116 packets / IT-PC-02からFILE-SRV-01へのSMB通信の増加。
- TR-INJ02-006: 116 packets / DEV-PC-03からFILE-SRV-01へのSMB通信の増加。
- TR-INJ02-007: 10 packets / 比較用の通常範囲のAD-SRV-01向け名前解決通信。
- TR-INJ02-008: 84 packets / 比較用の通常範囲のFILE-SRV-01向けファイル共有通信。
- TR-INJ03-001: 24 packets / IT支援セグメントから総務端末へのSMB接続増加。
- TR-INJ03-002: 24 packets / IT支援セグメントから経理端末へのRDP接続候補。
- TR-INJ03-003: 24 packets / 開発セグメントから営業端末へのSMB接続増加。
- TR-INJ03-004: 24 packets / 開発セグメントからIT支援端末へのRDP接続候補。
- TR-INJ03-005: 24 packets / DEV-PC-03から同一開発セグメント端末への管理系ポート通信。
- TR-INJ04-001: 116 packets / 外部宛て通信に近接して増えるFILE-SRV-01向けSMB通信。
- TR-INJ04-002: 116 packets / 外部宛て通信に近接して増えるDEV-PC-03からのSMB通信。
- TR-INJ04-003: 35 packets / IT-PC-02から演習用外部ホストへのHTTPS通信。
- TR-INJ04-004: 35 packets / DEV-PC-03から演習用外部ホストへのHTTPS通信。
- TR-INJ04-005: 14 packets / 外部宛てHTTPS通信の直前に観測される名前解決通信。
- TR-INJ04-006: 6 packets / DEV-PC-03の外部宛てHTTPS通信の直前に観測される名前解決通信。
- TR-INJ05-001: 84 packets / 業務影響申告の前後に増える総務端末からFILE-SRV-01へのSMB通信。
- TR-INJ05-002: 44 packets / 業務影響申告の前後に増える経理端末からFILE-SRV-01へのSMB通信。
- TR-INJ05-003: 44 packets / 業務影響申告の前後に増える開発端末からFILE-SRV-01へのSMB通信。
- TR-INJ05-004: 116 packets / 業務影響申告の時点まで継続するIT-PC-02からFILE-SRV-01へのSMB通信。
- TR-INJ05-005: 116 packets / 業務影響申告の時点まで継続するDEV-PC-03からFILE-SRV-01へのSMB通信。

### 失敗


### 未検証


## Finding検証結果

### 成功

- F-001: 50 packets / external-probe-01.example.invalidからUTM-VPN-01へのHTTPS/443通信が観測される。
- F-002: 50 packets / external-probe-02.example.invalidからUTM-VPN-01へのHTTPS/443通信が観測される。
- F-003: 40 packets / external-comparison-01.example.invalidからUTM-VPN-01へのHTTPS/443通信が観測される。
- F-004: 5 packets / UTM-VPN-01からAD-SRV-01へのDNS/53通信が観測される。
- F-005: 6 packets / UTM-VPN-01からAD-SRV-01へのKerberos/88通信が観測される。
- F-006: 24 packets / UTM-VPN-01からAD-SRV-01へのLDAP/389通信が観測される。
- F-007: 24 packets / UTM-VPN-01からFILE-SRV-01へのSMB/445通信が観測される。
- F-008: 14 packets / IT-PC-02からAD-SRV-01へのDNS/53通信が観測される。
- F-009: 8 packets / IT-PC-02からAD-SRV-01へのKerberos/88通信が観測される。
- F-010: 32 packets / DEV-PC-03からAD-SRV-01へのLDAP/389通信が観測される。
- F-011: 36 packets / DEV-PC-03からAD-SRV-01へのSMB/445通信が観測される。
- F-012: 116 packets / IT-PC-02からFILE-SRV-01へのSMB/445通信が観測される。
- F-013: 116 packets / DEV-PC-03からFILE-SRV-01へのSMB/445通信が観測される。
- F-014: 10 packets / GA-PC-01からAD-SRV-01へのDNS/53通信が観測される。
- F-015: 84 packets / GA-PC-01からFILE-SRV-01へのSMB/445通信が観測される。
- F-016: 24 packets / IT-PC-02からGA-PC-02へのSMB/445通信が観測される。
- F-017: 24 packets / IT-PC-02からACC-PC-02へのRDP/3389通信が観測される。
- F-018: 24 packets / DEV-PC-03からSALES-PC-02へのSMB/445通信が観測される。
- F-019: 24 packets / DEV-PC-03からIT-PC-03へのRDP/3389通信が観測される。
- F-020: 24 packets / DEV-PC-03からDEV-PC-04へのTCP/5985通信が観測される。
- F-021: 116 packets / IT-PC-02からFILE-SRV-01へのSMB/445通信が観測される。
- F-022: 116 packets / DEV-PC-03からFILE-SRV-01へのSMB/445通信が観測される。
- F-023: 35 packets / IT-PC-02からexternal-egress-01.example.invalidへのHTTPS/443通信が観測される。
- F-024: 35 packets / DEV-PC-03からexternal-egress-01.example.invalidへのHTTPS/443通信が観測される。
- F-025: 14 packets / IT-PC-02からAD-SRV-01へのDNS/53通信が観測される。
- F-026: 6 packets / DEV-PC-03からAD-SRV-01へのDNS/53通信が観測される。
- F-027: 84 packets / GA-PC-01からFILE-SRV-01へのSMB/445通信が観測される。
- F-028: 44 packets / ACC-PC-01からFILE-SRV-01へのSMB/445通信が観測される。
- F-029: 44 packets / DEV-PC-01からFILE-SRV-01へのSMB/445通信が観測される。
- F-030: 116 packets / IT-PC-02からFILE-SRV-01へのSMB/445通信が観測される。
- F-031: 116 packets / DEV-PC-03からFILE-SRV-01へのSMB/445通信が観測される。

### 失敗


### 未検証


## 判定

JSONとPCAPの間に重大な矛盾は確認されませんでした。次Stepへ進めます。