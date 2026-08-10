# Step 2：設計用JSONの生成

あなたは、防御演習用の構造化データ設計を支援するアシスタントです。

前Stepで出力した以下の内容を確定版として扱ってください。

- `design.xlsx`
- `cards.pptx`

`00_common.md` の共通方針に従ってください。

---

## 1. このStepの目的

このStepでは、状況付与に対応するネットワーク定義、PCAP設計、解答整理に使うJSONを作成します。

PCAPそのものはこのStepでは生成しません。

---

## 2. 重要条件

以下を守ってください。

- 演習目的、対象者、対象外、演習方式を変更しない
- 演習全体が2〜4時間程度であり、状況付与ごとに軽い解答確認・軌道修正時間がある前提を維持する
- 状況付与の内容を勝手に変更しない
- ネットワーク構成図に存在しない内部IP、端末、サーバ、セグメントを追加しない
- 実在IP、実在ドメイン、実在ホスト名を使用しない
- 外部通信先は演習用の架空ホストとして定義する
- PCAPだけでは分からない内容を、PCAPで確認できる事実として扱わない
- 1つのfindingに複数通信をまとめない
- `answer_key.json` のfindingは、必ず `pcap_design.json` の `traffic_id` を参照する形式にする
- JSONのキー名は、本プロンプトで指定するスキーマに厳密に従う
- 同じ意味の別キーを作成しない
- IPアドレスを表すキーは、`network.json` と `pcap_design.json` の `external_hosts` では `ip` に統一する
- 通信設計では、送信元IPを `src_ip`、宛先IPを `dst_ip` に統一する
- `ip_address`、`public_ip`、`external_ip`、`allowed_public_or_dmz_ips`、`related_traffic_ids` など、指定していない別名キーを使用しない

---

## 3. 出力ファイル

以下のJSONファイルを出力してください。

1. `network.json`
2. `pcap_design.json`
3. `answer_key.json`

---

# 4. network.json

ネットワーク構成図から読み取れる内部資産を整理してください。

このJSONは、PCAP内に存在してよい内部IPを確認するための基準にします。

## 4.1 キー名ルール

IPアドレスを表すキーは、原則として `ip` を使用してください。

以下のキー名は使用しないでください。

- `ip_address`
- `public_ip`
- `external_ip`
- `allowed_public_or_dmz_ips`

通信設計と後続のPython検証で扱いやすいように、キー名を言い換えないでください。

## 4.2 network.json の基本構造

以下の構造にしてください。

```json
{
  "schema_version": "1.0",
  "purpose": "PCAP内で使用してよい内部資産・IPアドレスを確認するための基準データ。",
  "internal_networks": [],
  "allowed_internal_ips_for_pcap_validation": [],
  "allowed_public_placeholder_ips_for_pcap_validation": [],
  "segments": [],
  "servers": [],
  "client_terminals": [],
  "security_devices": [],
  "unknowns": []
}
```

## 4.3 internal_networks

内部ネットワークのCIDRを文字列配列で整理してください。

例：

```json
"internal_networks": [
  "192.168.10.0/24",
  "192.168.100.0/24"
]
```

## 4.4 allowed_internal_ips_for_pcap_validation

PCAP内で内部IPとして使用してよいIPを文字列配列で整理してください。

含めるもの：

- 内部クライアント端末のIP
- 内部サーバのIP
- 内部ゲートウェイのIP
- UTM/VPNの内部側IP

含めないもの：

- 外部攻撃元IP
- 外部比較用ホストIP
- 構成図に存在しない内部資産IP

例：

```json
"allowed_internal_ips_for_pcap_validation": [
  "192.168.10.1",
  "192.168.10.254",
  "192.168.100.1"
]
```

## 4.5 allowed_public_placeholder_ips_for_pcap_validation

PCAP内で自組織側の公開・DMZ側IPとして使用してよい文書化用IPを文字列配列で整理してください。

含めるもの：

- UTM/VPN公開側IP
- DMZ上の自組織サーバIP

含めないもの：

- 外部攻撃元IP
- 外部比較用ホストIP

外部攻撃元や外部比較用ホストは、`pcap_design.json` の `external_hosts` に定義してください。

例：

```json
"allowed_public_placeholder_ips_for_pcap_validation": [
  "198.51.100.11",
  "198.51.100.12"
]
```

## 4.6 segments

各セグメントは以下の形式にしてください。

```json
{
  "segment_id": "VLAN10",
  "name": "General Affairs",
  "vlan": "VLAN10",
  "network_range": "192.168.10.0/24",
  "gateway": "192.168.10.254",
  "role": "client network",
  "unknowns": []
}
```

## 4.7 servers

各サーバは以下の形式にしてください。

```json
{
  "hostname": "AD-SRV-01",
  "ip": "192.168.100.1",
  "segment": "VLAN100",
  "role": "Active Directory",
  "open_ports": [53, 88, 135, 389, 445],
  "publicly_accessible": false
}
```

## 4.8 client_terminals

各クライアント端末は以下の形式にしてください。

```json
{
  "hostname": "GA-PC-01",
  "ip": "192.168.10.1",
  "segment": "VLAN10",
  "department": "General Affairs",
  "role": "client_terminal"
}
```

## 4.9 security_devices

各セキュリティ機器は以下の形式にしてください。

```json
{
  "device_id": "UTM-VPN-01",
  "hostname": "UTM-VPN-01",
  "ip": "198.51.100.11",
  "segment": "DMZ",
  "role": "Internet edge security device and VPN entry point",
  "internal_gateway_ips": [
    "192.168.10.254",
    "192.168.20.254"
  ]
}
```

---

# 5. pcap_design.json

状況付与ごとに、PCAPで裏付けるべき通信を設計してください。

含める項目は以下です。

- `schema_version`
- `scenario_title`
- `incident_type`
- `capture_point`
- `visible_scope`
- `not_visible_scope`
- `external_hosts`
- `traffic_plan`
- `normal_traffic`
- `suspicious_traffic`
- `comparison_traffic`
- `not_observable_in_pcap`
- `required_followup_information`
- `exercise_assumptions`
- `situation_traffic_coverage`

## 5.1 external_hosts

外部通信先は、必ず `external_hosts` に定義してください。

`external_hosts` の各要素は以下の形式にしてください。

```json
{
  "hostname": "external-probe-01.example.invalid",
  "ip": "198.51.100.23",
  "role": "exercise-only external host",
  "basis": "exercise_assumption"
}
```

条件：

- 外部ホストのIPキーは必ず `ip` とする
- `ip_address`、`public_ip`、`external_ip` は使用しない
- `traffic_plan` に登場する外部IPは、必ず `external_hosts` に定義する
- 実在IP、実在ドメイン、実在ホスト名は使用しない
- ドメイン名が必要な場合は `.example.invalid` を使用する
- 外部IPが必要な場合は、文書化用のアドレス範囲を使用する

## 5.2 traffic_plan

各通信は以下の形式にしてください。

```json
{
  "traffic_id": "TR-INJ01-001",
  "situation_id": "INJ-01",
  "src_ip": "198.51.100.23",
  "src_hostname": "external-probe-01.example.invalid",
  "dst_ip": "198.51.100.11",
  "dst_hostname": "UTM-VPN-01",
  "protocol": "TCP",
  "port": 443,
  "traffic_purpose": "UTM(VPN)公開側への接続試行増加。",
  "normal_or_suspicious": "suspicious",
  "reason_for_inclusion": "状況付与1を通信事実として裏付けるため。",
  "basis": "exercise_assumption"
}
```

条件：

- `traffic_id` は一意にする
- `situation_id` は状況付与IDと対応させる
- `src_ip` と `dst_ip` は必ずIPアドレス文字列にする
- `protocol` は検証可能な表記にする
- `port` は数値にする
- 外部IPを使う場合は、必ず `external_hosts` に同じIPを定義する
- 内部IPを使う場合は、必ず `network.json` の `allowed_internal_ips_for_pcap_validation` に含める
- 自組織側の公開・DMZ側IPを使う場合は、必ず `network.json` の `allowed_public_placeholder_ips_for_pcap_validation` に含める

`protocol` は原則として以下から選んでください。

- `TCP`
- `UDP`
- `ICMP`
- `DNS`
- `HTTP`
- `HTTPS`
- `SMB`
- `LDAP`
- `Kerberos`
- `RDP`
- `SSH`
- `SMTP`
- `IMAP`
- `POP3`
- `NTP`
- `SNMP`
- `Syslog`

`basis` は以下から選んでください。

- `report_fact`
- `inferred_from_report`
- `network_topology`
- `expert_knowledge`
- `exercise_assumption`

---

# 6. answer_key.json

演習担当者の解答整理と、PCAPから確認できる証拠整理のために `answer_key.json` を作成してください。

含める項目は以下です。

- `schema_version`
- `pcap_observable_findings`
- `non_pcap_findings`
- `situation_to_finding_map`
- `learner_misconceptions`
- `followup_questions`

## 6.1 pcap_observable_findings

PCAPから直接確認できる証拠だけを整理してください。

各findingは以下の形式にしてください。

```json
{
  "finding_id": "F-001",
  "related_situation_id": "INJ-01",
  "related_traffic_id": "TR-INJ01-001",
  "description": "external-probe-01.example.invalidからUTM-VPN-01へのTCP/443通信が観測される。",
  "evidence_to_observe": [
    "通信時刻",
    "送信元IPアドレス",
    "宛先IPアドレス",
    "プロトコル",
    "宛先ポート",
    "通信回数または継続時間",
    "通信方向"
  ],
  "basis": "exercise_assumption"
}
```

条件：

- `related_traffic_id` は必ず1つの文字列にする
- `related_traffic_ids` は使用しない
- 1つのfindingに複数通信をまとめない
- `related_traffic_id` は、必ず `pcap_design.json` の `traffic_plan` に存在する `traffic_id` を参照する
- finding内に `src_ip`、`dst_ip`、`protocol`、`port` を重複して書かない
- PCAPから直接確認できる証拠だけを書く
- 認証成功、ファイル閲覧、情報窃取、端末上のコマンド実行、暗号化実行などは `non_pcap_findings` に分ける
- Wiresharkフィルタは含めない

---

## 6.2 non_pcap_findings

PCAPだけでは断定できないが、演習上重要な確認事項を整理してください。

各項目は以下の形式にしてください。

```json
{
  "finding_id": "NF-001",
  "related_situation_id": ["INJ-01"],
  "description": "VPN認証の成否はPCAPだけでは断定できない。",
  "why_not_pcap_observable": "PCAPでは接続の存在やポートは確認できるが、VPN装置の認証判定は装置ログに依存する。",
  "required_information": [
    "UTM/VPN認証ログ",
    "接続元別の成功・失敗ログ"
  ],
  "basis": "expert_knowledge"
}
```

例：

- VPN認証の成否
- AD認証の成否
- 端末上で実行されたプロセス
- ファイル閲覧・コピー・削除の有無
- 情報窃取の有無
- 暗号化実行の有無

---

## 6.3 situation_to_finding_map

状況付与とfindingの対応関係を整理してください。

形式は以下にしてください。

```json
{
  "situation_id": "INJ-01",
  "pcap_finding_ids": ["F-001", "F-002"],
  "non_pcap_finding_ids": ["NF-001"],
  "learning_focus": "外部接続の事実と認証成功の断定を分ける。"
}
```

---

## 6.4 learner_misconceptions

初任者が誤解しやすい点を整理してください。

形式は以下にしてください。

```json
{
  "misconception": "外部IPからVPN装置に通信があったので侵入成功である。",
  "correction": "PCAPで言えるのは通信の有無・回数・時刻まで。認証成功はVPN装置ログで確認する。",
  "related_situation_id": "INJ-01"
}
```

---

## 6.5 followup_questions

追加確認事項につながる問いを整理してください。

形式は以下にしてください。

```json
{
  "question_id": "QF-001",
  "related_situation_id": "INJ-01",
  "question": "VPN装置への外部接続について、認証成功を確認するには何を見るべきか。",
  "expected_information": "VPN認証ログ、接続元IP別の成功・失敗、対象アカウント、時刻、ログ保全状況。",
  "category": "additional_log_review"
}
```

---

# 7. JSON出力全体の制約

以下を必ず守ってください。

- JSONとして構文エラーがない形式で出力する
- コメントをJSON内に含めない
- 末尾カンマを使用しない
- キー名を勝手に言い換えない
- 指定していない別名キーを追加しない
- IPアドレスのキー名は、`network.json` と `external_hosts` では `ip` に統一する
- 通信設計では `src_ip`、`dst_ip` に統一する
- `traffic_id`、`finding_id`、`situation_id` は一貫したID体系にする
- `answer_key.json` の `related_traffic_id` は、必ず `pcap_design.json` の `traffic_id` を参照する
- 後続のPython検証で扱えるよう、同じ意味の情報を複数のキー名で重複定義しない
- 各JSONは、それぞれ独立した妥当なJSONファイルとして保存できる形式にする

---

## 8. 最後に出力する要約

最後に、以下を短くまとめてください。

- このStepで出力したファイル
- 後続Stepに進む前に人間が確認すべき点
- PCAPだけでは断定できない事項
- 次のStepで出力すべきもの
