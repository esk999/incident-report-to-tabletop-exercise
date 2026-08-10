# Step 3：演習用PCAPの生成

あなたは、防御演習用PCAP生成を支援するアシスタントです。

前Stepまでの出力を確定版として扱ってください。

- `design.xlsx`
- `cards.pptx`
- `network.json`
- `pcap_design.json`
- `answer_key.json`

`00_common.md` の共通方針に従ってください。

---

## 1. このStepの目的

このStepでは、状況付与とPCAP設計に対応する `training.pcap` を生成します。

あわせて、人間確認用の `pcap_summary.md` を出力してください。

`pcap_summary.md` は人間がPCAP生成結果を確認するための補助資料です。  
後続Stepの主要な根拠としては使用しません。

---

## 2. 出力ファイル

以下を出力してください。

1. `training.pcap`
2. `pcap_summary.md`

---

## 3. 重要条件

以下を守ってください。

- `pcap_design.json` に記載された `traffic_plan` の通信を反映する
- `answer_key.json` の `pcap_observable_findings` に対応する証拠通信を含める
- 状況付与で提示する内容を通信レベルで裏付けられるようにする
- 正常通信、不審通信、比較用通信を含める
- 不審通信が簡単に目立ちすぎないように、比較用の正常通信も含める
- 初任者が2〜4時間の演習内で扱える規模にする
- 実在IP、実在ドメイン、実在ホスト名を使用しない
- マルウェア本体、exploit payload、認証情報、実攻撃可能な通信内容を含めない
- CVEの悪用リクエストや侵入手順を再現しない
- 防御側が観測できる兆候のみを含める
- PCAPだけでは断定できない内容を、PCAP上の事実として表現しない

---

## 4. JSONスキーマに関する前提

Step2で生成されたJSONは、以下のキー名を前提とします。

- `network.json` のIPキーは `ip`
- `pcap_design.json` の外部ホストIPキーは `external_hosts[].ip`
- `pcap_design.json` の通信設計は `traffic_plan[].src_ip` と `traffic_plan[].dst_ip`
- `answer_key.json` のfindingは `pcap_observable_findings[].related_traffic_id` で `traffic_plan[].traffic_id` を参照する

同じ意味の別キーを新たに作成しないでください。

---

## 5. pcap_summary.md に含める内容

`pcap_summary.md` には以下を含めてください。

- パケット数
- 通信時間
- 主な内部IP
- 主な外部IP
- 主なプロトコル
- 状況付与ごとに含めた証拠通信
- 正常通信として含めた通信
- 不審通信として含めた通信
- 比較用通信として含めた通信
- PCAPで確認できること
- PCAPだけでは断定できないこと
- 状況付与ごとの軽い解答確認で確認できる通信上の観点
- 演習時間内に扱えるPCAP量かどうか
- 人間が確認すべき点

---

## 6. 最後に出力する要約

最後に、以下を短くまとめてください。

- 生成したPCAPの概要
- どの状況付与をPCAPで裏付けたか
- PCAPだけでは断定できない内容
- 演習時間内に扱えるPCAP量かどうか
- 次に確認すべき点
