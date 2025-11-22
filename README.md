Chainsaw https://github.com/WithSecureLabs/chainsaw を使用した windows server イベントログ脅威検出ツール。
以下では **Dockerfile**、**docker-compose.yml**、および **スクリプト（Python）** をご用意します。

*   `evtx/` 配下にホスト名ごとのサブディレクトリがあり、その中に `.evtx` が置かれている前提です。
*   レポートは `reports/` にホストごとに保存します。
*   脅威（検出結果）があった場合のみメール通知します。
*   送信先や Chainsaw の引数（モード、ルールレベル、フォーマット等）は **docker compose の環境変数**で変更でき、**再ビルド不要**です。
*   スクリプト側でホスト単位の並列実行（疑似 `THREADS`）を実装しており、**Chainsaw 本体の CLI にスレッド指定はない**ため、**コンテナ内の並列度**を環境変数で制御します（Python の `ThreadPoolExecutor` を利用）。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw)

> 🧩 **Chainsaw のコマンドと出力オプション**  
> Chainsaw の `hunt` には、`--csv / --json / --log` の出力指定、`-o/--output` の出力先、`--level`（severityフィルタ）、`-s/--sigma` と `-m/--mapping`（Sigmaと対応付け）等の主要オプションがあります。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw), [\[github.com\]](https://github.com/WithSecureLabs/chainsaw/wiki/Usage)

***

## ディレクトリ構成（例）

    your-working-folder/
    ├─ Dockerfile
    ├─ docker-compose.yml
    ├─ scripts/
    │  └─ scan_and_report.py
    ├─ evtx/
    │  ├─ HOST-A/
    │  │  ├─ Security.evtx
    │  │  └─ ...
    │  └─ HOST-B/
    │     ├─ System.evtx
    │     └─ ...
    ├─ reports/        # 実行時に自動作成
    ├─ sigma/          # Sigmaルールをクローンする場合（例）
    └─ mappings/
       └─ sigma-event-logs-all.yml  # Chainsawのマッピングファイル（例）

> 参考：Sigma ルールと `mappings/sigma-event-logs-all.yml` は Chainsaw v2 で推奨される指定です。Sigma リポジトリをクローンし、マッピング YAML を用意して `-s` と `--mapping` で渡します。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw/wiki/Usage)

***

## 1) Dockerfile

> Chainsaw のリリース（v2.13.1 など）には Linux 用の事前ビルドバイナリ（`x86_64-unknown-linux-gnu.tar.gz` 等）が用意されています。必要に応じてアーキテクチャに合わせてアセット名を切り替えてください。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw/releases)

***

## 2) docker-compose.yml

> **ポイント**
>
> *   compose の `environment:` でメール設定や Chainsaw 引数を指定できます。
> *   ホストの作業フォルダ全体を `/workspace` にマウントするため、`evtx/`・`reports/`・`sigma/`・`mappings/` をそのまま使えます。
> *   並列度（ホスト単位の並列実行）は `THREADS` で指定。

> `hunt` モードは `-s/--sigma` と `-m/--mapping` の指定が必要です（Sigma ルールと対応付けファイル）。`--level` は複数指定可能で、`--csv / --json / --log` のフォーマットを選べます。`--local` または `--timezone` で時刻表記を制御できます。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw), [\[github.com\]](https://github.com/WithSecureLabs/chainsaw/wiki/Usage)

***

## 3) スクリプト（`scripts/scan_and_report.py`）

*   `evtx/` 配下の**ホストごとのサブディレクトリ**を列挙し、ホスト単位で Chainsaw を実行します。
*   出力は `reports/<HOST>-<YYYYmmddHHMMSS>.<ext>` に保存します（`ext` は `csv/json/log`）。
*   何かしらの検出行（CSVでヘッダ以降、JSONで非空、LOGで非空）があればそのホストは「検出あり」とみなし、**メール通知**します。
*   `THREADS` でホスト並列度を指定できます（Python のスレッドプール）。
*   `CHAINS_MODE="hunt"` 前提。`search` を使いたい場合はロジックを `build_hunt_cmd()` 相当で切り替えるだけです。

***

## 使い方

1.  **Sigma ルールとマッピングファイル**を用意
    *   例）`git clone https://github.com/SigmaHQ/sigma ./sigma`（ルール群）
    *   例）`mappings/sigma-event-logs-all.yml` を取得（Chainsaw リポジトリの `mappings/` 参照）。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw/wiki/Usage), [\[github.com\]](https://github.com/WithSecureLabs/chainsaw)

    > git clone https://github.com/SigmaHQ/sigma ./sigma
    > curl -o ./mappings/sigma-event-logs-all.yml https://raw.githubusercontent.com/WithSecureLabs/chainsaw/refs/heads/master/mappings/sigma-event-logs-all.yml        


2.  `evtx/` 配下にホストごとのサブディレクトリを作成し、各 `.evtx` を配置。

3.  `docker-compose.yml` の `environment:` を必要に応じて調整
    *   出力フォーマット（`CHAINS_FORMAT=csv|json|log`）
    *   ルールレベル（`CHAINS_LEVELS="critical,high,..."`）
    *   期間フィルタ（`FROM`, `TO`）
    *   タイムゾーン（`LOCAL_TIME=true` または `TIMEZONE="Asia/Tokyo"`）
    *   メール送信（`SMTP_*`, `MAIL_*`）
    *   並列度（`THREADS`）

4.  実行（作業フォルダで）：
    ```bash
    docker compose up --build
    ```
    実行後、`reports/` にホスト別レポートが生成されます。検出があったホストが1つでもあればメールが送信されます。

***

## 補足とTips

*   **出力と検出判定**  
    本スクリプトでは `-o/--output` を使わず **STDOUT をファイル保存**しています。これにより、フォーマット別の検出判定（CSVならヘッダ以外の行があるか、JSON/LOGなら非空か）を確実に行えます。`hunt` の標準オプションである `--csv / --json / --log` を使ってフォーマットを切り替え可能です。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw)

*   **拡張子フィルタ**  
    `--extension .evtx` を指定していますが、必要に応じて XML/JSON ログも対象にできます（`EXTENSIONS` でカンマ区切り）。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw)

*   **レベルフィルタ**  
    `--level` は複数指定可能です（例：`critical`, `high`, `medium`, `low`）。compose の `CHAINS_LEVELS` をカンマ区切りで渡すと、各レベルが個別に `--level` として適用されます。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw)

*   **Sigma とマッピング**  
    `-s/--sigma` と `--mapping` の指定は**必須**です。SigmaHQ のルール群と Chainsaw の `mappings/sigma-event-logs-all.yml` を使うのが手早いです。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw/wiki/Usage)

*   **並列度（THREADS）**  
    Chainsaw 自体の CLI にはスレッド数指定は見当たりません（v2 の `hunt` USAGEに未記載）。代わりに本スクリプトで**ホスト単位の並列実行**を行い、`THREADS` で制御します。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw)

*   **バージョン固定と更新**  
    Dockerfile の `CHAINSAW_VERSION` を変更すれば、ビルド時に別バージョンのバイナリを取得できます。最新版アセット名は GitHub Releases で確認できます。 [\[github.com\]](https://github.com/WithSecureLabs/chainsaw/releases)

***

## 次の一歩（ご希望があれば）

*   `.env` ファイルを同梱して **compose の環境変数を一元管理**
*   `search` モード用の分岐（例：特定 EventID を絞って CSV で可視化） [\[github.com\]](https://github.com/WithSecureLabs/chainsaw)
*   レポートの整形（検出件数／ルール別集計、Markdown要約など）

***

必要であれば、**SMTP の具体的な接続要件**（社内リレーの FQDN、認証要否、ポート番号、TLS/STARTTLS の可否）や、**Sigma の対象（どのサブセットを使うか）**、**タイムゾーン／期間フィルタの既定値**など、運用に合わせて初期値を組み込んだ `.env` を作ります。どのような初期セットにしましょう？
