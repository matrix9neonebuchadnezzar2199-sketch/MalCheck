# Malware Unified Analyzer (v1.0) 日本語ガイド

Python 製オーケストレーターで、**Phase 1（表層解析）**、任意の **Phase 2（動的解析スタブ）**、**Phase 3（Docker 内 Ghidra headless / ネットワーク隔離）** を実行し、**JSON + HTML** レポートを生成します。

## クイックスタート（FLARVM: Windows 10 / オフラインVM）

1. 事前準備（ホスト側：ネット有）

   - `ghidra_11.4.3_PUBLIC_20251203.zip` を `build/ghidra-headless/` に配置（初回のみ）
   - パッケージング実行：
     ```text
     bash make_usb.sh
     ```

2. FLARVM 側でデプロイ（オフライン：Windows）
   ```text
   deploy.bat
   ```
   （`deploy.bat` が `images/*.tar.gz` を `docker load` し、`docker-compose.usb.yml` で起動します）

3. 検体投入と解析実行
   ```text
   copy suspect.exe samples\
   docker exec orchestrator python -m mau.main suspect.exe
   ```

4. Web UI を開く（手順2の後）
   ```text
   http://127.0.0.1:8080
   ```

レポートは `results/reports/` に出力されます（JSON + HTML）。

停止:
```text
docker compose -f docker-compose.usb.yml --env-file compose\.env.runtime down
```

## Ghidra headless イメージ

`build/ghidra-headless/` に `ghidra_11.4.3_PUBLIC_20251203.zip` を配置（`PLACE_GHIDRA_ZIP_HERE.txt` 参照）してからビルドします。

```text
docker build -t ghidra-headless:latest -f build/ghidra-headless/Dockerfile build/ghidra-headless
```

このイメージが未作成の場合、Phase 3 はレポート内でエラー記録になりますが、Phase 1〜2 の処理とレポート生成は継続します。

## REMnux（USB / エアギャップ運用）

REMnux イメージを使う場合は、デフォルト compose の代わりに `docker-compose.remnux.yml` を使ってください。`SURFACE_CONTAINER` / `REMNUX_CONTAINER` は `remnux-analyzer` に設定します。

## USB デプロイ

- **開発マシン**: `bash build/build_and_pack.sh` を実行（Ghidra ZIP が必要）
- **解析マシン**: `deploy.sh` または `deploy.bat` を実行し、表示された `docker compose` コマンドで起動

## 設定

`compose/config/analyzer.yaml` を編集するか、`MAU_CONFIG` に YAML パスを指定します。

- `phases.dynamic.enabled`: `true` にする場合は JSON を返すカスタムフック（`MAU_DYNAMIC_HOOK`）を用意
- `report.executive_summary_llm`: Ollama API 到達可能時に有効化（`ollama.base_url`）

## テスト（ホスト）

```text
pip install -r requirements-dev.txt
pytest tests -v
```

## エラー処理

各フェーズは失敗を捕捉し、全体停止ではなくレポートに `{ "error": true, ... }` を埋め込む設計です（レポート生成自体の失敗は例外化）。詳細ログは `MAU_LOG_LEVEL=DEBUG` で確認できます。

