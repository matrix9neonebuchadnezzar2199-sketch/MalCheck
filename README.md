# MalCheck

> ローカル・オフライン運用を前提とした、統合マルウェア解析オーケストレーター

[![Python](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](#)
[![FastAPI](https://img.shields.io/badge/web-fastapi-009688?logo=fastapi&logoColor=white)](#)
[![Docker](https://img.shields.io/badge/runtime-docker%20compose-2496ED?logo=docker&logoColor=white)](#)
[![Ghidra](https://img.shields.io/badge/static-ghidra%20headless-orange)](#)
[![Report](https://img.shields.io/badge/output-json%20%2B%20html-4C1)](#)
[![Status](https://img.shields.io/badge/status-active-success)](#)

**タグ:** malware-analysis, ghidra, yara, capa, triage, offline, usb-deploy, reverse-engineering

---

## MalCheck とは

MalCheck は、以下のフェーズを統合実行する **フェーズ指向マルウェア解析オーケストレーター** です。

- **Phase 1 - 表層解析**（ハッシュ、文字列、IOC抽出、YARA/capa、エントロピー/パッカー推定）
- **Phase 2 - 動的解析コントラクト**（hook first、将来のサンドボックス連携を前提）
- **Phase 3 - 静的解析**（ネットワーク隔離した Ghidra headless）

出力は次の2系統です。

- **機械可読な JSON レポート**
- **アナリスト向け HTML レポート**

MalCheck は **ローカル環境・エアギャップ環境** での運用を想定し、マルウェア解析向けの安全境界を明示的に維持します。

英語版が必要な場合は [`README_JP.md`](README_JP.md) を参考に、今後 `README.md` の英訳版を追加してください。

---

## プロダクトとしての位置づけ

MalCheck は「統合解析の母艦」です。

- フェーズ制御とレポート契約は `mau/` に集約
- 静的解析/RE機能は段階的に統合
- 一発の大改修ではなく、スライス単位で進化

現行アーキテクチャとロードマップ:

- [`docs/architecture.html`](docs/architecture.html)
- [`docs/milestones.html`](docs/milestones.html)
- [`docs/implementation-rules.html`](docs/implementation-rules.html)
- [`docs/development-diary.html`](docs/development-diary.html)

---

## 主な機能

### 1) フェーズ指向パイプライン

`mau.phase_router.run_pipeline()` は次を制御します:

- `surface` -> 高速かつ耐障害性を重視した初期トリアージ
- `dynamic` -> skipped / not_implemented / hook結果
- `static` -> Ghidraコンテナ実行

各フェーズの失敗は分離され、パイプライン全体を停止させる代わりにレポートへ構造化記録されます。

### 2) オフラインファースト運用

- USB/オフライン配布向けスクリプトを同梱
- Windows/Linux のエアギャップ導入パスを用意
- Ghidra静的解析はデフォルトでネットワーク隔離

### 3) レポート中心設計

すべての実行で、構造化レポートを生成します。

- `results/reports/<sample>.json`
- `results/reports/<sample>.html`

現行レポート契約の代表項目:

- `meta.schema_version`
- `phase_status.surface/dynamic/static`
- normalized phase payloads

### 4) 拡張可能な動的解析連携

動的解析は意図的に hook first です。

- 安全な既定値: disabled（`skipped`）
- hook 未設定で enabled: `not_implemented`
- `MAU_DYNAMIC_HOOK` 使用時: 正規化された dynamic payload

---

## クイックスタート

### A. ローカル Docker 実行

```text
docker compose up -d
```

オーケストレーターから検体を1件実行:

```text
docker exec orchestrator python -m mau.main suspect.exe
```

Web UI:

```text
http://127.0.0.1:8080
```

### B. FLARE VM / オフライン運用（Windows）

1. ネット接続可能な端末でイメージ準備
   - `ghidra_11.4.3_PUBLIC_20251203.zip` を `build/ghidra-headless/` に配置
   - 次を実行:
   ```text
   bash make_usb.sh
   ```
2. オフライン解析端末で実行:
   ```text
   deploy.bat
   ```
3. 解析実行:
   ```text
   copy suspect.exe samples\
   docker exec orchestrator python -m mau.main suspect.exe
   ```

停止:

```text
docker compose -f docker-compose.usb.yml --env-file compose\.env.runtime down
```

---

## Surface イメージの再ビルド（M-U2 以降）

PE/Office/PDF 用の `pefile` / `oletools` / `pdfid` を surface コンテナに含めます。依存を更新したらリポジトリルートで:

```text
docker compose build surface-analyzer
```

（`containers/surface/Dockerfile` は `scripts/remnux/format_scanners.py` を `/scripts/` に COPY します。）

---

## Ghidra イメージのビルド

Ghidra ZIP を `build/ghidra-headless/` に配置したうえで、静的解析イメージをビルドします（リポジトリルートから）:

```text
docker build -t ghidra-headless:latest -f build/ghidra-headless/Dockerfile build/ghidra-headless
```

既定では **1 回**の headless 実行で `auto_analyze.py` が `/output/analysis.json` を生成します（CFG・コールグラフ・関数別デコンパイルを含む）。レガシー 3 パス出力が必要な場合はコンテナに `MAU_GHIDRA_LEGACY=1` を渡します。

スキーマ正本: [`docs/static-analysis-schema.html`](docs/static-analysis-schema.html)

このイメージが無い場合、Static フェーズは `status: failed` を記録しますが、他フェーズのレポート生成は継続します。

---

## 設定

主設定ファイル:

- `compose/config/analyzer.yaml`

環境変数での上書き:

- `MAU_CONFIG=<path-to-yaml>`

影響度の高いキー:

- `phases.dynamic.enabled`
- `phases.static.ghidra_image`
- `report.executive_summary_llm`
- `ollama.base_url`
- `ollama.model`
- `intake.enabled`, `intake.passwords`, `intake.max_extract_mb`

---

## テスト

ホスト側テストコマンド:

```text
pip install -r requirements-dev.txt
pytest tests -v
```

現行テストで確認している内容:

- 設定ロード / マージ挙動
- 表層解析 JSON コントラクト
- レポート集約と verdict ロジック
- dynamic hook 出力の正規化
- CLI のエラー / 終了コード挙動

---

## セキュリティ / OPSEC 境界

MalCheck はマルウェア解析用途です。検体由来データはすべて不正入力として扱ってください。

- Do not commit samples, payloads, or IOC-heavy artifacts
- Do not add automatic online IOC enrichment by default
- Keep static/Ghidra containers network-isolated
- Keep dynamic detonation opt-in and lab-backed

See full rules in [`docs/implementation-rules.html`](docs/implementation-rules.html).

---

## リポジトリ構成

```text
mau/                     # core orchestrator and report generation
scripts/remnux/          # surface analysis script
build/ghidra-headless/   # Ghidra static image assets
containers/surface/      # lightweight surface-analysis container
web_ui/                  # FastAPI + Jinja web interface
compose/config/          # runtime analyzer config
rules/yara/              # YARA rules
tests/                   # pytest suite
docs/                    # architecture, milestones, rules, diary
```

---

## ロードマップ概要

直近マイルストーン:

1. Surface analysis consolidation (stable scanner contract)
2. Richer static output integration
3. Report/UI improvements
4. Dynamic hook contract hardening
5. Optional CAPE/VM integration

Detailed plan: [`docs/milestones.html`](docs/milestones.html)

---

## 利用上の注意

このリポジトリは、防御目的の研究、リバースエンジニアリング、管理されたラボ運用を想定しています。  
マルウェア解析を行う法的権限と運用体制がある環境でのみ利用してください。
