#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
資安漏洞情報自動化系統 - 統一入口點
Usage:
    python scripts/main.py --config config.yaml --mode all
    python scripts/main.py --config config.yaml --mode collect
    python scripts/main.py --config config.yaml --mode notify
    python scripts/main.py --config config.yaml --mode web
    python scripts/main.py --config config.yaml --mode all --schedule --interval 60
"""

import argparse
import logging
import os
import sys
import time
import json
from datetime import datetime, timezone

import yaml

# 確保 scripts 目錄在路徑中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def setup_logging(log_level: str, log_dir: str) -> None:
    """設定日誌輸出（同時輸出至終端機和檔案）"""
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"vuln-intel-{datetime.now().strftime('%Y%m%d')}.log")
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )


def load_config(config_path: str) -> dict:
    """載入 YAML 設定檔"""
    if not os.path.exists(config_path):
        print(f"❌ 設定檔不存在：{config_path}")
        print("請先複製 assets/config_template.yaml 為 config.yaml 並填入設定。")
        sys.exit(1)
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_collect(config: dict) -> list:
    """執行漏洞蒐集"""
    from collector import VulnerabilityCollector
    from product_matcher import ProductMatcher
    from kev_checker import KEVChecker
    from poc_checker import PoCChecker
    from translator import Translator
    from onedrive_uploader import OneDriveUploader

    log = logging.getLogger("main.collect")
    log.info("🔍 開始蒐集漏洞資料...")

    # 初始化各元件
    translator = Translator(config.get("translation", {}))
    kev_checker = KEVChecker(config.get("kev", {}))

    # 從 OneDrive 下載產品清單
    uploader = OneDriveUploader(config["onedrive"])
    products_data = uploader.download_products_excel()
    product_matcher = ProductMatcher(products_data)

    poc_checker = PoCChecker(config.get("poc", {}))
    collector = VulnerabilityCollector(config.get("sources", {}))

    # 蒐集所有來源
    raw_vulns = collector.collect_all()
    log.info(f"📥 共蒐集到 {len(raw_vulns)} 筆原始資料")

    # 豐富化處理（翻譯、KEV、PoC、產品比對）
    enriched = []
    for i, vuln in enumerate(raw_vulns, 1):
        log.debug(f"處理第 {i}/{len(raw_vulns)} 筆：{vuln.get('title', 'N/A')[:50]}")
        try:
            # 翻譯
            if not vuln.get("description_zh"):
                vuln["description_zh"] = translator.translate(
                    vuln.get("description_en", ""), target="zh-TW"
                )
            # KEV 比對
            cve_id = vuln.get("cve_id", "N/A")
            if cve_id != "N/A":
                kev_result = kev_checker.check(cve_id)
                vuln["is_kev"] = kev_result.get("is_kev", False)
                vuln["kev_date_added"] = kev_result.get("date_added")
            else:
                vuln["is_kev"] = False
                vuln["kev_date_added"] = None

            # PoC 偵測
            poc_result = poc_checker.check(cve_id)
            vuln["has_poc"] = poc_result.get("has_poc", False)
            vuln["poc_urls"] = poc_result.get("poc_urls", [])

            # 產品比對
            vuln["hit_products"] = product_matcher.match(
                title=vuln.get("title", ""),
                description=vuln.get("description_en", ""),
                cpe_list=vuln.get("cpe_list", []),
            )

            enriched.append(vuln)
        except Exception as e:
            log.warning(f"處理漏洞時發生錯誤（跳過）：{e}")
            enriched.append(vuln)

    # 儲存至本地 JSON
    data_dir = config.get("storage", {}).get("data_dir", "./data")
    os.makedirs(data_dir, exist_ok=True)
    local_path = os.path.join(data_dir, "vulnerabilities.json")

    # 讀取既有資料（增量更新）
    existing = []
    if os.path.exists(local_path):
        with open(local_path, encoding="utf-8") as f:
            existing_data = json.load(f)
            existing = existing_data.get("vulnerabilities", [])

    # 去重（以 cve_id + source 為 key）
    existing_keys = {
        (v.get("cve_id", ""), v.get("source", ""), v.get("url", ""))
        for v in existing
    }
    new_vulns = [
        v for v in enriched
        if (v.get("cve_id", ""), v.get("source", ""), v.get("url", "")) not in existing_keys
    ]

    all_vulns = existing + new_vulns
    output_data = {
        "metadata": {
            "version": "1.0",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_count": len(all_vulns),
            "new_count": len(new_vulns),
            "sources": ["NVD", "GitHub", "MSRC", "ZDI", "iThome", "FISAC", "TWCERT"],
        },
        "vulnerabilities": all_vulns,
    }

    with open(local_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    log.info(f"✅ 新增 {len(new_vulns)} 筆，總計 {len(all_vulns)} 筆，已存至 {local_path}")

    # 上傳至 OneDrive
    try:
        uploader.upload_json(local_path, config["onedrive"].get("vuln_filename", "vulnerabilities.json"))
        log.info("☁️ 已上傳至 OneDrive")
    except Exception as e:
        log.error(f"OneDrive 上傳失敗（資料已存本地）：{e}")

    return new_vulns


def run_notify(config: dict, new_vulns: list = None) -> None:
    """執行郵件通知"""
    from email_notifier import EmailNotifier

    log = logging.getLogger("main.notify")

    if new_vulns is None:
        # 從本地 JSON 讀取最新資料
        local_path = os.path.join(
            config.get("storage", {}).get("data_dir", "./data"),
            "vulnerabilities.json"
        )
        if not os.path.exists(local_path):
            log.error("❌ 找不到本地漏洞資料，請先執行 collect 模式")
            return
        with open(local_path, encoding="utf-8") as f:
            data = json.load(f)
        new_vulns = data.get("vulnerabilities", [])

    # 過濾嚴重度門檻
    threshold_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    threshold = config.get("smtp", {}).get("severity_threshold", "MEDIUM")
    threshold_level = threshold_map.get(threshold.upper(), 2)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    filtered = [
        v for v in new_vulns
        if severity_order.get(v.get("severity", "LOW").upper(), 3) <= threshold_level
    ]

    if not filtered:
        log.info("ℹ️ 無符合門檻的新漏洞，不寄送郵件")
        return

    log.info(f"📧 準備寄送 {len(filtered)} 筆漏洞通知...")
    notifier = EmailNotifier(config["smtp"])
    notifier.send(filtered)
    log.info("✅ 郵件寄送完成")


def run_web(config: dict) -> None:
    """啟動網頁查詢介面"""
    from web_server import VulnWebServer

    log = logging.getLogger("main.web")
    web_cfg = config.get("web", {})
    host = web_cfg.get("host", "0.0.0.0")
    port = web_cfg.get("port", 8080)

    log.info(f"🌐 啟動漏洞查詢網頁：http://localhost:{port}")
    server = VulnWebServer(config)
    server.run(host=host, port=port)


def main():
    parser = argparse.ArgumentParser(
        description="資安漏洞情報自動化系統",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
執行模式說明：
  all      完整流程（蒐集 + 上傳 OneDrive + 郵件通知）
  collect  僅蒐集漏洞資料並存 JSON
  notify   從現有 JSON 讀取並寄送郵件
  web      啟動漏洞查詢網頁（http://localhost:8080）
        """,
    )
    parser.add_argument("--config", default="config.yaml", help="設定檔路徑（預設：config.yaml）")
    parser.add_argument(
        "--mode",
        choices=["all", "collect", "notify", "web"],
        default="all",
        help="執行模式",
    )
    parser.add_argument("--schedule", action="store_true", help="定時執行模式")
    parser.add_argument("--interval", type=int, default=60, help="定時執行間隔（分鐘，預設 60）")
    args = parser.parse_args()

    config = load_config(args.config)
    storage = config.get("storage", {})
    setup_logging(storage.get("log_level", "INFO"), storage.get("log_dir", "./logs"))
    log = logging.getLogger("main")

    log.info("=" * 60)
    log.info("🛡️  資安漏洞情報自動化系統 啟動")
    log.info(f"   模式：{args.mode} | 設定檔：{args.config}")
    log.info("=" * 60)

    def execute():
        if args.mode == "collect":
            run_collect(config)
        elif args.mode == "notify":
            run_notify(config)
        elif args.mode == "web":
            run_web(config)
        elif args.mode == "all":
            new_vulns = run_collect(config)
            run_notify(config, new_vulns)

    if args.schedule and args.mode != "web":
        import schedule as sched

        log.info(f"⏰ 定時模式：每 {args.interval} 分鐘執行一次")
        execute()  # 立即執行一次
        sched.every(args.interval).minutes.do(execute)
        while True:
            sched.run_pending()
            time.sleep(30)
    else:
        execute()


if __name__ == "__main__":
    main()
