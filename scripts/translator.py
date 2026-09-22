#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中英文翻譯模組
支援：Google Translate（免費）、DeepL、OpenAI
"""

import logging
from typing import Optional

log = logging.getLogger(__name__)


class Translator:
    """多服務翻譯器，自動降級"""

    def __init__(self, config: dict = None):
        self.cfg = config or {}
        self.service = self.cfg.get("service", "google").lower()
        self.target = self.cfg.get("target_language", "zh-TW")
        self._google_translator = None
        self._deepl_translator = None
        self._openai_client = None

    def translate(self, text: str, target: Optional[str] = None) -> str:
        """
        翻譯文字
        - 若文字為空，回傳空字串
        - 若翻譯失敗，回傳原文（附 [翻譯失敗] 標記）
        """
        if not text or not text.strip():
            return ""

        target_lang = target or self.target

        # 長文字截斷（避免超出 API 限制）
        if len(text) > 5000:
            text = text[:5000] + "..."

        try:
            if self.service == "google":
                return self._translate_google(text, target_lang)
            elif self.service == "deepl":
                return self._translate_deepl(text, target_lang)
            elif self.service == "openai":
                return self._translate_openai(text, target_lang)
            elif self.service == "none":
                return f"[翻譯已停用] {text}"
            else:
                log.warning(f"未知翻譯服務：{self.service}，使用 Google")
                return self._translate_google(text, target_lang)
        except Exception as e:
            log.warning(f"翻譯失敗（{self.service}）：{e}，回傳原文")
            return f"[翻譯失敗] {text}"

    def _translate_google(self, text: str, target: str) -> str:
        """使用 deep-translator 的 Google Translate（免費版）"""
        if self._google_translator is None:
            try:
                from deep_translator import GoogleTranslator
                self._google_translator = GoogleTranslator
            except ImportError:
                raise ImportError("請安裝：pip install deep-translator")

        # 將 zh-TW 對應到 Google 的語言代碼
        lang_map = {"zh-TW": "zh-TW", "zh-CN": "zh-CN", "en": "en"}
        target_code = lang_map.get(target, target)

        translator = self._google_translator(source="auto", target=target_code)
        return translator.translate(text)

    def _translate_deepl(self, text: str, target: str) -> str:
        """使用 DeepL API"""
        api_key = self.cfg.get("deepl_api_key", "")
        if not api_key:
            raise ValueError("DeepL API Key 未設定")

        try:
            import deepl
            if self._deepl_translator is None:
                self._deepl_translator = deepl.Translator(api_key)

            lang_map = {"zh-TW": "ZH", "zh-CN": "ZH", "en": "EN-US"}
            target_code = lang_map.get(target, "ZH")
            result = self._deepl_translator.translate_text(text, target_lang=target_code)
            return str(result.text)
        except ImportError:
            raise ImportError("請安裝：pip install deepl")

    def _translate_openai(self, text: str, target: str) -> str:
        """使用 OpenAI GPT 翻譯"""
        api_key = self.cfg.get("openai_api_key", "")
        if not api_key:
            raise ValueError("OpenAI API Key 未設定")

        try:
            import openai
            if self._openai_client is None:
                self._openai_client = openai.OpenAI(api_key=api_key)

            model = self.cfg.get("openai_model", "gpt-4o-mini")
            lang_name = {"zh-TW": "繁體中文", "zh-CN": "簡體中文", "en": "英文"}.get(target, target)

            response = self._openai_client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": f"你是專業的資安翻譯員，請將以下資安漏洞說明翻譯成{lang_name}，保留所有技術術語和 CVE 編號，只回傳翻譯結果，不要額外說明。",
                    },
                    {"role": "user", "content": text},
                ],
                temperature=0.1,
                max_tokens=2000,
            )
            return response.choices[0].message.content.strip()
        except ImportError:
            raise ImportError("請安裝：pip install openai")
