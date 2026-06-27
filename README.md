# AegisTrace DFIR — Chrome Browser Forensics Analyzer

[English](#english) | [العربية](#العربية)

---

<a id="english"></a>

# English

## Overview

**AegisTrace DFIR** is a Python-based Chrome browser forensics analyzer designed for digital forensic investigation, cybersecurity research, and incident response training. The tool extracts and analyzes Chrome profile artifacts, preserves evidence using forensic-safe working copies, generates structured reports, and provides an optional privacy-aware AI-assisted forensic summary.

> **Legal Notice:** This tool is intended only for lawful, authorized, and ethical digital forensic investigations. Do not use it on systems or data without permission.

---

## Key Features

- Investigation Setup Dialog for examiner name, case ID, and notes.
- Chrome profile directory selection through a graphical interface.
- Evidence-safe database copying before analysis.
- SHA-256 evidence integrity verification.
- Chain-of-custody logging.
- Parsing of 13 Chrome artifact categories:
  - History
  - Downloads
  - Cookies
  - Login Data
  - Top Sites
  - Bookmarks
  - Preferences
  - Web Data
  - Extensions
  - Favicons
  - Sessions
  - Local Storage
  - Deleted Records indicators
- Chrome epoch and filesystem timestamp normalization to UTC.
- Suspicious keyword detection using regex word-boundary matching.
- High-risk download detection.
- WAL/Journal/SHM companion file detection.
- SQLite ID gap analysis for possible deleted-record indicators.
- Optional AI-assisted forensic summary using OpenRouter/OpenAI-compatible APIs.
- Sensitive data redaction before external AI communication.
- Multi-format export:
  - JSON
  - Timeline CSV
  - History CSV
  - PDF
  - HTML dashboard
  - XLSX workbook
- Case Compare feature for side-by-side comparison of two exported case JSON files.

---

## Project Structure

```text
AegisTrace-DFIR/
├── main.py
├── gui.py
├── core.py
├── requirements.txt
├── aegistrace_settings.json
├── README_AI_INTEGRATION.md
└── README.md
```

---

## Requirements

- Windows 10 / Windows 11
- Python 3.10+
- Google Chrome profile directory
- Python dependencies listed in `requirements.txt`

Dependencies:

```text
Pillow
anthropic
matplotlib
openai
reportlab
requests
openpyxl
```

---

## Installation

1. Ensure **Python 3.10+** is installed.

2. Place all project files in a local directory.

3. Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Application

1. Launch the GUI:

```bash
python main.py
```

2. Complete the **Investigation Setup Dialog** by entering:
   - Examiner name
   - Case ID
   - Investigation notes

3. Click **Browse** to select the Chrome profile directory:

```text
%LOCALAPPDATA%\Google\Chrome\User Data\Default
```

4. Optional: enter the OpenRouter API key, model, and base URL, then click **Save Configuration**.

5. Optional: click **Configure Keywords** to customize the suspicious keyword list.

6. Click **Run Analysis** and monitor the real-time progress log.

7. Use **Export XLSX**, **Export HTML**, or **Open Report Folder** to access outputs.

8. Use the **Compare** tab to load two case JSON files for side-by-side analysis.

---

## AI Configuration

OpenRouter is the default AI provider.

Default configuration:

```text
Provider: OpenRouter
Model: openai/gpt-4o-mini
Base URL: https://openrouter.ai/api/v1
```

To use AI-assisted summaries:

1. Obtain an API key from OpenRouter.
2. Enter the API key in the AI panel.
3. Confirm the model and base URL.
4. Click **Save Configuration**.
5. Click **Generate AI Summary** after running the analysis.

If no API key is configured, the tool generates a local rule-based summary.

---

## Output Files

After analysis and export, the case directory may contain:

```text
analysis.json
timeline.csv
history.csv
report.pdf
dashboard.html
<case_id>_report.xlsx
Evidence/
chain_log.txt
report_sha256.txt
```

### Output Description

| Output | Description |
|---|---|
| `analysis.json` | Complete machine-readable analysis output. |
| `timeline.csv` | Chronological event list from all supported artifact sources. |
| `history.csv` | Browsing history with URL classification. |
| `report.pdf` | Formatted examiner PDF report. |
| `dashboard.html` | Interactive dark-mode forensic dashboard. |
| `<case_id>_report.xlsx` | Colour-coded Excel workbook with artifact sheets. |
| `Evidence/` | Working copies of Chrome SQLite databases. |
| `chain_log.txt` | Chain-of-custody log. |
| `report_sha256.txt` | SHA-256 hash of the PDF report. |

---

## Security and Privacy

AegisTrace DFIR applies several security controls:

- Original Chrome files are preserved.
- Parsing is performed on copied evidence files.
- SHA-256 hashes are used to verify evidence integrity.
- Chain-of-custody actions are logged.
- API keys should never be committed to GitHub.
- Sensitive fields are redacted before AI transmission, including:
  - passwords
  - cookie values
  - tokens
  - access tokens
  - refresh tokens
  - sessions
  - secrets



---

## Known Limitations

- Cookie values and stored passwords are DPAPI-encrypted and are not decrypted.
- The AI summary feature contacts external servers; use it only with proper authorization.
- The tool does not acquire or analyze volatile memory.
- Local Storage and Session file content is not fully decoded; filesystem metadata is extracted.
- WAL/Journal and ID gap analysis indicates possible deleted-record activity but does not guarantee full recovery of deleted records.

---

## Suggested Future Work

- Add Windows DPAPI decryption when legally and technically authorized.
- Add offline AI support using Ollama or another local model.
- Add full LevelDB Local Storage content parsing.
- Add Chromium session binary decoding.
- Add SQLite forensic carving for deleted records.
- Add Microsoft Edge and Mozilla Firefox support.
- Add PyInstaller packaging for a standalone Windows executable.
- Add automated tests using `pytest`.

---

## Disclaimer

This project is provided for educational, research, and authorized forensic investigation purposes only. The author is not responsible for misuse or illegal use.

---

## Author

Built by **ENG: Abed Alrahman Manasrah**

Graduation Project — Information Security / Digital Forensics

---

<a id="العربية"></a>

# العربية

## نظرة عامة

**AegisTrace DFIR** هي أداة مبنية بلغة Python لتحليل آثار متصفح Google Chrome ضمن مجال الأدلة الجنائية الرقمية. تهدف الأداة إلى مساعدة المحققين الرقميين، وطلاب الأمن السيبراني، وباحثي الاستجابة للحوادث على استخراج وتحليل آثار المتصفح بطريقة منظمة، قابلة للتكرار، ومراعية لسلامة الأدلة.

> **تنبيه قانوني:** هذه الأداة مخصصة فقط للاستخدام القانوني والمصرح به في التحقيقات الرقمية، والبحث الأكاديمي، والتدريب الأمني. لا تستخدمها على أجهزة أو بيانات لا تملك إذنًا قانونيًا لتحليلها.

---

## المميزات الرئيسية

- نافذة إعداد التحقيق لإدخال اسم المحقق، رقم القضية، وملاحظات التحقيق.
- اختيار مجلد ملف Chrome الشخصي من خلال واجهة رسومية.
- إنشاء نسخ عمل آمنة من قواعد البيانات قبل التحليل.
- التحقق من سلامة الأدلة باستخدام SHA-256.
- تسجيل سلسلة الحيازة Chain of Custody.
- تحليل 13 نوعًا من آثار Chrome:
  - History
  - Downloads
  - Cookies
  - Login Data
  - Top Sites
  - Bookmarks
  - Preferences
  - Web Data
  - Extensions
  - Favicons
  - Sessions
  - Local Storage
  - Deleted Records indicators
- تحويل طوابع Chrome الزمنية وطوابع نظام الملفات إلى UTC.
- كشف الكلمات المفتاحية المشبوهة باستخدام Regex مع مطابقة حدود الكلمات.
- كشف الملفات المحملة عالية الخطورة.
- كشف ملفات WAL/Journal/SHM المصاحبة.
- تحليل فجوات SQLite ID كمؤشرات محتملة على سجلات محذوفة.
- ملخص جنائي اختياري مدعوم بالذكاء الاصطناعي عبر OpenRouter أو واجهات OpenAI المتوافقة.
- إخفاء الحقول الحساسة قبل إرسال أي بيانات إلى مزود ذكاء اصطناعي خارجي.
- تصدير النتائج بعدة صيغ:
  - JSON
  - Timeline CSV
  - History CSV
  - PDF
  - HTML Dashboard
  - XLSX Workbook
- ميزة Case Compare لمقارنة ملفي JSON لقضيتين مختلفتين.

---

## هيكل المشروع

```text
AegisTrace-DFIR/
├── main.py
├── gui.py
├── core.py
├── requirements.txt
├── aegistrace_settings.json
├── README_AI_INTEGRATION.md
└── README.md
```

---

## المتطلبات

- Windows 10 / Windows 11
- Python 3.10 أو أحدث
- مجلد ملف Google Chrome الشخصي
- المكتبات الموجودة في ملف `requirements.txt`

المكتبات المطلوبة:

```text
Pillow
anthropic
matplotlib
openai
reportlab
requests
openpyxl
```

---

## التثبيت

1. تأكد من تثبيت **Python 3.10+**.

2. ضع جميع ملفات المشروع في مجلد محلي.

3. ثبّت المتطلبات:

```bash
pip install -r requirements.txt
```

---

## طريقة تشغيل الأداة

1. شغّل الواجهة الرسومية:

```bash
python main.py
```

2. أكمل نافذة **Investigation Setup Dialog** بإدخال:
   - اسم المحقق
   - رقم القضية
   - ملاحظات التحقيق

3. اضغط **Browse** لاختيار مجلد ملف Chrome الشخصي:

```text
%LOCALAPPDATA%\Google\Chrome\User Data\Default
```

4. اختياريًا: أدخل مفتاح OpenRouter API، واسم النموذج، وBase URL، ثم اضغط **Save Configuration**.

5. اختياريًا: اضغط **Configure Keywords** لتخصيص قائمة الكلمات المفتاحية المشبوهة.

6. اضغط **Run Analysis** وراقب سجل التقدم الحقيقي داخل الواجهة.

7. استخدم **Export XLSX** أو **Export HTML** أو **Open Report Folder** للوصول إلى المخرجات.

8. استخدم تبويب **Compare** لتحميل ملفي JSON لقضيتين ومقارنتهما جنبًا إلى جنب.

---

## إعداد الذكاء الاصطناعي

المزود الافتراضي هو OpenRouter.

الإعداد الافتراضي:

```text
Provider: OpenRouter
Model: openai/gpt-4o-mini
Base URL: https://openrouter.ai/api/v1
```

لاستخدام الملخص المدعوم بالذكاء الاصطناعي:

1. احصل على API Key من OpenRouter.
2. أدخل المفتاح في لوحة AI داخل الأداة.
3. تأكد من اسم النموذج وBase URL.
4. اضغط **Save Configuration**.
5. بعد تشغيل التحليل، اضغط **Generate AI Summary**.

إذا لم يتم إدخال مفتاح API، ستستخدم الأداة ملخصًا محليًا قائمًا على القواعد.

---

## ملفات المخرجات

بعد التحليل والتصدير، قد يحتوي مجلد القضية على:

```text
analysis.json
timeline.csv
history.csv
report.pdf
dashboard.html
<case_id>_report.xlsx
Evidence/
chain_log.txt
report_sha256.txt
```

### شرح المخرجات

| الملف | الوصف |
|---|---|
| `analysis.json` | ملف كامل يحتوي على نتائج التحليل بصيغة قابلة للمعالجة. |
| `timeline.csv` | قائمة زمنية للأحداث من جميع مصادر الآثار المدعومة. |
| `history.csv` | سجل التصفح مع تصنيف الروابط. |
| `report.pdf` | تقرير PDF منسق للمحقق. |
| `dashboard.html` | لوحة تحكم تفاعلية بوضع داكن. |
| `<case_id>_report.xlsx` | ملف Excel ملون ومنظم يحتوي على أوراق للآثار. |
| `Evidence/` | نسخ العمل من قواعد بيانات Chrome. |
| `chain_log.txt` | سجل سلسلة الحيازة. |
| `report_sha256.txt` | قيمة SHA-256 لتقرير PDF. |

---

## الأمان والخصوصية

تطبق AegisTrace DFIR عدة ضوابط أمنية:

- الحفاظ على ملفات Chrome الأصلية دون تعديل.
- تنفيذ التحليل على نسخ العمل فقط.
- استخدام SHA-256 للتحقق من سلامة الأدلة.
- تسجيل إجراءات سلسلة الحيازة.
- عدم رفع مفاتيح API إلى GitHub.
- إخفاء الحقول الحساسة قبل إرسال البيانات إلى AI، مثل:
  - كلمات المرور
  - قيم Cookies
  - Tokens
  - Access Tokens
  - Refresh Tokens
  - Sessions
  - Secrets



---

## الحدود المعروفة

- لا يتم فك تشفير كلمات المرور أو قيم Cookies المحمية بواسطة DPAPI.
- ميزة الملخص الذكي تتصل بخوادم خارجية؛ استخدمها فقط عند وجود تصريح مناسب.
- الأداة لا تقوم بالحصول على الذاكرة المتطايرة RAM أو تحليلها.
- محتوى Local Storage وSession لا يتم فكّه بالكامل؛ يتم استخراج بيانات وصفية على مستوى الملفات.
- تحليل WAL/Journal وفجوات ID يعطي مؤشرات محتملة على الحذف، لكنه لا يضمن استرجاع السجلات المحذوفة بالكامل.

---

## تحسينات مستقبلية مقترحة

- إضافة فك تشفير DPAPI عند وجود تصريح قانوني وتقني.
- دعم AI محلي باستخدام Ollama أو نموذج محلي آخر.
- إضافة تحليل كامل لمحتوى LevelDB الخاص بـ Local Storage.
- إضافة فك ملفات Chromium Session الثنائية.
- إضافة SQLite forensic carving لاسترجاع السجلات المحذوفة فعليًا.
- دعم Microsoft Edge وMozilla Firefox.
- إنشاء نسخة تنفيذية مستقلة لنظام Windows باستخدام PyInstaller.
- إضافة اختبارات آلية باستخدام `pytest`.

---

## إخلاء المسؤولية

هذا المشروع مخصص للأغراض التعليمية والبحثية والتحقيقات الرقمية المصرح بها فقط. يتحمل المستخدم كامل المسؤولية عن أي استخدام غير قانوني أو غير مصرح به.

---

## المطور

تم التطوير بواسطة **ENG: Abed Alrahman Manasrah**

مشروع تخرج — أمن المعلومات / الأدلة الجنائية الرقمية
