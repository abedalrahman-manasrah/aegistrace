import os
import json
import csv
import sqlite3
import shutil
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

APP_NAME = "AegisTrace DFIR Pro V3"
APP_AUTHOR = "Built by Abed Alrahman Manasrah"
EXPORT_DIR = os.path.join(os.getcwd(), "Forensics_Reports")
SETTINGS_FILE = os.path.join(os.getcwd(), "aegistrace_settings.json")


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_settings(settings):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)


def generate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            block = f.read(4096)
            if not block:
                break
            sha256.update(block)
    return sha256.hexdigest()


def safe_copy_db(original_path, destination_dir):
    ensure_dir(destination_dir)
    base_name = os.path.basename(original_path)
    copy_path = os.path.join(destination_dir, f"{base_name}_copy")
    shutil.copy2(original_path, copy_path)
    return copy_path


def chrome_time_to_str(chrome_time):
    try:
        if not chrome_time:
            return "N/A"
        unix_time = int(chrome_time) / 1000000 - 11644473600
        dt = datetime.utcfromtimestamp(unix_time)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


def file_time_to_str(ts):
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


def classify_url(url):
    domain = (urlparse(url).netloc or "").lower()
    if any(x in domain for x in ["facebook", "instagram", "twitter", "x.com", "tiktok", "snapchat", "linkedin"]):
        return "Social Media"
    if any(x in domain for x in ["youtube", "netflix", "twitch", "spotify", "shahid", "disneyplus"]):
        return "Entertainment"
    if any(x in domain for x in ["mail", "gmail", "outlook", "protonmail"]):
        return "Email"
    if any(x in domain for x in ["google", "bing", "duckduckgo", "yahoo"]):
        return "Search Engine"
    if any(x in domain for x in ["bank", "paypal", "stripe", "wise"]):
        return "Financial"
    if any(x in domain for x in ["adult", "porn"]):
        return "Adult"
    if any(x in domain for x in ["github", "gitlab", "stackoverflow"]):
        return "Development"
    return "Other"


def initialize_case(case_id):
    safe_case_id = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in case_id.strip()) or "Case_Unknown"
    case_dir = ensure_dir(os.path.join(EXPORT_DIR, safe_case_id))
    evidence_dir = ensure_dir(os.path.join(case_dir, "evidence_copies"))
    chain_log_path = os.path.join(case_dir, "chain_log.txt")

    with open(chain_log_path, "w", encoding="utf-8") as log:
        log.write("=====================================\n")
        log.write(f"{APP_NAME} - Chain Log\n")
        log.write(f"Case ID: {safe_case_id}\n")
        log.write(f"Start Time: {now_utc()}\n")
        log.write(f"{APP_AUTHOR}\n")
        log.write("=====================================\n\n")

    return {
        "case_id": safe_case_id,
        "case_dir": case_dir,
        "evidence_dir": evidence_dir,
        "chain_log_path": chain_log_path,
    }


def append_chain_log(chain_log_path, message, index):
    now = datetime.now().strftime("%H:%M:%S")
    with open(chain_log_path, "a", encoding="utf-8") as log:
        log.write(f"[{index}] {now} - {message}\n\n")


def analyze_history(profile_folder, evidence_dir):
    db = os.path.join(profile_folder, "History")
    if not os.path.exists(db):
        return []

    copied = safe_copy_db(db, evidence_dir)
    conn = sqlite3.connect(copied)
    cur = conn.cursor()
    entries = []

    try:
        cur.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 300
        """)
        for url, title, visits, last_visit_time in cur.fetchall():
            entries.append({
                "url": url or "",
                "title": title or "",
                "visits": visits or 0,
                "last_visit": chrome_time_to_str(last_visit_time),
                "category": classify_url(url or "")
            })
    except Exception as e:
        entries.append({"error": str(e)})
    finally:
        conn.close()

    return entries


def analyze_downloads(profile_folder, evidence_dir):
    db = os.path.join(profile_folder, "History")
    if not os.path.exists(db):
        return []

    copied = safe_copy_db(db, evidence_dir)
    conn = sqlite3.connect(copied)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    downloads = []

    try:
        cur.execute("""
            SELECT 
                d.current_path,
                d.target_path,
                d.total_bytes,
                d.mime_type,
                d.start_time,
                d.end_time,
                u.url AS source_url,
                u.referrer AS referrer
            FROM downloads d
            LEFT JOIN downloads_url_chains u ON d.id = u.id AND u.chain_index = 0
            ORDER BY d.start_time DESC
            LIMIT 200
        """)
        for r in cur.fetchall():
            downloads.append({
                "source_url": r["source_url"] or "",
                "referrer": r["referrer"] or "",
                "target_path": r["target_path"] or r["current_path"] or "",
                "total_bytes": r["total_bytes"] or 0,
                "mime_type": r["mime_type"] or "",
                "start_time": chrome_time_to_str(r["start_time"]),
                "end_time": chrome_time_to_str(r["end_time"]),
                "category": classify_url(r["source_url"] or "")
            })
    except sqlite3.OperationalError as e:
        downloads.append({"error": f"Downloads schema unavailable: {str(e)}"})
    except Exception as e:
        downloads.append({"error": str(e)})
    finally:
        conn.close()

    return downloads


def analyze_cookies(profile_folder, evidence_dir):
    db = os.path.join(profile_folder, "Cookies")
    if not os.path.exists(db):
        return []

    copied = safe_copy_db(db, evidence_dir)
    conn = sqlite3.connect(copied)
    cur = conn.cursor()
    cookies = []

    try:
        cur.execute("""
            SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, is_secure
            FROM cookies
            LIMIT 150
        """)
        for host_key, name, value, creation_utc, last_access_utc, expires_utc, is_secure in cur.fetchall():
            cookies.append({
                "host_key": host_key or "",
                "name": name or "",
                "value": value or "",
                "creation_time": chrome_time_to_str(creation_utc),
                "last_access_time": chrome_time_to_str(last_access_utc),
                "expires_time": chrome_time_to_str(expires_utc),
                "is_secure": bool(is_secure)
            })
    except Exception as e:
        cookies.append({"error": str(e)})
    finally:
        conn.close()

    return cookies


def analyze_logins(profile_folder, evidence_dir):
    db = os.path.join(profile_folder, "Login Data")
    if not os.path.exists(db):
        return []

    copied = safe_copy_db(db, evidence_dir)
    conn = sqlite3.connect(copied)
    cur = conn.cursor()
    logins = []

    try:
        cur.execute("""
            SELECT origin_url, username_value, date_created, date_last_used, times_used
            FROM logins
            LIMIT 150
        """)
        for origin_url, username_value, date_created, date_last_used, times_used in cur.fetchall():
            logins.append({
                "origin_url": origin_url or "",
                "username_value": username_value or "",
                "date_created": chrome_time_to_str(date_created),
                "date_last_used": chrome_time_to_str(date_last_used),
                "times_used": times_used or 0
            })
    except Exception as e:
        logins.append({"error": str(e)})
    finally:
        conn.close()

    return logins


def analyze_topsites(profile_folder, evidence_dir):
    db = os.path.join(profile_folder, "Top Sites")
    if not os.path.exists(db):
        return []

    copied = safe_copy_db(db, evidence_dir)
    conn = sqlite3.connect(copied)
    cur = conn.cursor()
    topsites = []

    try:
        for sql in (
            "SELECT url, title FROM top_sites LIMIT 100",
            "SELECT url, title FROM thumbnails LIMIT 100",
        ):
            try:
                cur.execute(sql)
                topsites = [{"url": r[0] or "", "title": r[1] or ""} for r in cur.fetchall()]
                if topsites:
                    break
            except Exception:
                continue
    except Exception as e:
        topsites.append({"error": str(e)})
    finally:
        conn.close()

    return topsites


def analyze_bookmarks(profile_folder):
    path = os.path.join(profile_folder, "Bookmarks")
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        return [{"error": str(e)}]

    bookmarks = []

    def walk(node, folder_name="root"):
        if isinstance(node, dict):
            if node.get("type") == "url":
                bookmarks.append({
                    "name": node.get("name", ""),
                    "url": node.get("url", ""),
                    "date_added": chrome_time_to_str(node.get("date_added")),
                    "folder": folder_name,
                    "category": classify_url(node.get("url", ""))
                })
            for key, value in node.items():
                if key == "children" and isinstance(value, list):
                    for child in value:
                        walk(child, node.get("name", folder_name))
                elif isinstance(value, (dict, list)):
                    walk(value, folder_name)
        elif isinstance(node, list):
            for item in node:
                walk(item, folder_name)

    walk(raw)
    return bookmarks[:300]


def analyze_preferences(profile_folder):
    path = os.path.join(profile_folder, "Preferences")
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        account_info = raw.get("account_info", [])
        download_dir = raw.get("download", {}).get("default_directory", "")
        homepage = raw.get("homepage", "")
        last_clear = raw.get("browser", {}).get("last_clear_browsing_data_time", "")

        return [{
            "homepage": homepage,
            "default_download_directory": download_dir,
            "account_count": len(account_info),
            "profile_name": raw.get("profile", {}).get("name", ""),
            "last_clear_browsing_data_time": chrome_time_to_str(last_clear),
            "translate_enabled": raw.get("translate", {}).get("enabled", ""),
            "dns_prefetching_enabled": raw.get("dns_prefetching", {}).get("enabled", "")
        }]
    except Exception as e:
        return [{"error": str(e)}]


def analyze_webdata(profile_folder, evidence_dir):
    db = os.path.join(profile_folder, "Web Data")
    if not os.path.exists(db):
        return []

    copied = safe_copy_db(db, evidence_dir)
    conn = sqlite3.connect(copied)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = []

    try:
        try:
            cur.execute("""
                SELECT name, value, date_created, date_last_used, count
                FROM autofill
                ORDER BY date_last_used DESC
                LIMIT 120
            """)
            for r in cur.fetchall():
                rows.append({
                    "type": "autofill",
                    "name": r["name"] or "",
                    "value": r["value"] or "",
                    "date_created": chrome_time_to_str(r["date_created"]),
                    "date_last_used": chrome_time_to_str(r["date_last_used"]),
                    "count": r["count"] or 0
                })
        except Exception:
            pass

        try:
            cur.execute("""
                SELECT guid, company_name, street_address, city, state, zipcode, country_code, date_modified
                FROM autofill_profiles
                LIMIT 80
            """)
            for r in cur.fetchall():
                rows.append({
                    "type": "autofill_profile",
                    "guid": r["guid"] or "",
                    "company_name": r["company_name"] or "",
                    "street_address": r["street_address"] or "",
                    "city": r["city"] or "",
                    "state": r["state"] or "",
                    "zipcode": r["zipcode"] or "",
                    "country_code": r["country_code"] or "",
                    "date_modified": chrome_time_to_str(r["date_modified"])
                })
        except Exception:
            pass

    except Exception as e:
        rows.append({"error": str(e)})
    finally:
        conn.close()

    return rows


def analyze_extensions(profile_folder):
    ext_root = os.path.join(profile_folder, "Extensions")
    if not os.path.exists(ext_root):
        return []

    rows = []
    try:
        for ext_id in os.listdir(ext_root):
            ext_dir = os.path.join(ext_root, ext_id)
            if not os.path.isdir(ext_dir):
                continue

            versions = [v for v in os.listdir(ext_dir) if os.path.isdir(os.path.join(ext_dir, v))]
            if not versions:
                rows.append({
                    "extension_id": ext_id,
                    "name": "",
                    "version": "",
                    "description": "",
                    "manifest_version": "",
                    "permissions": "",
                    "update_time": file_time_to_str(os.path.getmtime(ext_dir))
                })
                continue

            versions.sort(reverse=True)
            manifest_path = os.path.join(ext_dir, versions[0], "manifest.json")
            manifest = {}

            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest = json.load(f)
                except Exception:
                    manifest = {}

            perms = manifest.get("permissions", []) or manifest.get("host_permissions", []) or []
            rows.append({
                "extension_id": ext_id,
                "name": manifest.get("name", ""),
                "version": manifest.get("version", versions[0]),
                "description": manifest.get("description", ""),
                "manifest_version": manifest.get("manifest_version", ""),
                "permissions": ", ".join(perms[:10]) if isinstance(perms, list) else str(perms),
                "update_time": file_time_to_str(os.path.getmtime(ext_dir))
            })
    except Exception as e:
        rows.append({"error": str(e)})

    return rows[:200]


def analyze_favicons(profile_folder, evidence_dir):
    db = os.path.join(profile_folder, "Favicons")
    if not os.path.exists(db):
        return []

    copied = safe_copy_db(db, evidence_dir)
    conn = sqlite3.connect(copied)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = []

    try:
        queries = [
            """
            SELECT i.page_url, f.icon_url, b.last_updated, b.width, b.height
            FROM icon_mapping i
            LEFT JOIN favicons f ON i.icon_id = f.id
            LEFT JOIN favicon_bitmaps b ON f.id = b.icon_id
            LIMIT 150
            """,
            "SELECT page_url, icon_url, 0 as last_updated, 0 as width, 0 as height FROM icon_mapping LIMIT 150",
        ]
        for q in queries:
            try:
                cur.execute(q)
                fetched = cur.fetchall()
                if fetched:
                    for r in fetched:
                        rows.append({
                            "page_url": r[0] or "",
                            "icon_url": r[1] or "",
                            "last_updated": chrome_time_to_str(r[2]) if len(r) > 2 else "N/A",
                            "dimensions": f"{r[3]}x{r[4]}" if len(r) > 4 else ""
                        })
                    break
            except Exception:
                continue
    except Exception as e:
        rows.append({"error": str(e)})
    finally:
        conn.close()

    return rows


def analyze_sessions(profile_folder):
    sessions_dir = os.path.join(profile_folder, "Sessions")
    if not os.path.exists(sessions_dir):
        return []

    rows = []
    try:
        for name in os.listdir(sessions_dir):
            full = os.path.join(sessions_dir, name)
            if os.path.isfile(full):
                rows.append({
                    "file_name": name,
                    "size_bytes": os.path.getsize(full),
                    "modified_time": file_time_to_str(os.path.getmtime(full)),
                    "note": "Session metadata captured; deep tab parsing requires Chromium-specific binary parser."
                })
    except Exception as e:
        rows.append({"error": str(e)})

    rows.sort(key=lambda x: x.get("modified_time", ""), reverse=True)
    return rows[:100]


def analyze_local_storage(profile_folder):
    ls_dir = os.path.join(profile_folder, "Local Storage")
    if not os.path.exists(ls_dir):
        return []

    rows = []
    try:
        for root, _, files in os.walk(ls_dir):
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, ls_dir)
                rows.append({
                    "file": rel,
                    "size_bytes": os.path.getsize(full),
                    "modified_time": file_time_to_str(os.path.getmtime(full)),
                    "type": "leveldb/local_storage_metadata"
                })
    except Exception as e:
        rows.append({"error": str(e)})

    rows.sort(key=lambda x: x.get("modified_time", ""), reverse=True)
    return rows[:200]


def build_timeline(data):
    timeline = []

    for item in data.get("history", []):
        if item.get("last_visit") and item.get("last_visit") != "N/A":
            timeline.append({
                "time": item["last_visit"],
                "artifact": "history",
                "event": "Visited URL",
                "details": item.get("url", "")
            })

    for item in data.get("downloads", []):
        if item.get("start_time") and item.get("start_time") != "N/A":
            timeline.append({
                "time": item["start_time"],
                "artifact": "downloads",
                "event": "Download Started",
                "details": item.get("target_path", "") or item.get("source_url", "")
            })

    for item in data.get("cookies", []):
        if item.get("creation_time") and item.get("creation_time") != "N/A":
            timeline.append({
                "time": item["creation_time"],
                "artifact": "cookies",
                "event": "Cookie Created",
                "details": f'{item.get("host_key", "")} | {item.get("name", "")}'
            })

    for item in data.get("logins", []):
        if item.get("date_created") and item.get("date_created") != "N/A":
            timeline.append({
                "time": item["date_created"],
                "artifact": "logins",
                "event": "Login Entry Created",
                "details": f'{item.get("origin_url", "")} | {item.get("username_value", "")}'
            })

    for item in data.get("bookmarks", []):
        if item.get("date_added") and item.get("date_added") != "N/A":
            timeline.append({
                "time": item["date_added"],
                "artifact": "bookmarks",
                "event": "Bookmark Added",
                "details": item.get("url", "")
            })

    for item in data.get("webdata", []):
        if item.get("date_last_used") and item.get("date_last_used") != "N/A":
            timeline.append({
                "time": item["date_last_used"],
                "artifact": "webdata",
                "event": "Autofill Used",
                "details": f'{item.get("name", "")}: {item.get("value", "")}'
            })

    for item in data.get("extensions", []):
        if item.get("update_time") and item.get("update_time") != "N/A":
            timeline.append({
                "time": item["update_time"],
                "artifact": "extensions",
                "event": "Extension Observed",
                "details": item.get("name", "") or item.get("extension_id", "")
            })

    for item in data.get("sessions", []):
        if item.get("modified_time") and item.get("modified_time") != "N/A":
            timeline.append({
                "time": item["modified_time"],
                "artifact": "sessions",
                "event": "Session File Updated",
                "details": item.get("file_name", "")
            })

    for item in data.get("local_storage", []):
        if item.get("modified_time") and item.get("modified_time") != "N/A":
            timeline.append({
                "time": item["modified_time"],
                "artifact": "local_storage",
                "event": "Local Storage File Updated",
                "details": item.get("file", "")
            })

    def timeline_sort_key(x):
        try:
            return datetime.strptime(x["time"], "%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return datetime.min

    timeline.sort(key=timeline_sort_key, reverse=True)
    return timeline


def build_findings(data):
    findings = []

    history = data.get("history", [])
    logins = data.get("logins", [])
    cookies = data.get("cookies", [])
    downloads = data.get("downloads", [])
    bookmarks = data.get("bookmarks", [])
    webdata = data.get("webdata", [])
    extensions = data.get("extensions", [])
    sessions = data.get("sessions", [])
    local_storage = data.get("local_storage", [])

    categories = {}
    for item in history:
        cat = item.get("category", "Other")
        categories[cat] = categories.get(cat, 0) + 1

    if categories:
        top_category = max(categories, key=categories.get)
        findings.append({
            "severity": "Info",
            "title": "Top Browsing Category",
            "details": f"Most observed category in browsing history: {top_category} ({categories[top_category]} entries)."
        })

    if categories.get("Social Media", 0) > 10:
        findings.append({
            "severity": "Notable",
            "title": "High Social Media Activity",
            "details": f"Detected {categories['Social Media']} social media history entries."
        })

    if logins:
        findings.append({
            "severity": "Notable",
            "title": "Stored Login Records Found",
            "details": f"Detected {len(logins)} login records in Chrome Login Data."
        })

    if cookies:
        findings.append({
            "severity": "Info",
            "title": "Cookies Present",
            "details": f"Detected {len(cookies)} cookie entries."
        })

    if downloads:
        findings.append({
            "severity": "Notable",
            "title": "Downloads Detected",
            "details": f"Detected {len(downloads)} download records in Chrome History."
        })

    if bookmarks:
        findings.append({
            "severity": "Info",
            "title": "Bookmarks Present",
            "details": f"Detected {len(bookmarks)} bookmark entries."
        })

    if webdata:
        findings.append({
            "severity": "Sensitive",
            "title": "Autofill / Profile Data Present",
            "details": f"Detected {len(webdata)} Web Data entries that may contain user profile or form information."
        })

    if extensions:
        findings.append({
            "severity": "Notable",
            "title": "Browser Extensions Present",
            "details": f"Detected {len(extensions)} installed extension records."
        })

    if sessions:
        findings.append({
            "severity": "Info",
            "title": "Session Files Present",
            "details": f"Detected {len(sessions)} session metadata files."
        })

    if local_storage:
        findings.append({
            "severity": "Info",
            "title": "Local Storage Present",
            "details": f"Detected {len(local_storage)} local storage files."
        })

    adult_count = categories.get("Adult", 0)
    if adult_count > 0:
        findings.append({
            "severity": "Sensitive",
            "title": "Sensitive Domain Access",
            "details": f"Detected {adult_count} browsing entries categorized as Adult."
        })

    return findings


def generate_rule_based_summary(data, findings):
    lines = [f"{APP_NAME} Investigative Summary", "", "Overview:"]
    for key in [
        "history",
        "downloads",
        "cookies",
        "logins",
        "topsites",
        "bookmarks",
        "preferences",
        "webdata",
        "extensions",
        "favicons",
        "sessions",
        "local_storage",
    ]:
        label = key.replace("_", " ").title()
        lines.append(f"- {label} entries: {len(data.get(key, []))}")

    lines.append("")

    if findings:
        lines.append("Key Findings:")
        for item in findings:
            lines.append(f"- [{item['severity']}] {item['title']}: {item['details']}")
    else:
        lines.append("No significant findings were automatically generated.")

    return "\n".join(lines)


def generate_ai_summary(data, findings, api_key=None):
    if not api_key:
        return generate_rule_based_summary(data, findings)

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        prompt = {
            "counts": {k: len(v) for k, v in data.items()},
            "sample_history": data.get("history", [])[:15],
            "sample_downloads": data.get("downloads", [])[:15],
            "sample_logins": data.get("logins", [])[:15],
            "sample_bookmarks": data.get("bookmarks", [])[:15],
            "sample_webdata": data.get("webdata", [])[:15],
            "sample_extensions": data.get("extensions", [])[:15],
            "findings": findings,
        }

        response = client.responses.create(
            model="gpt-4.1-mini",
            input=[
                {
                    "role": "system",
                    "content": "You are a professional digital forensic analyst. Generate a concise investigative summary based only on the provided browser artifacts. Do not overstate conclusions. Separate factual observations from cautious inferences.",
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt, ensure_ascii=False, indent=2),
                },
            ],
        )

        text = getattr(response, "output_text", None)
        if text:
            return text.strip()

        return generate_rule_based_summary(data, findings)

    except Exception as e:
        return generate_rule_based_summary(data, findings) + f"\n\n[AI Fallback Reason] {str(e)}"


def export_json(case_dir, case_id, data, timeline, findings, summary):
    path = os.path.join(case_dir, f"{case_id}_analysis.json")
    payload = {
        "case_id": case_id,
        "generated_at": now_utc(),
        "data": data,
        "timeline": timeline,
        "findings": findings,
        "summary": summary,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return path


def export_timeline_csv(case_dir, case_id, timeline):
    path = os.path.join(case_dir, f"{case_id}_timeline.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "Artifact", "Event", "Details"])
        for item in timeline:
            writer.writerow([
                item.get("time", ""),
                item.get("artifact", ""),
                item.get("event", ""),
                item.get("details", ""),
            ])
    return path


def export_history_csv(case_dir, case_id, history):
    path = os.path.join(case_dir, f"{case_id}_history.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "URL", "Title", "Visits", "Last Visit"])
        for item in history:
            writer.writerow([
                item.get("category", ""),
                item.get("url", ""),
                item.get("title", ""),
                item.get("visits", ""),
                item.get("last_visit", ""),
            ])
    return path


def export_pdf(case_dir, case_id, data, findings, summary):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ModuleNotFoundError:
        raise RuntimeError("مكتبة reportlab غير مثبتة. ثبّتها بالأمر:\npython -m pip install reportlab")

    path = os.path.join(case_dir, f"{case_id}_report.pdf")
    c = canvas.Canvas(path, pagesize=A4)
    _, height = A4
    y = height - 40

    def new_page():
        nonlocal y
        c.showPage()
        y = height - 40
        c.setFont("Helvetica", 10)

    c.setTitle(f"{APP_NAME} Report - {case_id}")
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, APP_NAME)
    y -= 22

    c.setFont("Helvetica", 11)
    c.drawString(40, y, f"Case ID: {case_id}")
    y -= 16
    c.drawString(40, y, f"Generated: {now_utc()}")
    y -= 16
    c.drawString(40, y, APP_AUTHOR)
    y -= 24

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Artifact Counts")
    y -= 18

    c.setFont("Helvetica", 10)
    for key in [
        "history",
        "downloads",
        "cookies",
        "logins",
        "topsites",
        "bookmarks",
        "preferences",
        "webdata",
        "extensions",
        "favicons",
        "sessions",
        "local_storage",
    ]:
        if y < 60:
            new_page()
        c.drawString(50, y, f"{key.replace('_', ' ').title()}: {len(data.get(key, []))}")
        y -= 14

    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Findings")
    y -= 18
    c.setFont("Helvetica", 10)

    for item in findings:
        line = f"[{item.get('severity', 'Info')}] {item.get('title', '')}: {item.get('details', '')}"
        if y < 60:
            new_page()
        c.drawString(50, y, line[:110])
        y -= 14

    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Investigative Summary")
    y -= 18
    c.setFont("Helvetica", 10)

    for line in summary.splitlines():
        if y < 60:
            new_page()
        c.drawString(50, y, line[:110])
        y -= 14

    c.save()

    hash_path = os.path.join(case_dir, "report_sha256.txt")
    with open(hash_path, "w", encoding="utf-8") as f:
        f.write(generate_sha256(path))

    return path


def run_full_analysis(profile_folder, case_meta, log_callback=None):
    data = {}
    analyzers = [
        ("history", analyze_history, (profile_folder, case_meta["evidence_dir"])),
        ("downloads", analyze_downloads, (profile_folder, case_meta["evidence_dir"])),
        ("cookies", analyze_cookies, (profile_folder, case_meta["evidence_dir"])),
        ("logins", analyze_logins, (profile_folder, case_meta["evidence_dir"])),
        ("topsites", analyze_topsites, (profile_folder, case_meta["evidence_dir"])),
        ("bookmarks", analyze_bookmarks, (profile_folder,)),
        ("preferences", analyze_preferences, (profile_folder,)),
        ("webdata", analyze_webdata, (profile_folder, case_meta["evidence_dir"])),
        ("extensions", analyze_extensions, (profile_folder,)),
        ("favicons", analyze_favicons, (profile_folder, case_meta["evidence_dir"])),
        ("sessions", analyze_sessions, (profile_folder,)),
        ("local_storage", analyze_local_storage, (profile_folder,)),
    ]

    for key, fn, args in analyzers:
        result = fn(*args)
        data[key] = result
        if log_callback:
            log_callback(f"{key.replace('_', ' ').title()} analyzed ({len(result)} entries).")

    timeline = build_timeline(data)
    findings = build_findings(data)
    return data, timeline, findings