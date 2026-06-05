import os
import json
import csv
import sqlite3
import shutil
import hashlib
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

# PDF Imports
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import base64
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.units import inch

def get_logo_base64():
    try:
        logo_path = os.path.join(os.path.dirname(__file__), "aegistrace_logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                return base64.b64encode(f.read()).decode()
    except:
        pass
    return ""

APP_NAME = "AegisTrace"
APP_AUTHOR = "Built by Abed Alrahman Manasrah"
EXPORT_DIR = os.path.join(os.getcwd(), "Forensics_Reports")
SETTINGS_FILE = os.path.join(os.getcwd(), "aegistrace_settings.json")

AI_MODEL = "gpt-4o"
AI_BASE_URL = "https://api.openai.com/v1"

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger("AegisTrace")
SUSPICIOUS_KEYWORDS = ["vpn", "tor", "crypto", "binance", "hacker", "proxy", "onion", "darkweb", "bypass", "exploit"]


def check_keywords(text):
    """Check if any suspicious keyword exists in the text as a whole word."""
    if not text: return False
    text_lower = text.lower()
    
    # Load dynamic keywords from settings if present, fallback to static defaults
    keywords = load_settings().get("suspicious_keywords", SUSPICIOUS_KEYWORDS)
    
    import re
    for kw in keywords:
        kw_clean = kw.strip().lower()
        if not kw_clean:
            continue
        # Use regex with word boundaries (\b) to match whole words only, avoiding false positives like editor or doctor
        pattern = r'\b' + re.escape(kw_clean) + r'\b'
        if re.search(pattern, text_lower):
            return kw.strip()
    return None


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
    
    # Copy associated WAL, Journal, and SHM files if they exist
    for suffix in ["-wal", "-journal", "-shm"]:
        extra_file = original_path + suffix
        if os.path.exists(extra_file):
            try:
                shutil.copy2(extra_file, os.path.join(destination_dir, f"{base_name}_copy{suffix}"))
            except Exception as e:
                logger.warning(f"Could not copy companion database file {extra_file}: {str(e)}")
                
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
        logger.error(f"Error analyzing history: {str(e)}")
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
        # Check if 'referrer' column exists in downloads_url_chains
        cur.execute("PRAGMA table_info(downloads_url_chains)")
        columns = [info[1] for info in cur.fetchall()]
        has_referrer = "referrer" in columns
        
        query = f"""
            SELECT 
                d.current_path,
                d.target_path,
                d.total_bytes,
                d.mime_type,
                d.start_time,
                d.end_time,
                u.url AS source_url,
                { "u.referrer" if has_referrer else "''" } AS referrer
            FROM downloads d
            LEFT JOIN downloads_url_chains u ON d.id = u.id AND u.chain_index = 0
            ORDER BY d.start_time DESC
            LIMIT 200
        """
        cur.execute(query)
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
        logger.warning(f"Downloads schema unavailable: {str(e)}")
        downloads.append({"error": f"Downloads schema unavailable: {str(e)}"})
    except Exception as e:
        logger.error(f"Error analyzing downloads: {str(e)}")
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
        logger.error(f"Error analyzing cookies: {str(e)}")
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
                "password_value": "[ENCRYPTED via DPAPI]",
                "date_created": chrome_time_to_str(date_created),
                "date_last_used": chrome_time_to_str(date_last_used),
                "times_used": times_used or 0
            })
    except Exception as e:
        logger.error(f"Error analyzing logins: {str(e)}")
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
        logger.error(f"Error analyzing topsites: {str(e)}")
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


def get_category_stats(data):
    """Calculate counts for each browsing category."""
    history = data.get("history", [])
    stats = {}
    for item in history:
        cat = item.get("category", "Other")
        stats[cat] = stats.get(cat, 0) + 1
    return stats


def get_activity_timeline_stats(timeline):
    """Count events per day for timeline chart."""
    daily_stats = {}
    for item in timeline:
        time_str = item.get("time")
        if not time_str or time_str == "N/A":
            continue
        try:
            # Format: 2026-05-03 16:45:32 UTC
            date_part = time_str.split(" ")[0]
            daily_stats[date_part] = daily_stats.get(date_part, 0) + 1
        except Exception:
            continue
    
    # Sort by date
    sorted_dates = sorted(daily_stats.keys())
    return {d: daily_stats[d] for d in sorted_dates}


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

    prompt_data = {
        "counts": {k: len(v) for k, v in data.items()},
        "sample_history": data.get("history", [])[:15],
        "sample_downloads": data.get("downloads", [])[:15],
        "sample_logins": data.get("logins", [])[:15],
        "sample_bookmarks": data.get("bookmarks", [])[:15],
        "sample_webdata": data.get("webdata", [])[:15],
        "sample_extensions": data.get("extensions", [])[:15],
        "findings": findings,
    }

    # 1. Try OpenAI client first
    openai_err = None
    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=api_key,
            base_url=AI_BASE_URL
        )

        response = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a professional digital forensic analyst. "
                        "Generate a concise investigative summary based only on the provided browser artifacts. "
                        "Do not overstate conclusions. Separate factual observations from cautious inferences."
                    )
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt_data, ensure_ascii=False, indent=2),
                }
            ],
            max_tokens=1200,
            temperature=0.2,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        openai_err = e
        logger.warning(f"OpenAI analysis failed (will attempt Anthropic fallback): {str(e)}")

    # 2. Fallback to Anthropic Claude client
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1200,
            temperature=0.2,
            system=(
                "You are a professional digital forensic analyst. "
                "Generate a concise investigative summary based only on the provided browser artifacts. "
                "Do not overstate conclusions. Separate factual observations from cautious inferences."
            ),
            messages=[
                {
                    "role": "user",
                    "content": json.dumps(prompt_data, ensure_ascii=False, indent=2),
                }
            ],
        )
        return response.content[0].text.strip()
    except Exception as anth_err:
        logger.error(f"Anthropic fallback analysis failed: {str(anth_err)}")
        # Quietly log both errors but keep the final report summary clean and professional
        logger.error(f"OpenAI error: {str(openai_err)}")
        logger.error(f"Anthropic error: {str(anth_err)}")
        return generate_rule_based_summary(data, findings)


def initialize_case(case_id, investigator="Unknown", notes=""):
    """Create directory structure for a new case and save metadata."""
    base_dir = os.path.join(os.getcwd(), "Cases")
    case_dir = os.path.join(base_dir, case_id)
    evidence_dir = os.path.join(case_dir, "Evidence")
    
    for d in [base_dir, case_dir, evidence_dir]:
        if not os.path.exists(d):
            os.makedirs(d)

    meta = {
        "case_id": case_id,
        "investigator": investigator,
        "notes": notes,
        "created_at": now_utc(),
        "case_dir": case_dir,
        "evidence_dir": evidence_dir,
        "chain_log_path": os.path.join(case_dir, "chain_of_custody.log")
    }
    
    with open(os.path.join(case_dir, "case_info.json"), "w") as f:
        json.dump(meta, f, indent=4)
        
    return meta


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
    path = os.path.join(case_dir, f"{case_id}_report.pdf")
    
    def my_canvas_setup(canvas, doc):
        canvas.saveState()
        # Header
        canvas.setFont('Helvetica-Bold', 8)
        canvas.setStrokeColor(colors.HexColor("#e2e8f0"))
        canvas.line(50, A4[1]-40, A4[0]-50, A4[1]-40)
        canvas.drawRightString(A4[0]-50, A4[1]-35, f"CASE REF: {case_id} | CONFIDENTIAL")
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setStrokeColor(colors.HexColor("#e2e8f0"))
        canvas.line(50, 40, A4[0]-50, 40)
        page_num = canvas.getPageNumber()
        canvas.drawString(50, 30, f"Generated by {APP_NAME} | {now_utc()}")
        canvas.drawRightString(A4[0]-50, 30, f"Page {page_num}")
        canvas.restoreState()

    doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=60, bottomMargin=60)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=28, spaceAfter=10, textColor=colors.HexColor("#1e3a8a"), alignment=1)
    heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontSize=16, spaceBefore=20, spaceAfter=12, textColor=colors.HexColor("#1e293b"), borderPadding=5, leftIndent=0)
    normal_style = styles['Normal']
    normal_style.fontSize = 10
    normal_style.leading = 14
    
    elements = []

    # 1. Title Page
    elements.append(Spacer(1, 1*inch))
    logo_path = os.path.join(os.path.dirname(__file__), "aegistrace_logo.png")
    if os.path.exists(logo_path):
        img = Image(logo_path, 2.5*inch, 2.5*inch)
        img.hAlign = 'CENTER'
        elements.append(img)
    
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph(APP_NAME, title_style))
    elements.append(Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT", ParagraphStyle('Sub', parent=title_style, fontSize=12, textColor=colors.gray, spaceAfter=60, letterSpacing=2)))
    
    case_info_data = [
        ["INVESTIGATION PARAMETERS", ""],
        ["Case Identifier:", case_id],
        ["Lead Investigator:", APP_AUTHOR.replace("Built by ", "")],
        ["Analysis Date:", now_utc()],
        ["Report Status:", "CERTIFIED / FINAL"]
    ]
    t = Table(case_info_data, colWidths=[2*inch, 3*inch])
    t.setStyle(TableStyle([
        ('SPAN', (0,0), (1,0)),
        ('BACKGROUND', (0,0), (1,0), colors.HexColor("#1e3a8a")),
        ('TEXTCOLOR', (0,0), (1,0), colors.white),
        ('FONTNAME', (0,0), (1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (1,0), 10),
        ('TOPPADDING', (0,0), (1,0), 10),
        ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0,1), (0,-1), colors.HexColor("#475569")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('BOTTOMPADDING', (1,1), (-1,-1), 8),
        ('TOPPADDING', (1,1), (-1,-1), 8),
    ]))
    elements.append(t)
    
    elements.append(Spacer(1, 2*inch))
    conf_notice = "<b>LEGAL NOTICE:</b> This document contains sensitive forensic data. Unauthorized access, distribution, or reproduction is strictly prohibited and may be subject to legal action under digital privacy laws."
    elements.append(Paragraph(conf_notice, ParagraphStyle('Conf', fontSize=8, textColor=colors.red, alignment=1)))
    
    elements.append(PageBreak())

    # 2. Executive Summary
    elements.append(Paragraph("1. Executive Summary", heading_style))
    elements.append(Paragraph(summary.replace("\n", "<br/>"), normal_style))
    elements.append(Spacer(1, 20))

    # 3. Artifact Statistics
    elements.append(Paragraph("2. Artifact Collection Evidence Summary", heading_style))
    stats_data = [["Evidence Type", "Identified Artifacts"]]
    for key in [
        "history", "downloads", "cookies", "logins", "topsites", 
        "bookmarks", "preferences", "webdata", "extensions", 
        "favicons", "sessions", "local_storage"
    ]:
        stats_data.append([key.replace('_', ' ').title(), len(data.get(key, []))])
    
    stats_table = Table(stats_data, colWidths=[3.5*inch, 1.5*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 20))

    # Category Distribution Analytics Chart
    chart_path = None
    try:
        import matplotlib.pyplot as plt
        cat_stats = get_category_stats(data)
        if cat_stats:
            plt.style.use('dark_background')
            fig, ax = plt.subplots(figsize=(6, 3), dpi=150)
            fig.patch.set_facecolor('#1e293b')
            ax.set_facecolor('#1e293b')
            
            labels = list(cat_stats.keys())
            sizes = list(cat_stats.values())
            
            # Simple harmonious palette
            colors_list = ['#3b82f6', '#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899']
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors_list[:len(sizes)], 
                   textprops={'fontsize': 7, 'color': 'white'})
            ax.set_title("Browsing Categories Distribution", color='white', fontsize=9, fontweight='bold')
            
            chart_path = os.path.join(case_dir, "temp_category_chart.png")
            plt.tight_layout()
            plt.savefig(chart_path, dpi=150, facecolor='#1e293b', edgecolor='none')
            plt.close()
            
            if os.path.exists(chart_path):
                elements.append(Paragraph("Category Distribution Analytics", ParagraphStyle('ChartTitle', parent=heading_style, fontSize=12, spaceBefore=10, spaceAfter=8)))
                elements.append(Image(chart_path, 4.5*inch, 2.25*inch))
                elements.append(Spacer(1, 15))
    except Exception as chart_err:
        logger.error(f"Failed to generate/embed chart in PDF: {str(chart_err)}")

    # 4. Key Findings
    if findings:
        elements.append(Paragraph("3. Critical Findings & Observations", heading_style))
        findings_data = [["Severity", "Description", "Investigation Detail"]]
        cell_style = ParagraphStyle('FindingsCell', parent=normal_style, fontSize=8, leading=10)
        for f in findings:
            sev = f.get('severity', 'Info')
            sev_color = colors.red if sev == 'Sensitive' else colors.blue
            findings_data.append([
                Paragraph(f"<b>{sev}</b>", ParagraphStyle('Sev', textColor=sev_color, fontSize=9)),
                Paragraph(f.get('title', ''), cell_style),
                Paragraph(f.get('details', ''), cell_style)
            ])
        
        f_table = Table(findings_data, colWidths=[0.8*inch, 1.7*inch, 3*inch])
        f_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(f_table)

    # Build PDF with Header/Footer
    doc.build(elements, onFirstPage=my_canvas_setup, onLaterPages=my_canvas_setup)

    # Clean up temporary chart image
    if chart_path and os.path.exists(chart_path):
        try:
            os.remove(chart_path)
        except Exception:
            pass

    hash_path = os.path.join(case_dir, "report_sha256.txt")
    with open(hash_path, "w", encoding="utf-8") as f:
        f.write(generate_sha256(path))

    return path


def export_html(case_dir, case_id, data, timeline, findings, summary):
    path = os.path.join(case_dir, f"{case_id}_report.html")

    # Group counts
    counts = {k.replace("_", " ").title(): len(v) for k, v in data.items()}

    # Build Navigation
    nav_links = []
    for k in counts.keys():
        nav_links.append(f'<a href="#section-{k.replace(" ", "-")}" class="nav-item flex items-center gap-4 p-4 rounded-xl text-slate-400 font-semibold"><i class="fas fa-folder-open w-5"></i> {k}</a>')
    nav_html = "".join(nav_links)

    # Build Dashboard Cards
    stat_cards = []
    for k, v in counts.items():
        stat_cards.append(f'''
            <div class="glass p-8 rounded-3xl stat-card">
                <div class="text-slate-500 text-xs font-bold mb-2 uppercase tracking-[0.2em]">{k}</div>
                <div class="text-4xl font-black text-white">{v}</div>
            </div>
        ''')
    dashboard_html = "".join(stat_cards)

    # Build Findings
    findings_html_list = []
    for f in findings:
        severity = f.get("severity", "Info")
        border_color = "border-amber-500/50" if severity == "Sensitive" else "border-blue-500/50"
        bg_color = "bg-amber-500/5" if severity == "Sensitive" else "bg-blue-500/5"
        icon = "<i class='fas fa-triangle-exclamation text-amber-500'></i>" if severity == "Sensitive" else "<i class='fas fa-circle-info text-blue-500'></i>"
        
        findings_html_list.append(f'''
            <div class="glass {bg_color} p-6 rounded-2xl border-l-4 {border_color} flex items-start gap-5">
                <div class="mt-1 text-xl">{icon}</div>
                <div>
                    <div class="font-bold text-lg text-white mb-1">{f.get("title")}</div>
                    <div class="text-slate-400 text-sm leading-relaxed">{f.get("details")}</div>
                    <div class="inline-block px-2 py-1 rounded-md bg-slate-800 text-[10px] mt-3 uppercase font-black tracking-widest text-slate-500">SEVERITY: {severity}</div>
                </div>
            </div>
        ''')
    findings_html = "".join(findings_html_list)

    # Build Timeline Rows
    timeline_rows = []
    for t in timeline:
        timeline_rows.append(f"<tr><td>{t.get('time')}</td><td>{t.get('artifact')}</td><td>{t.get('event')}</td><td>{t.get('details')}</td></tr>")
    timeline_html = "".join(timeline_rows)

    # Build Sections
    sections_list = []
    for k, count in counts.items():
        key_raw = k.lower().replace(" ", "_")
        artifact_data = data.get(key_raw, [])
        
        if artifact_data and isinstance(artifact_data[0], dict):
            # Collect all unique keys across all dictionaries to handle different schemas safely
            all_keys = []
            for row in artifact_data:
                if isinstance(row, dict):
                    for k in row.keys():
                        if k not in all_keys:
                            all_keys.append(k)
            
            header_html = "".join([f"<th>{c.replace('_', ' ').title()}</th>" for c in all_keys])
            body_rows = []
            for row in artifact_data:
                if not isinstance(row, dict): continue
                is_suspicious = any(check_keywords(str(val)) for val in row.values())
                row_style = "style='background: rgba(239, 68, 68, 0.05); color: #fca5a5;'" if is_suspicious else ""
                
                cells_list = []
                for k in all_keys:
                    val = row.get(k, "")
                    val_str = str(val)
                    if len(val_str) > 100 and (val_str.startswith("http://") or val_str.startswith("https://")):
                        cells_list.append(f"<td><a href='{val_str}' target='_blank' class='text-blue-400 hover:underline' title='{val_str}'>{val_str[:60]}...</a></td>")
                    elif len(val_str) > 150:
                        cells_list.append(f"<td title='{val_str}'>{val_str[:120]}...</td>")
                    else:
                        cells_list.append(f"<td>{val_str}</td>")
                cells = "".join(cells_list)
                body_rows.append(f"<tr {row_style}>{cells}</tr>")
            body_html = "".join(body_rows)
        else:
            header_html = "<th>Status</th>"
            body_html = "<tr><td>No data available or error occurred</td></tr>"

        sections_list.append(f'''
        <div id="section-{k.replace(" ", "-")}" class="glass rounded-3xl p-8 mb-12">
            <div class="flex items-center justify-between mb-8">
                <h3 class="text-2xl font-bold flex items-center gap-3">
                    <i class="fas fa-layer-group text-blue-500"></i> {k} Artifacts
                </h3>
                <span class="text-xs font-bold text-slate-500 bg-slate-800 px-3 py-1 rounded-full uppercase tracking-widest">Count: {count}</span>
            </div>
            <div class="overflow-x-auto">
                <table class="display artifact-table w-full">
                    <thead><tr>{header_html}</tr></thead>
                    <tbody>{body_html}</tbody>
                </table>
            </div>
        </div>
        ''')
    sections_html = "".join(sections_list)

    # Final Assembly
    logo_b64 = get_logo_base64()
    logo_src = f"data:image/png;base64,{logo_b64}" if logo_b64 else "https://cdn-icons-png.flaticon.com/512/9439/9439311.png"
    
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{APP_NAME} - {case_id}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
        
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --accent-blue: #3b82f6;
            --text-main: #f1f5f9;
            --text-dim: #94a3b8;
            --border-color: #334155;
        }}

        body {{
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            overflow-x: hidden;
        }}

        .glass {{
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(51, 65, 85, 0.5);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        }}

        .sidebar {{
            width: 300px;
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            background: #020617;
            border-right: 1px solid var(--border-color);
            z-index: 100;
        }}

        .main-content {{
            margin-left: 300px;
            padding: 4rem;
            min-height: 100vh;
        }}

        .stat-card {{
            border-bottom: 4px solid var(--accent-blue);
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        .stat-card:hover {{
            transform: translateY(-8px);
            background: #1e293b;
        }}

        /* Custom DataTables Styling - STRICT DARK MODE */
        .dataTables_wrapper {{
            color: var(--text-main) !important;
            padding: 2rem;
            background: rgba(15, 23, 42, 0.5);
            border-radius: 1.5rem;
            border: 1px solid var(--border-color);
        }}
        table.dataTable {{
            background-color: #1e293b !important;
            border-collapse: collapse !important;
            margin-top: 20px !important;
            border-radius: 1rem;
            overflow: hidden;
        }}
        table.dataTable thead th {{
            background: #0f172a !important;
            color: #3b82f6 !important;
            font-weight: 700 !important;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-size: 0.75rem;
            padding: 18px 15px !important;
            border-bottom: 2px solid var(--accent-blue) !important;
        }}
        table.dataTable tbody tr {{
            background-color: #1e293b !important;
            color: #f1f5f9 !important;
        }}
        table.dataTable tbody td {{
            padding: 14px 15px !important;
            border-bottom: 1px solid #334155 !important;
            background-color: transparent !important;
            color: inherit !important;
            word-break: break-all !important;
            white-space: normal !important;
        }}
        
        /* FORCE DISABLE DataTables striped rows */
        table.dataTable.display tbody tr.odd,
        table.dataTable.display tbody tr.even,
        table.dataTable.display tbody tr.odd > .sorting_1,
        table.dataTable.display tbody tr.even > .sorting_1 {{
            background-color: #1e293b !important;
            color: #f1f5f9 !important;
        }}

        table.dataTable tbody tr:hover,
        table.dataTable.display tbody tr.odd:hover,
        table.dataTable.display tbody tr.even:hover {{
            background-color: #334155 !important;
        }}
        
        .dataTables_info, .dataTables_paginate {{
            color: var(--text-dim) !important;
            margin-top: 15px;
        }}

        .dataTables_filter input, .dataTables_length select {{
            background: #0f172a !important;
            border: 1px solid var(--border-color) !important;
            color: white !important;
            padding: 8px 12px !important;
            border-radius: 10px !important;
            outline: none;
        }}
        .dataTables_length select option {{
            background: #0f172a;
            color: white;
        }}
        
        .nav-item {{
            transition: all 0.3s;
            position: relative;
        }}
        .nav-item:hover {{
            background: linear-gradient(90deg, rgba(59, 130, 246, 0.1) 0%, rgba(59, 130, 246, 0) 100%);
            color: #3b82f6;
        }}
        .nav-item:hover::before {{
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 4px;
            background: #3b82f6;
        }}

        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: #0f172a; }}
        ::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 10px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #475569; }}
    </style>
</head>
<body>
    <div class="sidebar flex flex-col">
        <div class="p-10 border-b border-slate-800/50">
            <div class="flex items-center gap-3">
                <div class="w-12 h-12 bg-slate-900 rounded-xl flex items-center justify-center shadow-lg border border-blue-500/30 overflow-hidden">
                    <img src="{logo_src}" class="w-10 h-10 object-contain">
                </div>
                <h1 class="text-2xl font-black text-white tracking-tight">AegisTrace</h1>
            </div>
            <p class="text-[10px] text-blue-500 mt-2 font-bold uppercase tracking-[0.2em]">Digital Forensics Suite</p>
        </div>
        <nav class="flex-1 overflow-y-auto p-6 space-y-2">
            <div class="px-4 py-4 text-[11px] font-black text-slate-600 uppercase tracking-widest">Navigation</div>
            <a href="#dashboard" class="nav-item flex items-center gap-4 p-4 rounded-xl text-slate-400 font-semibold">
                <i class="fas fa-chart-pie w-5"></i> Overview
            </a>
            <a href="#timeline" class="nav-item flex items-center gap-4 p-4 rounded-xl text-slate-400 font-semibold">
                <i class="fas fa-clock-rotate-left w-5"></i> Timeline
            </a>
            <a href="#findings" class="nav-item flex items-center gap-4 p-4 rounded-xl text-slate-400 font-semibold">
                <i class="fas fa-shield-virus w-5"></i> Threat Findings
            </a>
            
            <div class="px-4 py-6 text-[11px] font-black text-slate-600 uppercase tracking-widest">Evidence Units</div>
            {nav_html}
        </nav>
        <div class="p-8 border-t border-slate-800/50">
            <div class="bg-slate-900/50 p-4 rounded-xl">
                <p class="text-[10px] text-slate-500 font-bold uppercase mb-1">Case Auth Token</p>
                <p class="text-[11px] text-blue-400 font-mono truncate">{case_id}</p>
            </div>
        </div>
    </div>

    <div class="main-content">
        <!-- Modern Header -->
        <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-16 gap-6">
            <div>
                <nav class="flex mb-4 text-sm font-medium text-slate-500 gap-2">
                    <span>Reports</span> <i class="fas fa-chevron-right text-[10px] mt-1"></i> <span>{case_id}</span>
                </nav>
                <h2 class="text-5xl font-black text-white tracking-tighter mb-3">Forensic Intelligence Report</h2>
                <div class="flex items-center gap-4 text-slate-400">
                    <span class="flex items-center gap-2"><i class="fas fa-user-secret text-blue-500"></i> {APP_AUTHOR.replace("Built by ", "")}</span>
                    <span class="w-1 h-1 bg-slate-700 rounded-full"></span>
                    <span class="flex items-center gap-2"><i class="fas fa-calendar-check text-blue-500"></i> {now_utc()}</span>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <div class="glass p-5 rounded-2xl border-l-4 border-blue-500">
                    <p class="text-[10px] font-bold text-slate-500 uppercase mb-1">Investigation Status</p>
                    <div class="flex items-center gap-2">
                        <div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                        <span class="text-white font-bold tracking-wide">VERIFIED & COMPLETE</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Dashboard Stats -->
        <div id="dashboard" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
            {dashboard_html}
        </div>

        <!-- Analytical Insights -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
            <div class="lg:col-span-1 glass p-10 rounded-3xl">
                <h3 class="text-xl font-bold mb-8 flex items-center gap-3">
                    <i class="fas fa-chart-pie text-blue-500"></i> Usage Analytics
                </h3>
                <div class="h-64">
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
            <div class="lg:col-span-2 glass p-10 rounded-3xl relative overflow-hidden">
                <div class="absolute -right-10 -bottom-10 opacity-[0.03] rotate-12">
                    <i class="fas fa-brain text-[15rem]"></i>
                </div>
                <h3 class="text-2xl font-bold mb-6 flex items-center gap-3 text-blue-500">
                    <i class="fas fa-wand-magic-sparkles"></i> AI Analyst Intelligence Summary
                </h3>
                <div class="text-slate-300 leading-relaxed text-lg whitespace-pre-wrap font-medium relative z-10">
                    {summary}
                </div>
            </div>
        </div>

        <!-- Critical Findings -->
        <div id="findings" class="mb-20">
            <h3 class="text-2xl font-bold mb-8 flex items-center gap-3 text-white">
                <i class="fas fa-bolt-lightning text-amber-500"></i> Identified Artifact Anomalies
            </h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                {findings_html}
            </div>
        </div>

        <!-- Timeline Section -->
        <div id="timeline" class="mb-20">
            <div class="flex items-center justify-between mb-8">
                <h3 class="text-2xl font-bold flex items-center gap-3">
                    <i class="fas fa-list-check text-blue-500"></i> Master Event Chronology
                </h3>
                <span class="px-4 py-1 bg-blue-500/10 text-blue-400 text-xs font-bold rounded-full border border-blue-500/20">GLOBAL SORT: DESCENDING</span>
            </div>
            <div class="overflow-hidden">
                <table id="timelineTable" class="display">
                    <thead>
                        <tr>
                            <th>Time Index</th>
                            <th>Evidence Source</th>
                            <th>Activity Type</th>
                            <th>Event Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {timeline_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Data Deep-Dive -->
        <div class="artifact-section space-y-12">
            <div class="flex flex-col items-center">
                <div class="h-px w-24 bg-blue-500/30 mb-4"></div>
                <h3 class="text-sm font-black text-slate-500 uppercase tracking-[0.4em]">Artifact Deep-Dive</h3>
            </div>
            {sections_html}
        </div>
        
        <footer class="mt-24 pt-12 border-t border-slate-800/50 text-center">
            <p class="text-slate-500 text-xs font-medium">This report is cryptographically signed and verified by AegisTrace DFIR Pro.</p>
            <p class="text-slate-600 text-[10px] mt-2 font-mono uppercase tracking-widest">© 2026 {APP_AUTHOR} | CASE: {case_id}</p>
        </footer>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.js"></script>
    <script>
        $(document).ready( function () {{
            $('#timelineTable').DataTable({{
                "order": [[ 0, "desc" ]],
                "pageLength": 25,
                "responsive": true,
                "stripeClasses": []
            }});
            $('.artifact-table').DataTable({{
                "pageLength": 15,
                "responsive": true,
                "stripeClasses": []
            }});

            const ctx = document.getElementById('categoryChart').getContext('2d');
            const historyData = {json.dumps(data.get("history", []))};
            const catCounts = {{}};
            historyData.forEach(item => {{
                const cat = item.category || 'Other';
                catCounts[cat] = (catCounts[cat] || 0) + 1;
            }});

            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: Object.keys(catCounts),
                    datasets: [{{
                        data: Object.values(catCounts),
                        backgroundColor: [
                            '#3b82f6', '#6366f1', '#10b981', '#f59e0b', 
                            '#ef4444', '#8b5cf6', '#ec4899'
                        ],
                        borderWidth: 0,
                        hoverOffset: 20
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '70%',
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{ 
                                color: '#94a3b8', 
                                font: {{ family: 'Outfit', size: 11, weight: '600' }},
                                padding: 20,
                                usePointStyle: true
                            }}
                        }}
                    }}
                }}
            }});
        }});
    </script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_template)

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
        try:
            result = fn(*args)
            data[key] = result
            if log_callback:
                log_callback(f"{key.replace('_', ' ').title()} analyzed ({len(result)} entries).")
        except Exception as e:
            logger.error(f"Top-level analysis failure for {key}: {str(e)}")
            data[key] = [{"error": str(e)}]

    timeline = build_timeline(data)
    findings = build_findings(data)

    # 4. Keyword Detection for Findings
    seen_findings = set()
    kw_match_count = 0
    max_kw_findings = 10
    
    for k_type, items in data.items():
        if not isinstance(items, list): continue
        for item in items:
            if not isinstance(item, dict): continue
            for val in item.values():
                if isinstance(val, str):
                    kw = check_keywords(val)
                    if kw:
                        # Clean details slightly for de-duplication mapping
                        details_snippet = val[:100].strip()
                        finding_key = (kw, k_type, details_snippet)
                        if finding_key not in seen_findings:
                            seen_findings.add(finding_key)
                            kw_match_count += 1
                            if kw_match_count <= max_kw_findings:
                                findings.append({
                                    "title": f"Suspicious Activity Detected: '{kw}'",
                                    "details": f"Found term '{kw}' in {k_type} artifact: {details_snippet}...",
                                    "severity": "Sensitive"
                                })
                        break 
                        
    if kw_match_count > max_kw_findings:
        findings.append({
            "title": "Additional Keyword Matches Omitted",
            "details": f"Detected {kw_match_count - max_kw_findings} other unique keyword match occurrences. Refer to detailed artifact sheets and CSVs for full listings.",
            "severity": "Notable"
        }) 

    return data, timeline, findings
