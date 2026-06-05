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
    for k_type, items in data.items():
        if not isinstance(items, list): continue
        for item in items:
            if not isinstance(item, dict): continue
            for val in item.values():
                if isinstance(val, str):
                    kw = check_keywords(val)
                    if kw:
                        findings.append({
                            "title": f"Suspicious Activity Detected: '{kw}'",
                            "details": f"Found term '{kw}' in {k_type} artifact: {val[:100]}...",
                            "severity": "Sensitive"
                        })
                        break 

    return data, timeline, findings
