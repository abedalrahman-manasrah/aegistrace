import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
try:
    from PIL import Image, ImageTk
except ImportError:
    Image, ImageTk = None, None
from datetime import datetime

from core import (
    APP_NAME,
    APP_AUTHOR,
    AI_MODEL,
    AI_BASE_URL,
    load_settings,
    save_settings,
    initialize_case,
    append_chain_log,
    run_full_analysis,
    generate_ai_summary,
    export_json,
    export_timeline_csv,
    export_history_csv,
    export_pdf,
    export_html,
    export_xlsx,
    check_keywords,
    get_category_stats,
    get_activity_timeline_stats
)


class ForensicTool:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1550x920")
        self.root.minsize(1300, 800)
        self.root.configure(bg="#0f1720")

        self.settings = load_settings()

        self.case_meta = None
        self.case_id = None
        self.investigator = None
        self.notes = None
        
        self._show_setup_dialog()
        
        if not self.case_id:
            root.destroy()
            return

        self.case_meta = initialize_case(self.case_id, self.investigator, self.notes)
        self.folder = self.settings.get("last_folder")
        self.log_index = 1
        self.data = {}
        self.timeline = []
        self.findings = []
        self.summary = ""
        self._case_a_data = None
        self._case_b_data = None

        self.settings["last_case_id"] = self.case_meta["case_id"]
        save_settings(self.settings)

        self._build_ui()
        self._refresh_case_info()
        self.log_chain_event("AegisTrace interface initialized.")

    def _show_setup_dialog(self):
        """Custom premium setup dialog with multiple fields."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Investigation Setup")
        dialog.geometry("600x650")
        dialog.configure(bg="#0f172a")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 300
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 325
        dialog.geometry(f"+{x}+{y}")

        content = tk.Frame(dialog, bg="#0f172a", padx=50, pady=40)
        content.pack(fill="both", expand=True)

        # Header with icon/logo
        header_frame = tk.Frame(content, bg="#0f172a")
        header_frame.pack(fill="x", pady=(0, 30))
        
        logo_loaded = False
        if ImageTk and Image:
            try:
                logo_path = os.path.join(os.path.dirname(__file__), "aegistrace_logo.png")
                if os.path.exists(logo_path):
                    img = Image.open(logo_path)
                    img = img.resize((64, 64), Image.Resampling.LANCZOS)
                    self.logo_img = ImageTk.PhotoImage(img)
                    tk.Label(header_frame, image=self.logo_img, bg="#0f172a").pack(side="left", padx=(0, 15))
                    logo_loaded = True
            except Exception:
                pass
        
        if not logo_loaded:
            tk.Label(header_frame, text="🕵️", fg="#3b82f6", bg="#0f172a", font=("Segoe UI", 32)).pack(side="left", padx=(0, 15))
            
        title_sub = tk.Frame(header_frame, bg="#0f172a")
        title_sub.pack(side="left")
        tk.Label(title_sub, text="Investigation Setup", fg="#f8fafc", bg="#0f172a", font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(title_sub, text="Configure case parameters and analyst identity", fg="#64748b", bg="#0f172a", font=("Segoe UI", 10)).pack(anchor="w")

        def create_field(label, var, icon=""):
            lbl_frame = tk.Frame(content, bg="#0f172a")
            lbl_frame.pack(fill="x", pady=(15, 5))
            tk.Label(lbl_frame, text=label, fg="#94a3b8", bg="#0f172a", font=("Segoe UI", 9, "bold")).pack(side="left")
            
            f = tk.Frame(content, bg="#1e293b", highlightthickness=1, highlightbackground="#334155")
            f.pack(fill="x", ipady=5)
            e = tk.Entry(f, textvariable=var, bg="#1e293b", fg="#f1f5f9", insertbackground="white", relief="flat", font=("Consolas", 12))
            e.pack(fill="x", padx=15, pady=10)
            return e

        self.setup_name_var = tk.StringVar(value=self.settings.get("last_investigator", "Investigator_01"))
        self.setup_case_var = tk.StringVar(value=self.settings.get("last_case_id", "CASE_2026_01"))
        self.setup_notes_var = tk.StringVar(value="Standard Forensic Analysis")

        create_field("INVESTIGATOR NAME", self.setup_name_var)
        create_field("CASE IDENTIFIER", self.setup_case_var)
        create_field("INVESTIGATION NOTES", self.setup_notes_var)

        def confirm(e=None):
            name = self.setup_name_var.get().strip()
            case = self.setup_case_var.get().strip()
            notes = self.setup_notes_var.get().strip()
            
            if name and case:
                self.investigator = name
                self.case_id = case
                self.notes = notes
                self.settings["last_investigator"] = name
                self.settings["last_case_id"] = case
                save_settings(self.settings)
                dialog.destroy()
            else:
                messagebox.showwarning("Input Required", "Investigator and Case ID are mandatory.")

        btn_frame = tk.Frame(content, bg="#0f172a")
        btn_frame.pack(fill="x", pady=(45, 0))
        self._button(btn_frame, "INITIALIZE WORKSPACE", confirm, "#3b82f6").pack(fill="x")
        
        dialog.bind("<Return>", confirm)
        self.root.wait_window(dialog)

    def log_chain_event(self, msg):
        now = datetime.now().strftime("%H:%M:%S")
        append_chain_log(self.case_meta["chain_log_path"], msg, index=self.log_index, examiner=self.investigator or "Unknown")
        self.log_index += 1
        self.chain_text.insert(tk.END, f"[{now}] {msg}\n")
        self.chain_text.see(tk.END)
        self.status_var.set(msg)

    def _build_ui(self):
        self._build_header()
        self._build_top_controls()
        self._build_action_buttons()
        self._build_main_content()
        self._build_footer()

    def _build_header(self):
        header = tk.Frame(self.root, bg="#111b2b", height=90)
        header.pack(fill="x")
        header.pack_propagate(False)

        left = tk.Frame(header, bg="#111b2b")
        left.pack(side="left", fill="y", padx=18, pady=12)

        tk.Label(
            left,
            text=APP_NAME,
            fg="#7dd3fc",
            bg="#111b2b",
            font=("Segoe UI", 24, "bold"),
        ).pack(anchor="w")

        tk.Label(
            left,
            text=f"Digital Forensics & Chrome Evidence Analysis Workspace - OpenRouter AI | Model: {AI_MODEL}",
            fg="#9fb3c8",
            bg="#111b2b",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 0))

        right = tk.Frame(header, bg="#111b2b")
        right.pack(side="right", fill="y", padx=18, pady=12)

        self.case_info_var = tk.StringVar(value="")
        tk.Label(
            right,
            textvariable=self.case_info_var,
            fg="#dbeafe",
            bg="#111b2b",
            justify="right",
            font=("Consolas", 10),
        ).pack(anchor="e")

    def _build_top_controls(self):
        top = tk.Frame(self.root, bg="#0f1720")
        top.pack(fill="x", padx=18, pady=(16, 8))

        left_card = tk.Frame(
            top,
            bg="#162233",
            bd=0,
            highlightthickness=1,
            highlightbackground="#22344a",
        )
        left_card.pack(side="left", fill="both", expand=True, padx=(0, 8), ipady=8)

        tk.Label(
            left_card,
            text="Evidence Source",
            fg="#e2e8f0",
            bg="#162233",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self.path_var = tk.StringVar(value=self.folder if self.folder else "No Chrome profile selected")
        tk.Label(
            left_card,
            textvariable=self.path_var,
            fg="#aab8c5",
            bg="#162233",
            font=("Consolas", 10),
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        right_card = tk.Frame(
            top,
            bg="#162233",
            bd=0,
            highlightthickness=1,
            highlightbackground="#22344a",
        )
        right_card.pack(side="right", fill="both", expand=True, padx=(8, 0), ipady=8)

        tk.Label(
            right_card,
            text="OpenRouter / OpenAI-Compatible AI Integration",
            fg="#e2e8f0",
            bg="#162233",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        api_row = tk.Frame(right_card, bg="#162233")
        api_row.pack(fill="x", padx=12, pady=(0, 4))

        # Load OpenRouter key first, then fallback to legacy keys if they exist.
        saved_key = self.settings.get(
            "openrouter_api_key",
            self.settings.get("openai_api_key", self.settings.get("anthropic_api_key", ""))
        )
        self.api_var = tk.StringVar(value=saved_key)
        self.ai_model_var = tk.StringVar(value=self.settings.get("ai_model", AI_MODEL))
        self.ai_base_url_var = tk.StringVar(value=self.settings.get("ai_base_url", AI_BASE_URL))
        self.ai_provider_var = tk.StringVar(value=self.settings.get("ai_provider", "openrouter"))
        self.api_entry = tk.Entry(
            api_row,
            textvariable=self.api_var,
            show="*",
            bg="#0f1720",
            fg="white",
            insertbackground="white",
            relief="flat",
            font=("Consolas", 10),
        )
        self.api_entry.pack(side="left", fill="x", expand=True, ipady=7)

        tk.Button(
            api_row,
            text="Save AI Key",
            command=self.save_api_key,
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=14,
            pady=7,
            cursor="hand2",
        ).pack(side="left", padx=(8, 0))

        model_row = tk.Frame(right_card, bg="#162233")
        model_row.pack(fill="x", padx=12, pady=(4, 4))

        tk.Label(model_row, text="Provider:", fg="#94a3b8", bg="#162233", font=("Consolas", 9)).pack(side="left")
        provider_combo = ttk.Combobox(
            model_row,
            textvariable=self.ai_provider_var,
            values=["openrouter", "openai", "anthropic"],
            state="readonly",
            width=12,
            font=("Segoe UI", 9)
        )
        provider_combo.pack(side="left", padx=(6, 10))

        tk.Label(model_row, text="Model:", fg="#94a3b8", bg="#162233", font=("Consolas", 9)).pack(side="left")
        tk.Entry(
            model_row,
            textvariable=self.ai_model_var,
            bg="#0f1720",
            fg="white",
            insertbackground="white",
            relief="flat",
            font=("Consolas", 9),
            width=18,
        ).pack(side="left", padx=(6, 10), ipady=4)

        tk.Label(model_row, text="Base URL:", fg="#94a3b8", bg="#162233", font=("Consolas", 9)).pack(side="left")
        tk.Entry(
            model_row,
            textvariable=self.ai_base_url_var,
            bg="#0f1720",
            fg="white",
            insertbackground="white",
            relief="flat",
            font=("Consolas", 9),
        ).pack(side="left", fill="x", expand=True, padx=(6, 0), ipady=4)

    def _button(self, parent, text, command, color):
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg="white",
            activebackground=color,
            activeforeground="white",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=12,
            cursor="hand2",
            bd=0,
            highlightthickness=0
        )
        
        def on_enter(e):
            btn.config(bg=self._lighten_color(color))
        
        def on_leave(e):
            btn.config(bg=color)
            
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    def _lighten_color(self, hex_color):
        """Simple helper to lighten hex color for hover effect."""
        try:
            hex_color = hex_color.lstrip('#')
            rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            new_rgb = tuple(min(255, int(c * 1.2)) for c in rgb)
            return '#%02x%02x%02x' % new_rgb
        except:
            return hex_color

    def _build_action_buttons(self):
        bar = tk.Frame(self.root, bg="#0f1720")
        bar.pack(fill="x", padx=25, pady=(10, 20))

        # Search Bar
        self.search_frame = tk.Frame(bar, bg="#1e293b", highlightthickness=1, highlightbackground="#334155")
        self.search_frame.pack(side="right", padx=(15, 0), ipady=3)
        
        tk.Label(self.search_frame, text=" 🔍 ", bg="#162233", fg="#3b82f6", font=("Segoe UI", 11)).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(
            self.search_frame, 
            textvariable=self.search_var,
            bg="#162233",
            fg="white",
            insertbackground="white",
            relief="flat",
            font=("Segoe UI", 10),
            width=30
        )
        self.search_entry.pack(side="left", padx=(0, 10), pady=5)
        self.search_entry.bind("<KeyRelease>", lambda e: self.filter_treeview())

        self._button(bar, "Browse", self.select_folder, "#334155").pack(side="left", padx=4)
        self._button(bar, "Configure Keywords", self.configure_keywords, "#475569").pack(side="left", padx=4)
        self._button(bar, "Run Analysis", self.analyze_all, "#0f766e").pack(side="left", padx=4)
        self._button(bar, "Generate AI Summary", self.run_ai, "#7c3aed").pack(side="left", padx=4)
        self._button(bar, "Export HTML Report", self.export_html_report, "#2563eb").pack(side="left", padx=4)
        self._button(bar, "Export PDF", self.export_pdf_report, "#b45309").pack(side="left", padx=4)
        self._button(bar, "Export JSON", self.export_json_bundle, "#1d4ed8").pack(side="left", padx=4)
        self._button(bar, "Export XLSX", self.export_xlsx_report, "#15803d").pack(side="left", padx=4)
        self._button(bar, "Open Report Folder", self.open_report_folder, "#475569").pack(side="left", padx=4)
        self._button(bar, "Export Timeline CSV", self.export_timeline_report, "#475569").pack(side="left", padx=4)
        self._button(bar, "Export History CSV", self.export_history_report, "#475569").pack(side="left", padx=4)

    def _build_main_content(self):
        content = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg="#0f1720")
        content.pack(fill="both", expand=True, padx=18, pady=(0, 12))

        left = tk.Frame(content, bg="#0f1720")
        right = tk.Frame(content, bg="#0f1720")
        content.add(left, stretch="always")
        content.add(right, stretch="always")

        self._build_stats_cards(left)
        self._build_tabs(left)
        self._build_right_panel(right)

    def _build_stats_cards(self, parent):
        cards = tk.Frame(parent, bg="#0f1720")
        cards.pack(fill="x", pady=(0, 10))

        keys = [
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
            "deleted_records",
        ]
        accents = [
            "#1d4ed8",
            "#0369a1",
            "#0f766e",
            "#7c3aed",
            "#b45309",
            "#be185d",
            "#475569",
            "#991b1b",
            "#15803d",
            "#0ea5e9",
            "#7c2d12",
            "#374151",
            "#dc2626",
        ]

        self.stat_vars = {}
        for key, accent in zip(keys, accents):
            var = tk.StringVar(value=f"{key.replace('_', ' ').title()}\n0")
            self.stat_vars[key] = var
            self._stat_card(cards, var, accent).pack(side="left", fill="x", expand=True, padx=2)

    def _stat_card(self, parent, var, accent):
        frame = tk.Frame(parent, bg="#162233", highlightthickness=1, highlightbackground="#22344a")
        tk.Frame(frame, bg=accent, height=5).pack(fill="x")
        tk.Label(
            frame,
            textvariable=var,
            bg="#162233",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            justify="center",
        ).pack(fill="both", expand=True, pady=12)
        return frame

    def _build_tabs(self, parent):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#0f1720", borderwidth=0)
        style.configure("TNotebook.Tab", background="#162233", foreground="white", padding=(14, 8))
        style.map("TNotebook.Tab", background=[("selected", "#22344a")])

        # Modern Progressbar Style
        style.configure(
            "Horizontal.TProgressbar",
            thickness=12,
            background="#3b82f6",
            troughcolor="#0f1720",
            borderwidth=0,
            highlightthickness=0,
        )

        self.tabs = ttk.Notebook(parent)
        self.tabs.pack(fill="both", expand=True)

        self.evidence_tab    = tk.Frame(self.tabs, bg="#162233")
        self.dashboard_tab   = tk.Frame(self.tabs, bg="#162233")
        self.summary_tab     = tk.Frame(self.tabs, bg="#162233")
        self.timeline_tab    = tk.Frame(self.tabs, bg="#162233")
        self.chain_tab       = tk.Frame(self.tabs, bg="#162233")
        self.compare_tab     = tk.Frame(self.tabs, bg="#162233")

        self.tabs.add(self.evidence_tab,  text="Evidence Explorer")
        self.tabs.add(self.dashboard_tab, text="Dashboard (Charts)")
        self.tabs.add(self.summary_tab,   text="Analyst Summary")
        self.tabs.add(self.timeline_tab,  text="Timeline")
        self.tabs.add(self.chain_tab,     text="Chain Log")
        self.tabs.add(self.compare_tab,   text="Case Compare")

        self._build_evidence_tab()
        self._build_dashboard_tab()
        self._build_summary_tab()
        self._build_timeline_tab()
        self._build_chain_tab()
        self._build_compare_tab()

    def _build_evidence_tab(self):
        tree_frame = tk.Frame(self.evidence_tab, bg="#162233")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("section", "field", "value")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        self.tree.heading("section", text="Section")
        self.tree.heading("field", text="Field")
        self.tree.heading("value", text="Value")

        self.tree.column("section", width=140, anchor="w")
        self.tree.column("field", width=200, anchor="w")
        self.tree.column("value", width=620, anchor="w")

        style = ttk.Style()
        style.configure(
            "Treeview",
            background="#0f1720",
            foreground="white",
            fieldbackground="#0f1720",
            rowheight=26,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#22344a",
            foreground="white",
            font=("Segoe UI", 9, "bold"),
        )

        yscroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        self.tree.tag_configure("suspicious", foreground="#ef4444")

    def _build_summary_tab(self):
        self.summary_text = tk.Text(
            self.summary_tab,
            bg="#0f1720",
            fg="white",
            insertbackground="white",
            wrap="word",
            font=("Consolas", 10),
            relief="flat",
        )
        self.summary_text.pack(fill="both", expand=True, padx=10, pady=10)

    def _build_timeline_tab(self):
        frame = tk.Frame(self.timeline_tab, bg="#162233")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("time", "artifact", "event", "details")
        self.timeline_tree = ttk.Treeview(frame, columns=columns, show="headings")

        for col, title, width in [
            ("time", "Time", 170),
            ("artifact", "Artifact", 120),
            ("event", "Event", 170),
            ("details", "Details", 560),
        ]:
            self.timeline_tree.heading(col, text=title, command=lambda c=col: self._sort_timeline(c, False))
            self.timeline_tree.column(col, width=width, anchor="w")

        yscroll = ttk.Scrollbar(frame, orient="vertical", command=self.timeline_tree.yview)
        self.timeline_tree.configure(yscrollcommand=yscroll.set)
        self.timeline_tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        self.timeline_tree.tag_configure("suspicious", foreground="#ef4444")

    def _sort_timeline(self, col, reverse):
        """Sorts the timeline treeview by the clicked column header."""
        l = [(self.timeline_tree.set(k, col), k) for k in self.timeline_tree.get_children("")]
        l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.timeline_tree.move(k, "", index)

        headers_map = {
            "time": "Time",
            "artifact": "Artifact",
            "event": "Event",
            "details": "Details"
        }
        for c_key, c_title in headers_map.items():
            if c_key == col:
                indicator = " ▼" if reverse else " ▲"
                self.timeline_tree.heading(c_key, text=c_title + indicator, command=lambda c=c_key: self._sort_timeline(c, not reverse))
            else:
                self.timeline_tree.heading(c_key, text=c_title, command=lambda c=c_key: self._sort_timeline(c, False))

    def _build_chain_tab(self):
        self.chain_text = tk.Text(
            self.chain_tab,
            bg="#0f1720",
            fg="#d1fae5",
            insertbackground="white",
            wrap="word",
            font=("Consolas", 10),
            relief="flat",
        )
        self.chain_text.pack(fill="both", expand=True, padx=10, pady=10)

    # ------------------------------------------------------------------ #
    # Feature 7 — Case Comparison Tab
    # ------------------------------------------------------------------ #
    def _build_compare_tab(self):
        """Build the Case Comparison tab UI."""
        top = tk.Frame(self.compare_tab, bg="#162233")
        top.pack(fill="x", padx=14, pady=12)

        tk.Label(
            top, text="Case Comparison",
            fg="#7dd3fc", bg="#162233",
            font=("Segoe UI", 14, "bold")
        ).pack(side="left")

        self._button(
            top, "Load Case B JSON",
            self.load_case_b, "#be185d"
        ).pack(side="right", padx=6)

        self._button(
            top, "Load Case A JSON",
            self.load_case_a, "#1d4ed8"
        ).pack(side="right", padx=6)

        self._button(
            top, "Clear",
            self.clear_compare, "#475569"
        ).pack(side="right")

        # Label showing which files are loaded
        self.compare_file_var = tk.StringVar(value="Case A: Current Case | Case B: None Loaded")
        tk.Label(
            self.compare_tab,
            textvariable=self.compare_file_var,
            fg="#94a3b8", bg="#162233",
            font=("Consolas", 9)
        ).pack(anchor="w", padx=14, pady=(0, 6))

        # Counts comparison table
        compare_frame = tk.Frame(self.compare_tab, bg="#162233")
        compare_frame.pack(fill="both", expand=True, padx=14, pady=6)

        cols = ("artifact", "current_case", "compare_case", "diff")
        self.compare_tree = ttk.Treeview(
            compare_frame, columns=cols, show="headings", height=16
        )
        for col, title, width in [
            ("artifact",      "Artifact",          160),
            ("current_case",  "Case A (Current)",  130),
            ("compare_case",  "Case B (Compared)", 130),
            ("diff",          "Δ Difference",      120),
        ]:
            self.compare_tree.heading(col, text=title)
            self.compare_tree.column(col, width=width, anchor="center")

        self.compare_tree.tag_configure("more",  foreground="#4ade80")
        self.compare_tree.tag_configure("less",  foreground="#f87171")
        self.compare_tree.tag_configure("same",  foreground="#94a3b8")

        ys = ttk.Scrollbar(compare_frame, orient="vertical",
                           command=self.compare_tree.yview)
        self.compare_tree.configure(yscrollcommand=ys.set)
        self.compare_tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")

        # Findings comparison side-by-side
        findings_frame = tk.Frame(self.compare_tab, bg="#162233")
        findings_frame.pack(fill="both", expand=True, padx=14, pady=10)

        # Left panel: Case A Findings
        left_f_panel = tk.Frame(findings_frame, bg="#162233")
        left_f_panel.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.case_a_findings_label = tk.Label(
            left_f_panel,
            text="Case A Findings",
            fg="#e2e8f0", bg="#162233",
            font=("Segoe UI", 10, "bold")
        )
        self.case_a_findings_label.pack(anchor="w", pady=(0, 4))
        self.case_a_findings_list = tk.Listbox(
            left_f_panel,
            bg="#0f1720", fg="white",
            selectbackground="#1d4ed8",
            relief="flat", font=("Segoe UI", 9),
            height=7
        )
        self.case_a_findings_list.pack(fill="both", expand=True)

        # Right panel: Case B Findings
        right_f_panel = tk.Frame(findings_frame, bg="#162233")
        right_f_panel.pack(side="right", fill="both", expand=True, padx=(6, 0))
        self.case_b_findings_label = tk.Label(
            right_f_panel,
            text="Case B Findings",
            fg="#e2e8f0", bg="#162233",
            font=("Segoe UI", 10, "bold")
        )
        self.case_b_findings_label.pack(anchor="w", pady=(0, 4))
        self.case_b_findings_list = tk.Listbox(
            right_f_panel,
            bg="#0f1720", fg="white",
            selectbackground="#1d4ed8",
            relief="flat", font=("Segoe UI", 9),
            height=7
        )
        self.case_b_findings_list.pack(fill="both", expand=True)

        # Alias self.compare_findings_list for compatibility
        self.compare_findings_list = self.case_b_findings_list

    def load_case_a(self):
        """Load JSON for Case A."""
        import json as _json
        path = filedialog.askopenfilename(
            title="Select Case A JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = _json.load(f)
            self._case_a_data = bundle
            self._update_compare_label()
            self._refresh_compare_view()
            self.log_chain_event(f"Case A loaded: {path}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    def load_case_b(self):
        """Load JSON for Case B."""
        import json as _json
        path = filedialog.askopenfilename(
            title="Select Case B JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = _json.load(f)
            self._case_b_data = bundle
            self._update_compare_label()
            self._refresh_compare_view()
            self.log_chain_event(f"Case B loaded: {path}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    def load_compare_case(self):
        self.load_case_b()

    def _update_compare_label(self):
        label_text = ""
        if self._case_a_data:
            label_text += f"Case A: {self._case_a_data.get('case_id', 'Unknown')}"
        else:
            label_text += "Case A: Current Case"
            
        label_text += " | "
        
        if self._case_b_data:
            label_text += f"Case B: {self._case_b_data.get('case_id', 'Unknown')}"
        else:
            label_text += "Case B: None Loaded"
        self.compare_file_var.set(label_text)

    def _refresh_compare_view(self):
        """Populate the comparison treeview and listboxes."""
        if self._case_a_data:
            case_a_data = self._case_a_data.get("data", {})
            case_a_findings = self._case_a_data.get("findings", [])
            case_a_name = self._case_a_data.get("case_id", "Case A")
        else:
            case_a_data = self.data or {}
            case_a_findings = self.findings or []
            case_a_name = self.case_meta.get("case_id", "Current Case") if self.case_meta else "Current Case"

        if self._case_b_data:
            case_b_data = self._case_b_data.get("data", {})
            case_b_findings = self._case_b_data.get("findings", [])
            case_b_name = self._case_b_data.get("case_id", "Case B")
        else:
            case_b_data = {}
            case_b_findings = []
            case_b_name = "Compared Case"

        self.compare_tree.heading("current_case", text=case_a_name)
        self.compare_tree.heading("compare_case", text=case_b_name)

        self.compare_tree.delete(*self.compare_tree.get_children())
        for artifact in [
            "history", "downloads", "cookies", "logins", "topsites",
            "bookmarks", "preferences", "webdata", "extensions",
            "favicons", "sessions", "local_storage", "deleted_records"
        ]:
            count_a = len(case_a_data.get(artifact, [])) if isinstance(case_a_data.get(artifact), list) else 0
            count_b = len(case_b_data.get(artifact, [])) if isinstance(case_b_data.get(artifact), list) else 0
            diff = count_a - count_b
            tag = "more" if diff > 0 else ("less" if diff < 0 else "same")
            diff_str = f"+{diff}" if diff > 0 else str(diff)
            self.compare_tree.insert(
                "", "end",
                values=(artifact.replace("_", " ").title(), count_a, count_b, diff_str),
                tags=(tag,)
            )

        self.case_a_findings_label.config(text=f"{case_a_name} Findings")
        self.case_a_findings_list.delete(0, tk.END)
        if not case_a_findings:
            self.case_a_findings_list.insert(tk.END, "No findings.")
        else:
            for f in case_a_findings:
                self.case_a_findings_list.insert(
                    tk.END, f"[{f.get('severity','?')}] {f.get('title','')}"
                )

        self.case_b_findings_label.config(text=f"{case_b_name} Findings")
        self.case_b_findings_list.delete(0, tk.END)
        if not case_b_findings:
            self.case_b_findings_list.insert(tk.END, "No findings.")
        else:
            for f in case_b_findings:
                self.case_b_findings_list.insert(
                    tk.END, f"[{f.get('severity','?')}] {f.get('title','')}"
                )

    def clear_compare(self):
        self._case_a_data = None
        self._case_b_data = None
        self._update_compare_label()
        self.compare_tree.delete(*self.compare_tree.get_children())
        self.case_a_findings_list.delete(0, tk.END)
        self.case_b_findings_list.delete(0, tk.END)

    def _build_right_panel(self, parent):
        frame = tk.Frame(parent, bg="#162233", highlightthickness=1, highlightbackground="#22344a")
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame,
            text="Investigation Findings",
            fg="white",
            bg="#162233",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", padx=12, pady=(12, 6))

        self.findings_list = tk.Listbox(
            frame,
            bg="#0f1720",
            fg="white",
            selectbackground="#1d4ed8",
            selectforeground="white",
            relief="flat",
            font=("Segoe UI", 10),
        )
        self.findings_list.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_footer(self):
        footer = tk.Frame(self.root, bg="#111b2b", height=34)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(
            footer,
            textvariable=self.status_var,
            fg="#cbd5e1",
            bg="#111b2b",
            font=("Segoe UI", 9),
        ).pack(side="left", padx=12)

        self.progress = ttk.Progressbar(
            footer, 
            orient="horizontal", 
            length=400, 
            mode="determinate", 
            style="Horizontal.TProgressbar"
        )
        self.progress.pack(side="left", padx=20)

        tk.Label(
            footer,
            text=APP_AUTHOR,
            fg="#7dd3fc",
            bg="#111b2b",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", padx=12)

    def _refresh_case_info(self):
        if self.case_meta:
            info = f"INVESTIGATOR: {self.case_meta.get('investigator', 'N/A')}\n"
            info += f"CASE ID: {self.case_meta['case_id']}\n"
            info += f"CREATED: {self.case_meta['created_at']}"
            self.case_info_var.set(info)

    def save_api_key(self):
        key_val = self.api_var.get().strip()
        self.settings["openrouter_api_key"] = key_val
        self.settings["ai_model"] = self.ai_model_var.get().strip() or AI_MODEL
        self.settings["ai_base_url"] = self.ai_base_url_var.get().strip() or AI_BASE_URL
        self.settings["ai_provider"] = self.ai_provider_var.get().strip()
        # Keep legacy key names for backward compatibility, but prefer openrouter_api_key.
        self.settings["openai_api_key"] = key_val
        self.settings["last_case_id"] = self.case_meta["case_id"]
        if self.folder:
            self.settings["last_folder"] = self.folder
        save_settings(self.settings)
        self.log_chain_event("AI configuration saved locally.")
        messagebox.showinfo("Saved", "AI configuration saved successfully.")

    def select_folder(self):
        folder = filedialog.askdirectory(title="Select Chrome Profile Folder")
        if not folder:
            return

        self.folder = folder
        self.path_var.set(folder)
        self.settings["last_folder"] = folder
        self.settings["last_case_id"] = self.case_meta["case_id"]
        save_settings(self.settings)
        self.log_chain_event(f"Evidence source selected: {folder}")

    def configure_keywords(self):
        current_keywords = self.settings.get("suspicious_keywords", [
            "vpn", "tor", "crypto", "binance", "hacker", "proxy", "onion", "darkweb", "bypass", "exploit"
        ])
        keywords_str = ", ".join(current_keywords)
        new_keywords = simpledialog.askstring(
            "Configure Keywords",
            "Enter suspicious keywords separated by commas:",
            initialvalue=keywords_str,
            parent=self.root
        )
        if new_keywords is not None:
            keywords_list = [k.strip() for k in new_keywords.split(",") if k.strip()]
            self.settings["suspicious_keywords"] = keywords_list
            save_settings(self.settings)
            self.log_chain_event(f"Suspicious keywords list updated: {len(keywords_list)} terms.")
            messagebox.showinfo("Success", f"Keywords updated successfully:\n{', '.join(keywords_list[:10])}...")

    def analyze_all(self):
        if not self.folder:
            messagebox.showwarning("Missing Folder", "Please select a Chrome profile folder first.")
            return

        self.log_chain_event("Professional V3 full analysis started (Threaded).")
        self.progress["value"] = 0
        
        # Start analysis in a separate thread
        threading.Thread(target=self._run_analysis_thread, daemon=True).start()

    def _run_analysis_thread(self):
        try:
            def progress_callback(msg):
                self.root.after(0, lambda m=msg: self.log_chain_event(m))
                self.root.after(0, self._increment_progress)

            self.data, self.timeline, self.findings = run_full_analysis(
                self.folder,
                self.case_meta,
                log_callback=progress_callback,
            )
            
            # Update UI on completion
            self.root.after(0, self._on_analysis_complete)
        except Exception as e:
            self.root.after(0, lambda err=e: self.log_chain_event(f"Analysis error: {str(err)}"))
            self.root.after(0, lambda err=e: messagebox.showerror("Error", str(err)))

    def _increment_progress(self):
        self.progress["value"] += (100 / 13)
        self.root.update_idletasks()

    def _on_analysis_complete(self):
        self.display_data()
        self.display_findings()
        self.display_timeline()
        self.update_stats()
        self.render_charts()
        self.progress["value"] = 100
        self.log_chain_event("Professional V3 analysis completed.")
        # Feature 6 — Real-time alert popup for sensitive findings
        sensitive = [f for f in self.findings if f.get("severity") == "Sensitive"]
        if sensitive:
            self._show_alert_popup(sensitive)
        else:
            messagebox.showinfo("Analysis Complete", "Professional V3 analysis completed successfully.")

    # ------------------------------------------------------------------ #
    # Feature 6 — Real-time Alert Popup
    # ------------------------------------------------------------------ #
    def _show_alert_popup(self, sensitive_findings):
        """Show a blinking red alert window listing all Sensitive findings."""
        popup = tk.Toplevel(self.root)
        popup.title("⚠ ALERT — Sensitive Findings Detected")
        popup.configure(bg="#1a0000")
        popup.geometry("640x480")
        popup.resizable(True, True)
        popup.transient(self.root)

        # Center
        self.root.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width() // 2) - 320
        py = self.root.winfo_y() + (self.root.winfo_height() // 2) - 240
        popup.geometry(f"+{px}+{py}")

        # Animated border via label background swap
        border = tk.Frame(popup, bg="#dc2626", padx=3, pady=3)
        border.pack(fill="both", expand=True, padx=6, pady=6)
        inner = tk.Frame(border, bg="#1a0000")
        inner.pack(fill="both", expand=True)

        tk.Label(
            inner,
            text="🚨  SENSITIVE FINDINGS DETECTED",
            fg="#ef4444", bg="#1a0000",
            font=("Segoe UI", 15, "bold")
        ).pack(pady=(20, 4))
        tk.Label(
            inner,
            text=f"{len(sensitive_findings)} sensitive artifact(s) require immediate attention.",
            fg="#fca5a5", bg="#1a0000",
            font=("Segoe UI", 10)
        ).pack(pady=(0, 14))

        listbox = tk.Listbox(
            inner, bg="#0f0000", fg="#fca5a5",
            selectbackground="#7f1d1d", font=("Segoe UI", 9),
            relief="flat", bd=0
        )
        for f in sensitive_findings:
            listbox.insert(tk.END, f"  🔴  {f.get('title','')} — {f.get('details','')[:90]}")
        listbox.pack(fill="both", expand=True, padx=16, pady=4)

        btn_row = tk.Frame(inner, bg="#1a0000")
        btn_row.pack(fill="x", padx=16, pady=14)

        def go_findings():
            popup.destroy()
            self.tabs.select(self.chain_tab)   # switch focus to main window

        self._button(btn_row, "View All Findings", go_findings, "#dc2626").pack(side="left")
        self._button(btn_row, "Dismiss", popup.destroy, "#374151").pack(side="right")

        # Blinking border animation
        _blink_colors = ["#dc2626", "#7f1d1d"]
        _blink_state = [0]
        def blink():
            if popup.winfo_exists():
                border.config(bg=_blink_colors[_blink_state[0] % 2])
                _blink_state[0] += 1
                popup.after(700, blink)
        blink()

    def _build_dashboard_tab(self):
        self.charts_scroll = tk.Canvas(self.dashboard_tab, bg="#162233", highlightthickness=0)
        self.charts_scroll.pack(side="left", fill="both", expand=True)
        
        scroll_v = ttk.Scrollbar(self.dashboard_tab, orient="vertical", command=self.charts_scroll.yview)
        scroll_v.pack(side="right", fill="y")
        
        self.charts_scroll.configure(yscrollcommand=scroll_v.set)
        self.charts_frame = tk.Frame(self.charts_scroll, bg="#162233")
        self.charts_scroll.create_window((0, 0), window=self.charts_frame, anchor="nw")
        
        def on_configure(e):
            self.charts_scroll.configure(scrollregion=self.charts_scroll.bbox("all"))
        self.charts_frame.bind("<Configure>", on_configure)

    def render_charts(self):
        # Clear previous charts
        for child in self.charts_frame.winfo_children():
            child.destroy()
            
        if not self.data:
            return

        cat_stats = get_category_stats(self.data)
        timeline_stats = get_activity_timeline_stats(self.timeline)

        plt.style.use('dark_background')

        # 1. Category Pie Chart
        if cat_stats:
            fig1, ax1 = plt.subplots(figsize=(8, 5), dpi=100)
            fig1.patch.set_facecolor('#162233')
            ax1.set_facecolor('#162233')
            
            labels = list(cat_stats.keys())
            sizes = list(cat_stats.values())
            
            ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=plt.cm.Paired.colors)
            ax1.set_title("Browsing Categories Distribution", color='white', fontsize=12, fontweight='bold')
            
            canvas1 = FigureCanvasTkAgg(fig1, master=self.charts_frame)
            canvas1.draw()
            canvas1.get_tk_widget().pack(pady=20, fill="x", expand=True)

        # 2. Activity Timeline Chart
        if timeline_stats:
            fig2, ax2 = plt.subplots(figsize=(8, 4), dpi=100)
            fig2.patch.set_facecolor('#162233')
            ax2.set_facecolor('#162233')
            
            dates = list(timeline_stats.keys())
            counts = list(timeline_stats.values())
            
            ax2.plot(dates, counts, marker='o', color='#3b82f6', linewidth=2)
            ax2.fill_between(dates, counts, color='#3b82f6', alpha=0.3)
            ax2.set_title("Investigation Timeline Density", color='white', fontsize=12, fontweight='bold')
            
            # Limit the number of date ticks to prevent text cluttering and overlapping on the X-axis
            num_dates = len(dates)
            if num_dates > 8:
                indices = [int(i * (num_dates - 1) / 7) for i in range(8)]
                indices = sorted(list(set(indices)))
                ax2.set_xticks(indices)
                ax2.set_xticklabels([dates[idx] for idx in indices], rotation=45, ha='right')
            else:
                ax2.set_xticks(range(num_dates))
                ax2.set_xticklabels(dates, rotation=45, ha='right')
                
            ax2.tick_params(axis='x', colors='white')
            ax2.tick_params(axis='y', colors='white')
            ax2.set_ylabel("Event Count", color='white')
            
            plt.tight_layout()
            
            canvas2 = FigureCanvasTkAgg(fig2, master=self.charts_frame)
            canvas2.draw()
            canvas2.get_tk_widget().pack(pady=20, fill="x", expand=True)

        # Feature 5 — Chart 3: Top 10 visited domains
        history = self.data.get("history", [])
        if history:
            from urllib.parse import urlparse
            from collections import Counter
            domains = Counter()
            for item in history:
                try:
                    netloc = urlparse(item.get("url", "")).netloc.lower()
                    if netloc:
                        domains[netloc] += item.get("visits", 1) or 1
                except Exception:
                    pass
            top_domains = domains.most_common(10)
            if top_domains:
                fig3, ax3 = plt.subplots(figsize=(8, 4), dpi=100)
                fig3.patch.set_facecolor('#162233')
                ax3.set_facecolor('#162233')
                labels3 = [d[0] for d in top_domains]
                counts3 = [d[1] for d in top_domains]
                bars3 = ax3.barh(labels3[::-1], counts3[::-1],
                                 color='#6366f1', edgecolor='none', height=0.6)
                ax3.set_title("Top 10 Most Visited Domains", color='white',
                              fontsize=12, fontweight='bold')
                ax3.tick_params(axis='x', colors='white')
                ax3.tick_params(axis='y', colors='#94a3b8', labelsize=8)
                ax3.set_xlabel("Visit Count", color='white')
                for bar, val in zip(bars3, counts3[::-1]):
                    ax3.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                             str(val), va='center', color='white', fontsize=8)
                plt.tight_layout()
                canvas3 = FigureCanvasTkAgg(fig3, master=self.charts_frame)
                canvas3.draw()
                canvas3.get_tk_widget().pack(pady=20, fill="x", expand=True)

        # Feature 5 — Chart 4: Downloads by file extension
        downloads = self.data.get("downloads", [])
        if downloads:
            import os as _os
            from collections import Counter
            ext_counter = Counter()
            for dl in downloads:
                path = dl.get("target_path", "")
                if path:
                    ext = _os.path.splitext(path)[1].lower() or "(none)"
                    ext_counter[ext] += 1
            top_ext = ext_counter.most_common(12)
            if top_ext:
                fig4, ax4 = plt.subplots(figsize=(8, 3.5), dpi=100)
                fig4.patch.set_facecolor('#162233')
                ax4.set_facecolor('#162233')
                ext_labels = [e[0] for e in top_ext]
                ext_counts = [e[1] for e in top_ext]
                bar_colors = ['#ef4444' if ext in (
                    '.exe','.msi','.bat','.cmd','.ps1','.vbs','.scr',
                    '.jar','.apk','.dll','.zip','.rar','.7z'
                ) else '#10b981' for ext in ext_labels]
                ax4.bar(ext_labels, ext_counts, color=bar_colors, edgecolor='none', width=0.6)
                ax4.set_title("Downloads by File Extension", color='white',
                              fontsize=12, fontweight='bold')
                ax4.tick_params(axis='x', colors='#94a3b8', rotation=30, labelsize=8)
                ax4.tick_params(axis='y', colors='white')
                ax4.set_ylabel("Count", color='white')
                plt.tight_layout()
                canvas4 = FigureCanvasTkAgg(fig4, master=self.charts_frame)
                canvas4.draw()
                canvas4.get_tk_widget().pack(pady=20, fill="x", expand=True)

        # Feature 5 — Chart 5: Activity by hour of day
        if self.timeline:
            from collections import Counter
            hour_counter = Counter()
            for item in self.timeline:
                t = item.get("time", "")
                try:
                    hour = int(t.split(" ")[1].split(":")[0])
                    hour_counter[hour] += 1
                except Exception:
                    pass
            if hour_counter:
                fig5, ax5 = plt.subplots(figsize=(8, 3), dpi=100)
                fig5.patch.set_facecolor('#162233')
                ax5.set_facecolor('#162233')
                hours = list(range(24))
                values = [hour_counter.get(h, 0) for h in hours]
                ax5.bar(hours, values, color='#f59e0b', edgecolor='none', width=0.75)
                ax5.set_title("Activity Heatmap — Hour of Day", color='white',
                              fontsize=12, fontweight='bold')
                ax5.set_xticks(hours)
                ax5.set_xticklabels([f"{h:02d}h" for h in hours],
                                    rotation=45, ha='right', color='#94a3b8', fontsize=7)
                ax5.tick_params(axis='y', colors='white')
                ax5.set_xlabel("Hour (UTC)", color='white')
                ax5.set_ylabel("Events", color='white')
                plt.tight_layout()
                canvas5 = FigureCanvasTkAgg(fig5, master=self.charts_frame)
                canvas5.draw()
                canvas5.get_tk_widget().pack(pady=20, fill="x", expand=True)

        plt.close('all') # Free memory

    def filter_treeview(self):
        query = self.search_var.get().lower()
        self.display_data(query=query)

    def display_data(self, query=None):
        self.tree.delete(*self.tree.get_children())
        for section, items in self.data.items():
            if not items:
                if not query:
                    self.tree.insert("", "end", values=(section, "status", "No entries"))
                continue
            for item in items:
                # Check if query matches any value in the item
                if query:
                    match = False
                    for v in item.values():
                        if query in str(v).lower():
                            match = True
                            break
                    if not match:
                        continue
                
                # Check for keywords for UI highlighting
                tag = ""
                for v in item.values():
                    if check_keywords(str(v)):
                        tag = "suspicious"
                        break
                
                for k, v in item.items():
                    self.tree.insert("", "end", values=(section, k, str(v)), tags=(tag,))

    def run_ai(self):
        if not self.data:
            messagebox.showwarning("No Data", "Run analysis first.")
            return

        api_key = self.api_var.get().strip()
        model = self.ai_model_var.get().strip() or AI_MODEL
        base_url = self.ai_base_url_var.get().strip() or AI_BASE_URL
        provider = self.ai_provider_var.get().strip()
        self.log_chain_event(f"AI summary requested using {model} (Threaded).")

        # Run AI in background
        threading.Thread(target=self._run_ai_thread, args=(api_key, model, base_url, provider), daemon=True).start()

    def _run_ai_thread(self, api_key, model, base_url, provider):
        try:
            summary = generate_ai_summary(
                self.data,
                self.findings,
                api_key=api_key,
                provider=provider,
                model=model,
                base_url=base_url,
            )
            self.root.after(0, lambda s=summary: self._on_ai_complete(s))
        except Exception as e:
            self.root.after(0, lambda err=e: messagebox.showerror("AI Error", str(err)))

    def _on_ai_complete(self, summary):
        self.summary_text.delete("1.0", tk.END)
        self.summary_text.insert(tk.END, summary)
        self.summary = summary
        self.tabs.select(self.summary_tab)
        self.log_chain_event("AI Summary generated successfully.")

    def display_findings(self):
        self.findings_list.delete(0, tk.END)
        if not self.findings:
            self.findings_list.insert(tk.END, "No findings generated.")
            return
        for item in self.findings:
            self.findings_list.insert(tk.END, f"[{item.get('severity', 'Info')}] {item.get('title', '')}")

    def display_timeline(self):
        self.timeline_tree.delete(*self.timeline_tree.get_children())
        for item in self.timeline:
            tag = ""
            for v in item.values():
                if check_keywords(str(v)):
                    tag = "suspicious"
                    break
            self.timeline_tree.insert(
                "",
                "end",
                values=(
                    item.get("time", ""),
                    item.get("artifact", ""),
                    item.get("event", ""),
                    item.get("details", ""),
                ),
                tags=(tag,)
            )

    def update_stats(self):
        for key, var in self.stat_vars.items():
            var.set(f"{key.replace('_', ' ').title()}\n{len(self.data.get(key, []))}")

    def ensure_summary(self):
        if not self.summary:
            self.summary = generate_ai_summary(
                self.data,
                self.findings,
                api_key=self.api_var.get().strip(),
                provider=self.ai_provider_var.get().strip(),
                model=self.ai_model_var.get().strip() or AI_MODEL,
                base_url=self.ai_base_url_var.get().strip() or AI_BASE_URL,
            )
            self.root.after(0, self._update_summary_widget)

    def _update_summary_widget(self):
        self.summary_text.delete("1.0", tk.END)
        self.summary_text.insert(tk.END, self.summary)

    def _run_export_thread(self, export_type):
        try:
            self.ensure_summary()
            
            if export_type == "json":
                path = export_json(
                    self.case_meta["case_dir"],
                    self.case_meta["case_id"],
                    self.data,
                    self.timeline,
                    self.findings,
                    self.summary,
                )
                self.log_chain_event(f"JSON exported: {path}")
                self.root.after(0, lambda: messagebox.showinfo("Export Complete", f"JSON saved to:\n{path}"))
            elif export_type == "pdf":
                path = export_pdf(
                    self.case_meta["case_dir"],
                    self.case_meta["case_id"],
                    self.data,
                    self.findings,
                    self.summary,
                )
                self.log_chain_event(f"PDF report exported: {path}")
                self.root.after(0, lambda: messagebox.showinfo("Export Complete", f"PDF report saved to:\n{path}"))
            elif export_type == "html":
                path = export_html(
                    self.case_meta["case_dir"],
                    self.case_meta["case_id"],
                    self.data,
                    self.timeline,
                    self.findings,
                    self.summary,
                )
                self.log_chain_event(f"HTML report exported: {path}")
                self.root.after(0, lambda: messagebox.showinfo("Export Complete", f"HTML report saved to:\n{path}"))
        except Exception as e:
            self.log_chain_event(f"{export_type.upper()} export error: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror(f"{export_type.upper()} Export Error", str(e)))

    def export_json_bundle(self):
        if not self.data:
            messagebox.showwarning("No Data", "Run analysis first.")
            return

        self.log_chain_event("JSON export started (Threaded).")
        threading.Thread(target=self._run_export_thread, args=("json",), daemon=True).start()

    def export_timeline_report(self):
        if not self.timeline:
            messagebox.showwarning("No Timeline", "Run analysis first.")
            return

        path = export_timeline_csv(
            self.case_meta["case_dir"],
            self.case_meta["case_id"],
            self.timeline,
        )
        self.log_chain_event(f"Timeline CSV exported: {path}")
        messagebox.showinfo("Export Complete", f"Timeline CSV saved to:\n{path}")

    def export_history_report(self):
        history = self.data.get("history", [])
        if not history:
            messagebox.showwarning("No History", "No history data available.")
            return

        path = export_history_csv(
            self.case_meta["case_dir"],
            self.case_meta["case_id"],
            history,
        )
        self.log_chain_event(f"History CSV exported: {path}")
        messagebox.showinfo("Export Complete", f"History CSV saved to:\n{path}")

    def export_pdf_report(self):
        if not self.data:
            messagebox.showwarning("No Data", "Run analysis first.")
            return

        self.log_chain_event("PDF export started (Threaded).")
        threading.Thread(target=self._run_export_thread, args=("pdf",), daemon=True).start()

    def export_html_report(self):
        if not self.data:
            messagebox.showwarning("No Data", "Run analysis first.")
            return

        self.log_chain_event("HTML export started (Threaded).")
        threading.Thread(target=self._run_export_thread, args=("html",), daemon=True).start()

    def export_xlsx_report(self):
        """Feature 8 — Export a colour-coded Excel workbook."""
        if not self.data:
            messagebox.showwarning("No Data", "Run analysis first.")
            return
        try:
            path = export_xlsx(
                self.case_meta["case_dir"],
                self.case_meta["case_id"],
                self.data,
                self.findings,
            )
            self.log_chain_event(f"XLSX report exported: {path}")
            messagebox.showinfo("Export Complete", f"Excel report saved to:\n{path}")
        except ImportError:
            messagebox.showerror(
                "Missing Library",
                "openpyxl is not installed.\nRun:  pip install openpyxl"
            )
        except Exception as e:
            self.log_chain_event(f"XLSX export error: {str(e)}")
            messagebox.showerror("XLSX Export Error", str(e))

    def open_report_folder(self):
        if not self.case_meta or not self.case_meta.get("case_dir"):
            messagebox.showwarning("No Case", "Please run analysis or initialize case first.")
            return
        
        case_dir = self.case_meta["case_dir"]
        import sys
        import subprocess
        try:
            if os.name == 'nt':
                os.startfile(case_dir)
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', case_dir])
            else:
                subprocess.Popen(['xdg-open', case_dir])
            self.log_chain_event(f"Report folder opened: {case_dir}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder:\n{str(e)}")
