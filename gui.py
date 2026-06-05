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
        append_chain_log(self.case_meta["chain_log_path"], msg, self.log_index)
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
            text=f"Digital Forensics & Chrome Evidence Analysis Workspace - AgentRouter / Claude | Model: {AI_MODEL}",
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
            text="OpenAI (GPT-4o) Integration",
            fg="#e2e8f0",
            bg="#162233",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        api_row = tk.Frame(right_card, bg="#162233")
        api_row.pack(fill="x", padx=12, pady=(0, 4))

        # Load OpenAI key first, fallback to legacy key if exists
        saved_key = self.settings.get("openai_api_key", self.settings.get("anthropic_api_key", ""))
        self.api_var = tk.StringVar(value=saved_key)
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

        tk.Label(
            right_card,
            text=f"Base URL: {AI_BASE_URL} | Model: {AI_MODEL}",
            fg="#94a3b8",
            bg="#162233",
            font=("Consolas", 9),
        ).pack(anchor="w", padx=12, pady=(0, 8))

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

        self._button(bar, "Select Chrome Folder", self.select_folder, "#334155").pack(side="left", padx=4)
        self._button(bar, "Configure Keywords", self.configure_keywords, "#475569").pack(side="left", padx=4)
        self._button(bar, "Run Full Analysis", self.analyze_all, "#0f766e").pack(side="left", padx=4)
        self._button(bar, "Generate AI Summary", self.run_ai, "#7c3aed").pack(side="left", padx=4)
        self._button(bar, "Export HTML Report", self.export_html_report, "#2563eb").pack(side="left", padx=4)
        self._button(bar, "Export PDF", self.export_pdf_report, "#b45309").pack(side="left", padx=4)
        self._button(bar, "Export JSON", self.export_json_bundle, "#1d4ed8").pack(side="left", padx=4)
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

        self.evidence_tab = tk.Frame(self.tabs, bg="#162233")
        self.dashboard_tab = tk.Frame(self.tabs, bg="#162233")
        self.summary_tab = tk.Frame(self.tabs, bg="#162233")
        self.timeline_tab = tk.Frame(self.tabs, bg="#162233")
        self.chain_tab = tk.Frame(self.tabs, bg="#162233")

        self.tabs.add(self.evidence_tab, text="Evidence Explorer")
        self.tabs.add(self.dashboard_tab, text="Dashboard (Charts)")
        self.tabs.add(self.summary_tab, text="Analyst Summary")
        self.tabs.add(self.timeline_tab, text="Timeline")
        self.tabs.add(self.chain_tab, text="Chain Log")

        self._build_evidence_tab()
        self._build_dashboard_tab()
        self._build_summary_tab()
        self._build_timeline_tab()
        self._build_chain_tab()

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
            self.timeline_tree.heading(col, text=title)
            self.timeline_tree.column(col, width=width, anchor="w")

        yscroll = ttk.Scrollbar(frame, orient="vertical", command=self.timeline_tree.yview)
        self.timeline_tree.configure(yscrollcommand=yscroll.set)
        self.timeline_tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        self.timeline_tree.tag_configure("suspicious", foreground="#ef4444")

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
        self.settings["openai_api_key"] = key_val
        self.settings["anthropic_api_key"] = key_val  # Keep for backward compatibility
        self.settings["last_case_id"] = self.case_meta["case_id"]
        if self.folder:
            self.settings["last_folder"] = self.folder
        save_settings(self.settings)
        self.log_chain_event("OpenAI API key saved locally.")
        messagebox.showinfo("Saved", "OpenAI API key saved successfully.")

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
        self.progress["value"] += (100 / 12)
        self.root.update_idletasks()

    def _on_analysis_complete(self):
        self.display_data()
        self.display_findings()
        self.display_timeline()
        self.update_stats()
        self.render_charts()
        self.progress["value"] = 100
        self.log_chain_event("Professional V3 analysis completed.")
        messagebox.showinfo("Analysis Complete", "Professional V3 analysis completed successfully.")

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
        self.log_chain_event(f"AI summary requested using {AI_MODEL} (Threaded).")
        
        # Run AI in background
        threading.Thread(target=self._run_ai_thread, args=(api_key,), daemon=True).start()

    def _run_ai_thread(self, api_key):
        try:
            summary = generate_ai_summary(self.data, self.findings, api_key=api_key)
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
            )

    def export_json_bundle(self):
        if not self.data:
            messagebox.showwarning("No Data", "Run analysis first.")
            return

        self.ensure_summary()
        path = export_json(
            self.case_meta["case_dir"],
            self.case_meta["case_id"],
            self.data,
            self.timeline,
            self.findings,
            self.summary,
        )
        self.log_chain_event(f"JSON exported: {path}")
        messagebox.showinfo("Export Complete", f"JSON saved to:\n{path}")

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

        self.ensure_summary()
        try:
            path = export_pdf(
                self.case_meta["case_dir"],
                self.case_meta["case_id"],
                self.data,
                self.findings,
                self.summary,
            )
            self.log_chain_event(f"PDF report exported: {path}")
            messagebox.showinfo("Export Complete", f"PDF report saved to:\n{path}")
        except Exception as e:
            self.log_chain_event(f"PDF export error: {str(e)}")
            messagebox.showerror("PDF Export Error", str(e))

    def export_html_report(self):
        if not self.data:
            messagebox.showwarning("No Data", "Run analysis first.")
            return

        self.ensure_summary()
        try:
            path = export_html(
                self.case_meta["case_dir"],
                self.case_meta["case_id"],
                self.data,
                self.timeline,
                self.findings,
                self.summary,
            )
            self.log_chain_event(f"HTML report exported: {path}")
            messagebox.showinfo("Export Complete", f"HTML report saved to:\n{path}")
        except Exception as e:
            self.log_chain_event(f"HTML export error: {str(e)}")
            messagebox.showerror("HTML Export Error", str(e))