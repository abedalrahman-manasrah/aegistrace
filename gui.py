import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from datetime import datetime

from core import (
    APP_NAME,
    APP_AUTHOR,
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
)


class ForensicTool:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1550x920")
        self.root.minsize(1300, 800)
        self.root.configure(bg="#0f1720")

        self.settings = load_settings()

        new_case = simpledialog.askstring("New Case", "Enter New Case Name / Number:")
        if new_case and new_case.strip():
            self.case_id = new_case.strip()
        else:
            self.case_id = self.settings.get("last_case_id", "Case_Unknown")

        self.case_meta = initialize_case(self.case_id)
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
        self.log_chain_event("Professional V3 interface initialized.")

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
            text="Digital Forensics & Chrome Evidence Analysis Workspace - Professional V3",
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
            text="AI Integration",
            fg="#e2e8f0",
            bg="#162233",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        api_row = tk.Frame(right_card, bg="#162233")
        api_row.pack(fill="x", padx=12, pady=(0, 8))

        self.api_var = tk.StringVar(value=self.settings.get("openai_api_key", ""))
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

    def _button(self, parent, text, command, color):
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg="white",
            activebackground=color,
            activeforeground="white",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=14,
            pady=10,
            cursor="hand2",
            bd=0,
        )

    def _build_action_buttons(self):
        bar = tk.Frame(self.root, bg="#0f1720")
        bar.pack(fill="x", padx=18, pady=(4, 10))

        self._button(bar, "Select Chrome Folder", self.select_folder, "#334155").pack(side="left", padx=4)
        self._button(bar, "Run Full Analysis", self.analyze_all, "#0f766e").pack(side="left", padx=4)
        self._button(bar, "Generate AI Summary", self.run_ai, "#7c3aed").pack(side="left", padx=4)
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

        self.tabs = ttk.Notebook(parent)
        self.tabs.pack(fill="both", expand=True)

        self.evidence_tab = tk.Frame(self.tabs, bg="#162233")
        self.summary_tab = tk.Frame(self.tabs, bg="#162233")
        self.timeline_tab = tk.Frame(self.tabs, bg="#162233")
        self.chain_tab = tk.Frame(self.tabs, bg="#162233")

        self.tabs.add(self.evidence_tab, text="Evidence Explorer")
        self.tabs.add(self.summary_tab, text="Analyst Summary")
        self.tabs.add(self.timeline_tab, text="Timeline")
        self.tabs.add(self.chain_tab, text="Chain Log")

        self._build_evidence_tab()
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

        tk.Label(
            footer,
            text=APP_AUTHOR,
            fg="#7dd3fc",
            bg="#111b2b",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", padx=12)

    def _refresh_case_info(self):
        self.case_info_var.set(
            f"Case ID: {self.case_meta['case_id']}\n"
            f"UTC: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Output: {self.case_meta['case_dir']}"
        )

    def save_api_key(self):
        self.settings["openai_api_key"] = self.api_var.get().strip()
        self.settings["last_case_id"] = self.case_meta["case_id"]
        if self.folder:
            self.settings["last_folder"] = self.folder
        save_settings(self.settings)
        self.log_chain_event("AI API key saved locally.")
        messagebox.showinfo("Saved", "AI API key saved successfully.")

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

    def analyze_all(self):
        if not self.folder:
            messagebox.showwarning("Missing Folder", "Please select a Chrome profile folder first.")
            return

        self.log_chain_event("Professional V3 full analysis started.")
        try:
            self.data, self.timeline, self.findings = run_full_analysis(
                self.folder,
                self.case_meta,
                log_callback=self.log_chain_event,
            )
            self.display_data()
            self.display_findings()
            self.display_timeline()
            self.update_stats()
            self.log_chain_event("Professional V3 analysis completed.")
            messagebox.showinfo("Analysis Complete", "Professional V3 analysis completed successfully.")
        except Exception as e:
            self.log_chain_event(f"Analysis error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def run_ai(self):
        if not self.data:
            messagebox.showwarning("No Data", "Run analysis first.")
            return

        api_key = self.api_var.get().strip()
        self.log_chain_event("AI summary requested.")
        summary = generate_ai_summary(self.data, self.findings, api_key=api_key)

        self.summary_text.delete("1.0", tk.END)
        self.summary_text.insert(tk.END, summary)
        self.summary = summary
        self.tabs.select(self.summary_tab)

        self.log_chain_event("Summary generated.")

    def display_data(self):
        self.tree.delete(*self.tree.get_children())
        for section, items in self.data.items():
            if not items:
                self.tree.insert("", "end", values=(section, "status", "No entries"))
                continue
            for item in items:
                for k, v in item.items():
                    self.tree.insert("", "end", values=(section, k, str(v)))

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
            self.timeline_tree.insert(
                "",
                "end",
                values=(
                    item.get("time", ""),
                    item.get("artifact", ""),
                    item.get("event", ""),
                    item.get("details", ""),
                ),
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