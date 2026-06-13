# main.py - entry point for the password strength analyzer

import os
import json
import threading
import importlib
from datetime import datetime

from models   import User, Admin
from analyzer import (Password, PasswordAnalyzer, VulnerabilityScanner,
                      PasswordGenerator, EmptyPasswordError,
                      WeakPasswordError, InvalidPasswordFormatError)
from reports  import SecurityReport, ReportGenerationError
from crack_time import CrackTimeEstimator




class PasswordStrengthSystem:


    DATA_FILE = "data/system_data.json"

    def __init__(self):
        self.users            = {}
        self.analysis_records = []
        self.reports          = []

        self.__analyzer  = PasswordAnalyzer()
        self.__scanner   = VulnerabilityScanner("data/common_passwords.txt")
        self.__generator = PasswordGenerator()

        self.load_data()

    def analyze_password(
        self,
        password_text: str,
        user: User = None,
        mode: str = Password.MODE_MIXED,
    ) -> dict:

        pwd      = Password(password_text)
        checks   = self.__analyzer.check_complexity(pwd)
        entropy  = self.__analyzer.calculate_entropy(pwd)
        patterns = self.__analyzer.detect_patterns(password_text)
        issues   = self.__scanner.scan_password(pwd, patterns)
        extra    = self.__scanner.detect_common_patterns(password_text)
        issues  += [f"Format issue: {e}" for e in extra]


        score = self.__analyzer.compute_final_score(pwd, issues, entropy, mode)
        level = pwd.calculate_strength(score)


        estimator   = CrackTimeEstimator(entropy)
        crack_times = estimator.estimate_all()
        crack_ref   = crack_times.get("Offline MD5 (10B/s)", {}).get("human_readable", "—")

        record = {
            "password_masked": '*' * len(password_text),
            "score":           score,
            "level":           level,
            "entropy":         entropy,
            "crack_ref":       crack_ref,
            "crack_times":     crack_times,
            "issues":          issues,
            "checks":          checks,
            "mode":            mode,
            "date":            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        self.analysis_records.append(record)
        if user:
            user.add_to_history(record)

        return record

    def generate_strong_password(self, length: int = 16) -> str:
        return self.__generator.generate_password(length)

    def generate_reports(self) -> str:
        if not self.analysis_records:
            return ""
        report_id = datetime.now().strftime("%Y%m%d%H%M%S")
        report    = SecurityReport(report_id, self.analysis_records)
        paths     = report.export_report("reports")
        self.reports.append({"id": report_id, "date": report.report_date, "paths": paths})
        return report_id

    def save_data(self):
        os.makedirs("data", exist_ok=True)
        data = {
            "users":            {uid: u.to_dict() for uid, u in self.users.items()},
            "analysis_records": self.analysis_records,
            "reports":          self.reports,
        }
        with open(self.DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)

    def load_data(self):
        try:
            with open(self.DATA_FILE, 'r') as f:
                data = json.load(f)
            for uid, udata in data.get("users", {}).items():
                self.users[uid] = User.from_dict(udata)
            self.analysis_records = data.get("analysis_records", [])
            self.reports          = data.get("reports", [])
        except FileNotFoundError:
            pass
        except json.JSONDecodeError:
            print("  [WARNING] Corrupt data file. Starting fresh.")

    def __len__(self):
        return len(self.analysis_records)




def launch_gui(system: PasswordStrengthSystem):
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog


    BG       = "#0f1117"
    BG2      = "#161b27"
    BG3      = "#1e2535"
    BG4      = "#252d3d"
    FG       = "#e8eaf0"
    FG2      = "#9ba3b8"
    FG3      = "#5f6880"
    PURPLE   = "#7c6ff7"
    PURPLE2  = "#a49bff"
    TEAL     = "#2dd4bf"
    TEAL2    = "#99f6e4"
    GREEN    = "#4ade80"
    AMBER    = "#fb923c"
    RED      = "#f87171"
    BLUE     = "#60a5fa"

    def strength_color(score: int) -> str:
        if score < 20: return RED
        if score < 40: return AMBER
        if score < 60: return "#fbbf24"
        if score < 80: return GREEN
        return TEAL

    def strength_label(score: int) -> str:
        if score <= 20: return "Very Weak"
        if score <= 40: return "Weak"
        if score <= 60: return "Moderate"
        if score <= 80: return "Strong"
        return "Very Strong"


    root = tk.Tk()
    root.title("Password Strength Analyzer")
    root.configure(bg=BG)
    root.geometry("860x720")
    root.minsize(700, 580)
    root.resizable(True, True)

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TNotebook",        background=BG,  borderwidth=0)
    style.configure("TNotebook.Tab",    background=BG3, foreground=FG2,
                    padding=[14, 6],    font=("Segoe UI", 10, "bold"))
    style.map("TNotebook.Tab",
              background=[("selected", BG4)],
              foreground=[("selected", FG)])
    style.configure("Horizontal.TProgressbar",
                    troughcolor=BG3, bordercolor=BG3,
                    background=PURPLE, lightcolor=PURPLE, darkcolor=PURPLE)

    def frame(parent, **kw):
        return tk.Frame(parent, bg=kw.pop("bg", BG2), **kw)

    def label(parent, text, size=11, color=FG, bold=False, **kw):
        font = ("Segoe UI", size, "bold" if bold else "normal")
        return tk.Label(parent, text=text, bg=kw.pop("bg", parent["bg"]),
                        fg=color, font=font, **kw)

    def btn(parent, text, cmd, color=PURPLE, fg=FG, **kw):
        b = tk.Button(parent, text=text, command=cmd,
                      bg=color, fg=fg, activebackground=PURPLE2,
                      activeforeground="#ffffff", relief="flat",
                      cursor="hand2", font=("Segoe UI", 10, "bold"),
                      padx=14, pady=7, **kw)
        return b


    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=12, pady=12)

    tab_analyze  = frame(nb, bg=BG)
    tab_generate = frame(nb, bg=BG)
    tab_history  = frame(nb, bg=BG)
    tab_reports  = frame(nb, bg=BG)
    tab_users    = frame(nb, bg=BG)

    nb.add(tab_analyze,  text="  🔍  Analyze  ")
    nb.add(tab_generate, text="  ✨  Generate  ")
    nb.add(tab_history,  text="  🕓  History  ")
    nb.add(tab_reports,  text="  📊  Reports  ")
    nb.add(tab_users,    text="  👤  Users  ")



    def make_card(parent, title="", pady=8):
        outer = frame(parent, bg=BG2)
        outer.pack(fill="x", padx=10, pady=(0, pady))
        inner = frame(outer, bg=BG2)
        inner.pack(fill="x", padx=10, pady=8)
        if title:
            label(inner, title, size=9, color=FG2, bg=BG2).pack(anchor="w", pady=(0,6))
        return inner


    entry_card = make_card(tab_analyze, "ENTER PASSWORD", pady=6)

    pwd_var     = tk.StringVar()
    show_var    = tk.BooleanVar(value=False)
    mode_var    = tk.StringVar(value=Password.MODE_MIXED)

    pwd_row = frame(entry_card, bg=BG2)
    pwd_row.pack(fill="x")

    pwd_entry = tk.Entry(
        pwd_row, textvariable=pwd_var, show="•",
        bg=BG3, fg=FG, insertbackground=FG,
        font=("Courier New", 13), relief="flat",
        highlightthickness=1, highlightcolor=PURPLE,
        highlightbackground=BG4,
    )
    pwd_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 6))

    def toggle_show():
        pwd_entry.config(show="" if show_var.get() else "•")
    show_cb = tk.Checkbutton(
        pwd_row, text="Show", variable=show_var, command=toggle_show,
        bg=BG2, fg=FG2, activebackground=BG2, activeforeground=FG,
        selectcolor=BG4, relief="flat", font=("Segoe UI", 9),
    )
    show_cb.pack(side="left")


    mode_card = make_card(tab_analyze, "SCORING MODE", pady=6)
    mode_row  = frame(mode_card, bg=BG2)
    mode_row.pack(fill="x")
    for val, txt in [
        (Password.MODE_MIXED,   "Both (mixed)"),
        (Password.MODE_ENTROPY, "Entropy only"),
        (Password.MODE_CRACK,   "Crack time only"),
    ]:
        tk.Radiobutton(
            mode_row, text=txt, variable=mode_var, value=val,
            bg=BG2, fg=FG2, activebackground=BG2,
            selectcolor=BG4, font=("Segoe UI", 9),
        ).pack(side="left", padx=(0, 12))


    btn_row = frame(entry_card, bg=BG2)
    btn_row.pack(fill="x", pady=(8, 0))
    analyze_btn = btn(btn_row, "⚡  Analyze Password", lambda: run_analysis())
    analyze_btn.pack(fill="x")


    score_card = make_card(tab_analyze)
    score_hdr  = frame(score_card, bg=BG2)
    score_hdr.pack(fill="x")
    score_lbl  = label(score_hdr, "—", size=14, bold=True, bg=BG2)
    score_lbl.pack(side="left")
    score_val  = label(score_hdr, "", size=10, color=FG2, bg=BG2)
    score_val.pack(side="right")
    mode_tag   = label(score_card, "", size=9, color=FG3, bg=BG2)
    mode_tag.pack(anchor="w")

    prog = ttk.Progressbar(score_card, orient="horizontal",
                           mode="determinate", length=400)
    prog.pack(fill="x", pady=(6, 2))


    metrics_card = make_card(tab_analyze)
    metrics_row  = frame(metrics_card, bg=BG2)
    metrics_row.pack(fill="x")

    def metric_box(parent, title, val_text, color):
        box = frame(parent, bg=BG3)
        box.pack(side="left", expand=True, fill="x", padx=3)
        label(box, val_text, size=16, color=color, bold=True, bg=BG3).pack(pady=(8,2))
        label(box, title.upper(), size=8, color=FG3, bg=BG3).pack(pady=(0,8))
        return box

    m_length  = metric_box(metrics_row, "Length",  "—", PURPLE2)
    m_entropy = metric_box(metrics_row, "Entropy", "—", TEAL2)
    m_level   = metric_box(metrics_row, "Level",   "—", GREEN)
    m_crack   = metric_box(metrics_row, "MD5 crack","—", AMBER)

    def update_metric(box, val, color):
        for w in box.winfo_children():
            if w["font"].split()[1] == "16" or "16" in str(w["font"]):
                w.config(text=val, fg=color)
                return
        box.winfo_children()[0].config(text=val, fg=color)


    result_card = make_card(tab_analyze)
    result_text = tk.Text(
        result_card, bg=BG3, fg=FG, insertbackground=FG,
        font=("Courier New", 10), relief="flat",
        highlightthickness=0, height=14, wrap="word",
        state="disabled",
    )
    sb = tk.Scrollbar(result_card, command=result_text.yview, bg=BG3)
    result_text.configure(yscrollcommand=sb.set)
    result_text.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")

    result_text.tag_config("head",   foreground=PURPLE2, font=("Courier New", 10, "bold"))
    result_text.tag_config("ok",     foreground=GREEN)
    result_text.tag_config("warn",   foreground=RED)
    result_text.tag_config("tip",    foreground=BLUE)
    result_text.tag_config("crack",  foreground=TEAL2)
    result_text.tag_config("key",    foreground=FG2)
    result_text.tag_config("muted",  foreground=FG3)

    def append(text, tag=""):
        result_text.config(state="normal")
        result_text.insert("end", text, tag)
        result_text.config(state="disabled")

    def clear_result():
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.config(state="disabled")

    TIPS_MAP = {
        "short":     "Use at least 12–16 characters.",
        "uppercase": "Add uppercase letters (A–Z).",
        "lowercase": "Add lowercase letters (a–z).",
        "digit":     "Include numbers (0–9).",
        "special":   "Add special chars (!@#$%^&*).",
        "common":    "Avoid common/dictionary passwords.",
        "pattern":   "Avoid keyboard patterns & sequences.",
        "variety":   "Increase character variety.",
        "all digit": "Mix in letters and symbols.",
        "all letter":"Add digits and special characters.",
    }

    def run_analysis(pw_text=None):
        pw_text = pw_text or pwd_var.get()
        if not pw_text:
            messagebox.showwarning("Empty input", "Please enter a password.")
            return

        try:
            record = system.analyze_password(pw_text, mode=mode_var.get())
        except EmptyPasswordError as e:
            messagebox.showerror("Error", str(e))
            return
        except Exception as e:
            messagebox.showerror("Unexpected error", str(e))
            return

        sc     = record["score"]
        color  = strength_color(sc)
        lbl    = strength_label(sc)
        mode   = record["mode"]


        score_lbl.config(text=lbl, fg=color)
        score_val.config(text=f"{sc}/100")
        mode_labels = {
            Password.MODE_MIXED:   "Scoring: Mixed (entropy + complexity)",
            Password.MODE_ENTROPY: "Scoring: Entropy-based",
            Password.MODE_CRACK:   "Scoring: Crack-time-based",
        }
        mode_tag.config(text=mode_labels.get(mode, ""))

        style.configure("Horizontal.TProgressbar", background=color)
        prog["value"] = sc


        crack_ref = record.get("crack_ref", "—")
        for box, val, col in [
            (m_length,  str(len(pw_text)),          PURPLE2),
            (m_entropy, f"{record['entropy']} bits", TEAL2),
            (m_level,   lbl,                         color),
            (m_crack,   crack_ref,                   AMBER),
        ]:
            for w in box.winfo_children():
                try:
                    if "16" in str(w.cget("font")):
                        w.config(text=val, fg=col)
                        break
                except tk.TclError:
                    pass


        clear_result()
        append("  COMPLEXITY CHECKS\n", "head")
        checks = record["checks"]
        icons = {
            "length_ok":   ("Length ≥ 8",         checks["length_ok"]),
            "has_upper":   ("Uppercase (A–Z)",     checks["has_upper"]),
            "has_lower":   ("Lowercase (a–z)",     checks["has_lower"]),
            "has_digit":   ("Digits (0–9)",        checks["has_digit"]),
            "has_special": ("Special characters",  checks["has_special"]),
        }
        for k, (name, passed) in icons.items():
            sym = "  ✓" if passed else "  ✗"
            tag = "ok" if passed else "warn"
            append(f"{sym}  {name}\n", tag)

        append("\n  ENTROPY\n", "head")
        append(f"  Entropy     : {record['entropy']} bits\n", "crack")
        append(f"  Charset     : {Password.get_charset_size(pw_text)} characters\n", "key")
        append(f"  Formula     : {len(pw_text)} × log₂({Password.get_charset_size(pw_text)})\n", "muted")

        append("\n  CRACK TIME ESTIMATES\n", "head")
        for profile, data in record.get("crack_times", {}).items():
            danger = data.get("danger", "")
            t_col  = "ok" if danger in ("NEGLIGIBLE", "VERY LOW", "LOW") else (
                     "tip" if danger == "MEDIUM" else "warn")
            append(f"  {profile:<38}", "key")
            append(f"{data['human_readable']}\n", t_col)

        if record["issues"]:
            append("\n  ISSUES FOUND\n", "head")
            for issue in record["issues"]:
                append(f"  ✗  {issue}\n", "warn")
            append("\n  RECOMMENDATIONS\n", "head")
            seen = set()
            for issue in record["issues"]:
                il = issue.lower()
                for k, tip in TIPS_MAP.items():
                    if k in il and tip not in seen:
                        append(f"  →  {tip}\n", "tip")
                        seen.add(tip)
        else:
            append("\n  ✓  No major issues detected!\n", "ok")

        result_text.see("1.0")

    pwd_entry.bind("<Return>", lambda _: run_analysis())



    gen_card = make_card(tab_generate, "PASSWORD GENERATOR")

    length_var = tk.IntVar(value=16)
    len_row    = frame(gen_card, bg=BG2)
    len_row.pack(fill="x", pady=(0, 8))
    label(len_row, "Length:", bg=BG2).pack(side="left")
    len_disp = label(len_row, "16", size=12, color=TEAL2, bold=True, bg=BG2)
    len_disp.pack(side="right")
    len_slider = tk.Scale(
        len_row, from_=8, to=64, orient="horizontal",
        variable=length_var, bg=BG2, fg=FG2,
        troughcolor=BG3, highlightthickness=0, relief="flat",
        sliderrelief="flat", command=lambda v: len_disp.config(text=v),
    )
    len_slider.pack(side="left", fill="x", expand=True, padx=8)


    cs_row = frame(gen_card, bg=BG2)
    cs_row.pack(fill="x", pady=(0, 10))
    cs_vars = {
        "upper":   tk.BooleanVar(value=True),
        "lower":   tk.BooleanVar(value=True),
        "digits":  tk.BooleanVar(value=True),
        "special": tk.BooleanVar(value=True),
    }
    cs_labels = {"upper": "A–Z", "lower": "a–z", "digits": "0–9", "special": "!@#$"}
    for key, var in cs_vars.items():
        tk.Checkbutton(
            cs_row, text=cs_labels[key], variable=var,
            bg=BG2, fg=FG2, activebackground=BG2, activeforeground=FG,
            selectcolor=BG4, relief="flat", font=("Segoe UI", 9),
        ).pack(side="left", padx=(0, 12))

    gen_var    = tk.StringVar()
    gen_output = tk.Entry(
        gen_card, textvariable=gen_var, state="readonly",
        readonlybackground=BG3, fg=TEAL2,
        font=("Courier New", 14), relief="flat",
        highlightthickness=1, highlightcolor=TEAL,
        highlightbackground=BG4,
    )
    gen_output.pack(fill="x", ipady=10, pady=(0, 10))

    def do_generate():
        length = length_var.get()
        sets = {
            "upper":   "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "lower":   "abcdefghijklmnopqrstuvwxyz",
            "digits":  "0123456789",
            "special": "!@#$%^&*()_+-=[]{}|;:,.<>?",
        }
        active = [k for k, v in cs_vars.items() if v.get()]
        if not active:
            messagebox.showwarning("No charset", "Enable at least one character set.")
            return
        pool  = "".join(sets[k] for k in active)
        chars = [sets[k][__import__("random").randrange(len(sets[k]))] for k in active]
        import random as _r
        chars += [_r.choice(pool) for _ in range(length - len(chars))]
        _r.shuffle(chars)
        gen_var.set("".join(chars))

    def copy_generated():
        pw = gen_var.get()
        if pw:
            root.clipboard_clear()
            root.clipboard_append(pw)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

    def analyze_generated():
        pw = gen_var.get()
        if not pw:
            messagebox.showwarning("Nothing to analyze", "Generate a password first.")
            return
        pwd_var.set(pw)
        nb.select(tab_analyze)
        run_analysis(pw)

    btn_row2 = frame(gen_card, bg=BG2)
    btn_row2.pack(fill="x", pady=(0, 4))
    btn(btn_row2, "↺  Generate", do_generate, TEAL, "#000").pack(side="left", padx=(0, 8))
    btn(btn_row2, "⧉  Copy", copy_generated, BG3, FG).pack(side="left", padx=(0, 8))
    btn(btn_row2, "⚡  Analyze this", analyze_generated).pack(side="left")

    do_generate()



    hist_card  = make_card(tab_history, "ANALYSIS HISTORY")
    hist_frame = frame(hist_card, bg=BG2)
    hist_frame.pack(fill="both", expand=True)

    hist_cols = ("masked", "score", "level", "mode", "crack", "date")
    hist_tree = ttk.Treeview(hist_frame, columns=hist_cols, show="headings", height=16)
    for col, txt, w in [
        ("masked",  "Password",    160),
        ("score",   "Score",        60),
        ("level",   "Strength",     90),
        ("mode",    "Mode",         80),
        ("crack",   "MD5 crack",   160),
        ("date",    "Date",        130),
    ]:
        hist_tree.heading(col, text=txt)
        hist_tree.column(col, width=w, minwidth=40)
    style.configure("Treeview",
                    background=BG3, foreground=FG, fieldbackground=BG3,
                    rowheight=24, font=("Segoe UI", 9))
    style.configure("Treeview.Heading",
                    background=BG4, foreground=FG2, font=("Segoe UI", 9, "bold"))
    style.map("Treeview", background=[("selected", BG4)])

    hist_sb = tk.Scrollbar(hist_frame, command=hist_tree.yview, bg=BG3)
    hist_tree.configure(yscrollcommand=hist_sb.set)
    hist_tree.pack(side="left", fill="both", expand=True)
    hist_sb.pack(side="right", fill="y")

    def refresh_history():
        hist_tree.delete(*hist_tree.get_children())
        for rec in reversed(system.analysis_records[-200:]):
            hist_tree.insert("", "end", values=(
                rec.get("password_masked", ""),
                rec.get("score", 0),
                rec.get("level", ""),
                rec.get("mode", "mixed"),
                rec.get("crack_ref", "—"),
                rec.get("date", ""),
            ))

    btn(hist_card, "↺  Refresh", refresh_history, BG3, FG2).pack(anchor="e", pady=(6, 0))



    rep_card = make_card(tab_reports, "SECURITY REPORTS")
    rep_text = tk.Text(
        rep_card, bg=BG3, fg=FG, insertbackground=FG,
        font=("Courier New", 10), relief="flat",
        highlightthickness=0, height=18, wrap="word", state="disabled",
    )
    rep_sb = tk.Scrollbar(rep_card, command=rep_text.yview, bg=BG3)
    rep_text.configure(yscrollcommand=rep_sb.set)
    rep_text.pack(side="left", fill="both", expand=True)
    rep_sb.pack(side="right", fill="y")

    rep_text.tag_config("h", foreground=PURPLE2, font=("Courier New", 10, "bold"))
    rep_text.tag_config("g", foreground=GREEN)
    rep_text.tag_config("r", foreground=RED)
    rep_text.tag_config("d", foreground=FG2)

    def gen_report():
        rep_text.config(state="normal")
        rep_text.delete("1.0", "end")
        if not system.analysis_records:
            rep_text.insert("end", "  No analyses yet.\n")
            rep_text.config(state="disabled")
            return
        rid    = system.generate_reports()
        scores = [r.get("score", 0) for r in system.analysis_records]
        avg    = round(sum(scores) / len(scores), 2) if scores else 0
        weak   = sum(1 for s in scores if s <= 40)
        strong = sum(1 for s in scores if s >= 61)

        def w(txt, tag=""):
            rep_text.insert("end", txt, tag)

        w(f"  {'─'*54}\n", "d")
        w(f"  SECURITY REPORT  |  ID: {rid}\n", "h")
        w(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n", "d")
        w(f"  {'─'*54}\n\n", "d")
        w(f"  Total analyses : {len(system.analysis_records)}\n", "d")
        w(f"  Average score  : {avg}/100\n", "d")
        w(f"  Weak passwords : {weak}\n", "r" if weak else "d")
        w(f"  Strong         : {strong}\n", "g" if strong else "d")
        w(f"\n  Per-user summary:\n", "h")
        for uid, u in system.users.items():
            w(f"    • {u.name}: {len(u)} analyses  |  avg: {u.security_score}\n", "d")
        w(f"\n  ✓ JSON + CSV exported to reports/\n", "g")
        messagebox.showinfo("Report saved", f"Report {rid} exported to reports/")
        rep_text.config(state="disabled")

    btn_row3 = frame(rep_card, bg=BG2)
    btn_row3.pack(fill="x", pady=(8, 0))
    btn(btn_row3, "📊  Generate Report", gen_report).pack(side="left", padx=(0, 8))
    btn(btn_row3, "💾  Save Data",
        lambda: (system.save_data(), messagebox.showinfo("Saved", "Data saved.")),
        BG3, FG2).pack(side="left")



    usr_card = make_card(tab_users, "USER MANAGEMENT")

    usr_name_var  = tk.StringVar()
    usr_email_var = tk.StringVar()

    for lbl_txt, var in [("Name:", usr_name_var), ("Email:", usr_email_var)]:
        row = frame(usr_card, bg=BG2)
        row.pack(fill="x", pady=3)
        label(row, lbl_txt, bg=BG2, width=8, anchor="w").pack(side="left")
        tk.Entry(
            row, textvariable=var, bg=BG3, fg=FG,
            insertbackground=FG, font=("Segoe UI", 10),
            relief="flat", highlightthickness=1,
            highlightcolor=PURPLE, highlightbackground=BG4,
        ).pack(side="left", fill="x", expand=True, ipady=5)

    usr_list = tk.Listbox(
        usr_card, bg=BG3, fg=FG, font=("Segoe UI", 10),
        relief="flat", highlightthickness=0, selectbackground=BG4,
        height=8,
    )
    usr_list.pack(fill="x", pady=(10, 4))

    def refresh_users():
        usr_list.delete(0, "end")
        for uid, u in system.users.items():
            usr_list.insert("end", f"  {u.name}  <{u.email}>  |  {len(u)} analyses")

    def register_user():
        name  = usr_name_var.get().strip()
        email = usr_email_var.get().strip()
        if not name or not email:
            messagebox.showwarning("Missing fields", "Please fill in name and email.")
            return
        uid  = f"USR{len(system.users)+1:04d}"
        user = User(uid, name, email)
        system.users[uid] = user
        usr_name_var.set("")
        usr_email_var.set("")
        refresh_users()
        messagebox.showinfo("Registered", f"User '{name}' registered (ID: {uid}).")

    btn(usr_card, "➕  Register User", register_user).pack(fill="x", pady=(4, 0))

    refresh_users()


    def on_tab_change(event):
        tab = nb.index(nb.select())
        if tab == 2:
            refresh_history()

    nb.bind("<<NotebookTabChanged>>", on_tab_change)

    root.mainloop()




def launch_console(system: PasswordStrengthSystem):
    from analyzer import EmptyPasswordError, InvalidPasswordFormatError

    def print_menu():
        print(f"\n{'╔'+'═'*48+'╗'}")
        print(f"║{'PASSWORD STRENGTH ANALYZER':^48}║")
        print(f"{'╠'+'═'*48+'╣'}")
        print(f"║  1. Analyze Password                           ║")
        print(f"║  2. Generate Strong Password                   ║")
        print(f"║  3. View History                               ║")
        print(f"║  4. Security Report                            ║")
        print(f"║  5. Register User                              ║")
        print(f"║  6. Save / Load Data                           ║")
        print(f"║  7. Exit                                       ║")
        print(f"{'╚'+'═'*48+'╝'}")

    while True:
        print_menu()
        choice = input("  Enter choice (1-7): ").strip()
        try:
            if choice == '1':
                pw = input("  Enter password: ")
                print("  Score mode: [1] Mixed  [2] Entropy  [3] Crack time")
                m  = input("  Choose (1-3, default 1): ").strip()
                mode = {
                    '2': Password.MODE_ENTROPY,
                    '3': Password.MODE_CRACK,
                }.get(m, Password.MODE_MIXED)
                rec = system.analyze_password(pw, mode=mode)
                print(f"\n  Score : {rec['score']}/100  |  Level : {rec['level']}")
                print(f"  Entropy : {rec['entropy']} bits")
                print(f"  MD5 crack : {rec.get('crack_ref','—')}")
                if rec['issues']:
                    print("  Issues:")
                    for i in rec['issues']:
                        print(f"    ✗ {i}")
                from crack_time import CrackTimeEstimator
                est = CrackTimeEstimator(rec['entropy'])
                est.print_crack_table()

            elif choice == '2':
                try:
                    length = int(input("  Length (min 8): "))
                except ValueError:
                    length = 16
                pw = system.generate_strong_password(max(8, length))
                print(f"  Generated: {pw}")

            elif choice == '3':
                for rec in system.analysis_records[-20:]:
                    print(f"  {rec['date']}  {rec['password_masked']}  {rec['score']}/100  {rec['level']}")

            elif choice == '4':
                rid = system.generate_reports()
                if rid:
                    print(f"  Report {rid} exported.")
                else:
                    print("  No data to report.")

            elif choice == '5':
                name  = input("  Name  : ").strip()
                email = input("  Email : ").strip()
                uid   = f"USR{len(system.users)+1:04d}"
                system.users[uid] = User(uid, name, email)
                print(f"  Registered {name} ({uid})")

            elif choice == '6':
                sub = input("  [1] Save  [2] Load: ").strip()
                if sub == '1':
                    system.save_data()
                    print("  Saved.")
                elif sub == '2':
                    system.load_data()
                    print("  Loaded.")

            elif choice == '7':
                if input("  Save before exit? (y/n): ").strip().lower() == 'y':
                    system.save_data()
                print("  Goodbye! Stay secure. 🔐")
                break

        except (EmptyPasswordError, InvalidPasswordFormatError) as e:
            print(f"  [ERROR] {e}")
        except KeyboardInterrupt:
            print("\n  Interrupted.")
            break
        except Exception as e:
            print(f"  [ERROR] {e}")




def main():
    system = PasswordStrengthSystem()
    try:
        import tkinter
        launch_gui(system)
    except ImportError:
        print("  [INFO] Tkinter not available – launching console mode.")
        launch_console(system)


if __name__ == "__main__":
    main()
