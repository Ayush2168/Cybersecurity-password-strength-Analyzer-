# reports.py - handles report generation and export

import json
import csv
import os
from datetime import datetime




class ReportGenerationError(Exception):
    pass




class SecurityReport:



    STRENGTH_LEVELS = (
        (0,  20,  "Very Weak"),
        (21, 40,  "Weak"),
        (41, 60,  "Moderate"),
        (61, 80,  "Strong"),
        (81, 100, "Very Strong"),
    )

    def __init__(self, report_id: str, analysis_records: list):
        self.report_id    = report_id
        self.report_date  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.security_level = "N/A"
        self.__records    = analysis_records

    def generate_report(self):
        for record in self.__records:
            yield record

    def export_report(self, output_dir: str = "reports") -> dict:
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, f"report_{self.report_id}.json")
        csv_path  = os.path.join(output_dir, f"report_{self.report_id}.csv")


        report_data = {
            "report_id":     self.report_id,
            "report_date":   self.report_date,
            "total_records": len(self.__records),
            "records":       self.__records
        }
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=4)


        if self.__records:
            fieldnames = ["password_masked", "score", "level", "crack_difficulty", "issues", "date"]
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for record in self.__records:
                    writer.writerow({
                        "password_masked":  record.get("password_masked", ""),
                        "score":            record.get("score", 0),
                        "level":            record.get("level", ""),
                        "crack_difficulty": record.get("crack_difficulty", ""),
                        "issues":           "; ".join(record.get("issues", [])),
                        "date":             record.get("date", "")
                    })

        return {"json": json_path, "csv": csv_path}

    def print_summary(self, users: dict = None):
        scores = [r.get("score", 0) for r in self.__records]
        avg    = round(sum(scores) / len(scores), 2) if scores else 0


        weak_list   = [r for r in self.__records if r.get("score", 0) <= 40]
        strong_list = [r for r in self.__records if r.get("score", 0) >= 61]
        risky_list  = [r for r in self.__records if r.get("issues") and len(r.get("issues", [])) >= 3]

        print(f"\n{'='*55}")
        print(f"  SECURITY REPORT  |  ID: {self.report_id}")
        print(f"  Generated: {self.report_date}")
        print(f"{'='*55}")
        print(f"  Total Analyses   : {len(self.__records)}")
        print(f"  Average Score    : {avg}/100")
        print(f"  Weak Passwords   : {len(weak_list)}")
        print(f"  Strong Passwords : {len(strong_list)}")
        print(f"  High Risk (3+ issues): {len(risky_list)}")

        if users:
            print(f"\n  Per-User Summary:")
            for uid, user in users.items():
                print(f"    • {user.name}: {len(user)} analyses | "
                      f"Avg Score: {user.security_score}")

        print(f"\n  Recent Analyses:")
        recent = sorted(self.__records, key=lambda r: r.get("date",""), reverse=True)[:5]
        for r in recent:
            print(f"    [{r.get('date','')[:10]}] Score: {r.get('score',0):>3}/100 | "
                  f"{r.get('level',''):<12} | Issues: {len(r.get('issues',[]))}")
        print(f"{'='*55}")

    def __str__(self):
        return f"SecurityReport(id={self.report_id}, records={len(self.__records)}, date={self.report_date})"

    def __repr__(self):
        return f"SecurityReport(report_id={self.report_id})"
