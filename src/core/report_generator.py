import os
import json
from datetime import datetime

class ReportGenerator:
    def save_report(self, data, filename_base):
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)

        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(reports_dir, f"{filename_base}_{now}.json")

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return report_path
