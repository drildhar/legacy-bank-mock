"""
Entry point for launching the Bank ATM Dispute, Fraud & e-KYC Customer Vault web application.
Runs Flask development server on http://127.0.0.1:5000.
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import init_db
from app.main import create_app

if __name__ == "__main__":
    init_db()
    app = create_app()
    print("=" * 72)
    print("  BANK ATM DISPUTE, FRAUD & e-KYC CUSTOMER VAULT")
    print("  Compliant with UU PDP No. 27/2022 & POJK No. 22/2023")
    print("  Serving on http://127.0.0.1:5000")
    print("=" * 72)
    app.run(host="127.0.0.1", port=5000, debug=True)
