echo "Creating Python environment..."
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt --quiet

echo "Don't forget to activate Python environment before using nmap2mysql"