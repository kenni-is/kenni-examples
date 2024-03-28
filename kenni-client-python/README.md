# Kenni Python client

- python3 -m pip install -r requirements.txt
- python3 -m uvicorn client:app --reload --log-level debug --port 4007
- python3 -m uvicorn resource:app --port 4008 --reload --log-level debug
