# IntentGuard (Academic Prototype)

IntentGuard is a **schema-bound intent-to-firewall policy compiler** 

It converts:

Natural language security intent  
→ **LLM-assisted structured extraction  
→ **canonical intermediate representation 
→ **validation (schema + semantic checks)**  
→ **deterministic Linux `iptables` filter-table generation**  
→ **Mininet simulation**.



## Repository structure 

```
.
├── intentguard/                 # Core library (compiler pipeline)
│   ├── context/                 # YAML context model + loader
│   ├── llm/                     # Gemini JSON-only extraction
│   ├── ir/                      # Canonical, platform-independent IR
│   ├── validate/                # Schema + semantic validators
│   ├── generator/               # Deterministic iptables generator
│   ├── pipeline/                # Orchestration glue
│   ├── schemas/                 # JSON Schemas (extraction + IR)
│   └── sim/mininet/             # Deterministic Mininet demo helpers
├── contexts/example/            # Example context (single context.yaml)
├── scripts/
│   ├── intentguard_cli.py       # Compile NL -> IR -> iptables commands
│   └── mininet_demo.py          # Optional demo (sudo) with rule apply + tests
└── requirements.txt
```


## How to run

### 1) Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create `.env` from the example:

```bash
cp .env.example .env
```

Set `GEMINI_API_KEY` in `.env`.

### 2) Compile an intent (CLI)

```bash
python -m scripts.intentguard_cli compile \
  "Allow hr_laptops to access web_server on https" \
  --context-dir contexts/example
```

Output includes:
- extracted JSON
- canonical IR
- validation issues (warnings/errors)
- `iptables` commands as an ordered list

### 3) Mininet feasibility demo

Requires `mininet` and `conntrack` installed and must run with sudo:

```bash
sudo -E python -m scripts.mininet_demo
```



