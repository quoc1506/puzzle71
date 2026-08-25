# Puzzle Client

BTC Puzzle 71 Brute-Force Client.

## Prerequisites

- Python 3.10+
- Dependencies from `requirements.txt`:
  - `numpy>=1.24`
  - `coincurve>=18`
  - `pycryptodome>=3.19`

Install them with:

```bash
pip install -r requirements.txt
```

## Run Locally (Python)

```bash
chmod +x puzzle_hope.pyz
./puzzle_hope.pyz --puzzle 71 --user <your_username>
```

Or run directly with Python:

```bash
python puzzle_hope.pyz --puzzle 71 --user <your_username>
```

## Run with PM2

```bash
pm2 start puzzle_hope.pyz --name puzzle-hope --interpreter python3 -- --puzzle 71 --user <your_username>
```
