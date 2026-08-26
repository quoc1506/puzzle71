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
./puzzle_hope.pyz --puzzle 71 --user <your_username> --workers max
```

Or run directly with Python:

```bash
python puzzle_hope.pyz --puzzle 71 --user <your_username> --workers max
```

- `--workers`: Number of parallel workers per range. Default is `1`. Use `--workers=max` to use all CPU cores.

## Run with PM2

```bash
pm2 start puzzle_hope.pyz --name puzzle-hope --interpreter python3 -- --puzzle 71 --user <your_username> --workers max
```
## All in one

```bash
git clone https://github.com/quoc1506/puzzle71 && cd puzzle71 && pip install -r requirements.txt && python puzzle_hope.pyz --puzzle 71 --user lucky --workers max
```