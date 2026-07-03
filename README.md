# Tranco Registrar & DNS Host Dashboard

Fetches the [Tranco](https://tranco-list.eu/) top-1M list and, for the top *N*
domains, works out:

- **Registrar** — via [RDAP](https://about.rdap.org/) (IANA bootstrap → the
  registry's RDAP server, falling back to `rdap.org`). e.g. *MarkMonitor*.
- **DNS host** — via a live `NS` lookup, mapping nameservers to a provider.
  e.g. *Amazon Route 53*. Unknown providers are grouped by the nameserver's
  registrable domain (usually the hosting company or a self-hosted zone).

Results are written to `data.json`; `dashboard.html` renders them.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python3 topregistrars.py                  # top 10,000 (default)
python3 topregistrars.py --limit 1000     # only the top 1,000
python3 topregistrars.py --limit 50000 --concurrency 32
```

Key flags:

| flag | default | meaning |
|------|---------|---------|
| `--limit N` | `10000` | how far down the list to check |
| `--concurrency N` | `24` | concurrent workers |
| `--timeout S` | `15` | per-RDAP-request timeout |
| `--output PATH` | `data.json` | output file |
| `--cache-dir DIR` | `.cache` | list / bootstrap / partial-results cache |
| `--no-resume` | off | ignore cached per-domain results |

The downloaded list, the RDAP bootstrap, and every per-domain result are cached
under `--cache-dir`, so re-running or resuming after Ctrl-C is cheap. RDAP
servers (especially Verisign for `.com`) rate-limit; the script backs off and
retries, and marks anything it still can't resolve as `Unknown`. Lower
`--concurrency` if you see a lot of Unknowns.

## View the dashboard

`dashboard.html` loads `data.json` from the same directory with `fetch()`, so it
must be served over HTTP (opening the file directly is blocked by the browser):

```bash
python3 -m http.server 8000
# then open http://localhost:8000/dashboard.html
```

The dashboard shows:

- summary cards (domains / registrars / DNS hosts / TLDs),
- **By Registrar** and **By DNS Host** tables with counts, share, and bars,
- a **By TLD** breakdown,
- a searchable, sortable, paginated **Domains** table.

Everything is filterable by TLD (the dropdown, or click a row in a breakdown
table), and the search box filters by domain / registrar / DNS host.
