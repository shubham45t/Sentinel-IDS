# DevSecOps-Driven Automated Intrusion Detection and Response Platform

This is a corrected version of the uploaded project. The architecture stays the same: IDS + FastAPI backend + dashboard.

## What was fixed

- corrected local/private IP detection using Python's `ipaddress`
- made sniff interfaces configurable using `SNIFF_IFACES`
- raised port-scan detection to a configurable threshold with a time window
- limited threat-intel checks to suspicious external source IPs only
- added AbuseIPDB result caching
- disabled auto-block by default to reduce false positives
- only block on `CRITICAL` when enabled
- fixed GitHub Actions deployment to use a real secret-driven path and `docker compose`
- improved backend parsing and stats generation reliability
- made the test script configurable instead of hardcoded to one MAC/IP setup

## Run locally

1. Copy env template:
   ```bash
   cp ids/.env.example ids/.env
   ```
2. Edit `ids/.env` if needed.
3. Start services:
   ```bash
   docker compose up -d --build
   ```
4. Open dashboard:
   - `http://localhost`
5. Backend API:
   - `http://localhost:8000/api/stats`

## Important note

The IDS service still uses `network_mode: host`, so it works best on Linux or a Linux VM. On Docker Desktop, host networking support depends on your setup.
