@'
# Secure DevOps – Assignment 3 (22167521)

**Student:** Vrushti  
**Repo:** https://github.com/vrushti54/SecureDevOps-Assignment3-22167521

This repository contains Docker/Compose stacks, Clair v4 scanning, helper scripts, a CSV export, and screenshots that prove each task.

---

## Quick Start

```bash
docker compose up -d
chmod +x ./clair.sh
./clair.sh scan ubuntu 22.04 ubuntu-22_04-vulns.csv
./clair.sh scan alpine 3.19
./clair.sh delete --last
