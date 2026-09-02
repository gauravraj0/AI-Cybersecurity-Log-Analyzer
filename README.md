# Aegis AI Cybersecurity Log Analyzer

A polished, responsive command-center dashboard for analyzing security logs with AI-assisted detection triage.

## Run locally

This is a dependency-free static site. From the project directory, run:

```bash
python3 -m http.server 4173 --bind 0.0.0.0
```

Then open `http://localhost:4173`.

## Included interactions

- Threat activity range switching between 24 hours, 7 days, and 30 days
- Detection queue search and severity filters
- Detection detail modal with AI reasoning
- CSV report export
- Log upload and drag-and-drop ingestion state
- Live activity pause/resume control
- Workspace, notification, responsive navigation, and toast feedback
