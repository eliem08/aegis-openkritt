"""Draft a reproduction plan for a validated finding.

Every serious program (Vercel, Matomo, and most others) rejects static-analysis or
AI output that has not been reproduced against a running instance. This module turns
a confirmed hypothesis