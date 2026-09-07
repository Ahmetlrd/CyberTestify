# CyberTestify

**Automated web security pre-assessment platform** — helping businesses understand
their external security posture before committing to a full manual penetration test.

> This repository is a **case study / project showcase**. The production codebase
> is private, as CyberTestify is a live commercial product with real customers.

## Overview

CyberTestify runs a tiered set of automated security scans against a target domain
and turns the results into a structured, evidence-backed PDF report — from a fast
passive header/TLS check up to a fully autonomous AI-driven red-team engagement.
The goal is honest, defensible reporting: every claim in a report is either backed
by concrete evidence or explicitly marked as "not tested," never silently assumed safe.

## Key Features

- **Tiered scan packages** — from lightweight passive checks (HTTP security headers,
  TLS/certificate posture, server fingerprinting) to active verification and a fully
  autonomous AI red-team engagement, so customers can choose the right depth for
  their budget and risk appetite.
- **Deterministic, evidence-linked reporting** — findings are generated from a
  rule-based engine rather than free-form LLM text, with every "no issue found"
  claim distinguished from "not tested" (no false assurance).
- **Autonomous AI red-team engine** — an LLM-orchestrated agent that plans and
  executes a bounded, cost-capped reconnaissance/verification campaign against a
  verified target, with hard evidence-binding rules to prevent hallucinated findings.
- **Multi-region support (TR / EN / DE)** — full report and product-copy localization,
  including region-specific compliance framework mapping (e.g. KVKK for Turkey).
- **Compliance readiness mapping** — maps externally observable gaps to relevant
  KVKK / PCI-DSS / ISO 27001 checkpoints as a pre-assessment signal, not a formal audit.
- **Free instant preview scan** — a lightweight, ownership-independent passive check
  as a lead-generation entry point, gated to non-invasive checks only.

## Engineering Highlights

- Designed a **three-state finding model** (clean / finding / not-evaluated) across
  every report template to keep automated security claims honest and legally defensible.
- Built a **cost- and time-capped autonomous agent pipeline** for the AI red-team
  tier, with checklist-based hard gates and strict evidence-to-claim binding.
- Implemented **deterministic PDF report generation** with a shared, reusable
  presentation layer across multiple product tiers.
- Localized the entire report and marketing surface across three languages while
  keeping compliance-sensitive content (e.g. KVKK) region-gated.

## Tech Stack

TypeScript · Node.js · LLM orchestration (agentic pipelines) · PDF generation ·
Headless browser automation · i18n / multi-region content pipeline

## Live Product

🔗 [cybertestify.com](https://cybertestify.com)

## Disclaimer

CyberTestify is an automated pre-assessment tool and does not replace a certified
manual penetration test. All reports carry explicit scope and limitation disclosures.
