---
title: "Django Allauth: Account Takeover via Provider Identifier Mutability"
date: 2024-12-25
description: "Account impersonation in django-allauth through mutable preferred_username used as provider identifier."
tags: ["cve", "research", "web-security", "account-takeover"]
categories: ["vulnerability-research"]
draft: false
---

> *"There's always a side door."*

## Overview

I discovered an account takeover vulnerability in [django-allauth](https://github.com/pennersr/django-allauth), one of the most widely-used authentication libraries for Django. The vulnerability allows an attacker to impersonate arbitrary users by exploiting how certain OAuth providers' identifiers are resolved.

## Vulnerability Details

**CVE:** CVE-2025-65431
**Type:** Improper Authentication / Account Takeover (CWE-287)
**Impact:** Account Impersonation
**Affected Versions:** django-allauth < 65.13.0

### The Bug

Both the Okta and NetIQ providers were using `preferred_username` as the identifier for third-party provider accounts. This value is **mutable** — users can change their `preferred_username` on the identity provider side.

This means:
1. Victim authenticates via Okta/NetIQ, django-allauth stores `preferred_username` as their provider UID
2. Attacker changes their own `preferred_username` on the identity provider to match the victim's stored value
3. Attacker authenticates — django-allauth matches them to the victim's account
4. Full account takeover

### Why It Matters

The core issue is using a mutable, user-controlled value for authorization decisions. OAuth providers typically expose multiple identifier fields:

| Field | Mutable | Safe for Auth |
|-------|---------|---------------|
| `sub` (subject) | No | Yes |
| `email` | Sometimes | Risky |
| `preferred_username` | Yes | No |

The `sub` claim is the only identifier guaranteed to be immutable and unique per provider. Using anything else for account binding is a security anti-pattern.

## Fix

Fixed in django-allauth **65.13.0**. The Okta and NetIQ providers now use immutable identifiers (`sub`) instead of `preferred_username` for account resolution.

## References

- [CVE-2025-65431 — Snyk](https://security.snyk.io/vuln/SNYK-DEBIAN13-DJANGOALLAUTH-14423078)
- [django-allauth Release Notes 65.3.1](https://docs.allauth.org/en/dev/release-notes/2024.html)
- [ZeroPath — django-allauth Account Takeover Vulnerabilities](https://zeropath.com/blog/django-allauth-account-takeover-vulnerabilities)

## Timeline

| Date | Event |
|------|-------|
| 2024 | Vulnerability discovered |
| 2024-12-25 | Fix released in django-allauth 65.3.1 |
| 2025 | CVE-2025-65431 assigned |

---

*Responsible disclosure was followed.*
