---
tags: [Testing, Markdown, Pentest Notes, Beginner]
---

# Test Post: Quick Pentest Checklist for 2025

**Date:** 2025-11-21  
**Category:** Notes  
**Author:** Nikhil (h4ck3rfirst)

## Why This Post?
Just testing the blog setup! If this loads, your site is working. Drop real write-ups here next.

## Quick Pentest Workflow
1. **Recon**: Always start with Nmap + Gobuster.
   ```bash
   sudo nmap -sC -sV -p- -T4 target.com -oN recon.nmap
   gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt