# Security Policy

## Supported Versions

This project is currently in active development. Security updates will be applied to the main branch.

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in this project, please report it privately:

### How to Report

1. **Email:** Send details to the repository owner (check GitHub profile for contact)
2. **GitHub Security Advisory:** Use the "Security" tab → "Report a vulnerability" (preferred)

### What to Include

Please include as much of the following information as possible:

- Type of vulnerability (e.g., command injection, information disclosure, authentication bypass)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response:** Within 48 hours
- **Vulnerability Assessment:** Within 7 days
- **Fix Development:** Depends on severity (critical: 7 days, high: 14 days, medium/low: 30 days)
- **Public Disclosure:** After fix is released and users have had time to update (typically 14 days)

## Security Best Practices for Users

### Network Configuration

- ✅ Keep MCP server bound to `127.0.0.1` (localhost)
- ✅ Use Tailscale/WireGuard for remote access
- ❌ Never expose port 8765 to the internet
- ❌ Never bind to `0.0.0.0` without authentication

### API Key Management

- ✅ Store `ANTHROPIC_API_KEY` in `.env` file (never commit to git)
- ✅ Monitor API usage at https://console.anthropic.com/
- ✅ Set up billing alerts for unexpected usage
- ❌ Never share your API key
- ❌ Never commit `.env` to version control

### System Access

- ✅ Run the MCP server as a non-root user
- ✅ Ensure PiHole log files have appropriate permissions
- ✅ Keep your Raspberry Pi OS updated
- ❌ Never give remote access to strangers for "debugging"

### Privacy

- ✅ Understand that DNS logs contain sensitive browsing data
- ✅ Protect log files with appropriate file permissions
- ✅ Implement log retention policies
- ❌ Never share raw log files publicly

## Known Security Considerations

### By Design

1. **DNS Query Logging:** All DNS queries are logged and analyzed. This is required for functionality but has privacy implications.

2. **Local System Access:** The tools execute PiHole CLI commands via `subprocess`. This requires appropriate system permissions.

3. **Audit Trail:** All whitelist/blacklist modifications are logged to `~/pihole-agent/logs/audit.jsonl` for accountability.

### Mitigations in Place

- Input validation on domain names (regex validation)
- Use of `subprocess.run()` with list arguments (prevents shell injection)
- Server bound to localhost by default
- Email address validation
- Rate limiting on time-based queries (max 7 days)

## Security Update Policy

Security fixes will be released as follows:

- **Critical:** Immediate patch release + security advisory
- **High:** Patch within 7 days + advisory
- **Medium/Low:** Included in next regular release

Users will be notified via:
- GitHub Security Advisories
- Release notes
- README updates

## Credits

We appreciate the security research community and will acknowledge researchers who responsibly disclose vulnerabilities (unless they prefer to remain anonymous).

## Contact

For security concerns, use GitHub's private vulnerability reporting feature or contact the repository maintainer through their GitHub profile.
