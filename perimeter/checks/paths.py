"""Admin path probe — checks common sensitive paths for 200/403 responses."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "Admin Path Probe"
TIMEOUT = 8
MAX_WORKERS = 10

# (path, severity_if_200, label)
PATHS: list[tuple[str, Severity, str]] = [
    # Secret files that must never be publicly accessible
    ("/.env",               Severity.HIGH,   "environment variables file"),
    ("/.git/HEAD",          Severity.HIGH,   "Git repository metadata"),
    ("/.git/config",        Severity.HIGH,   "Git configuration"),
    ("/phpinfo.php",        Severity.HIGH,   "PHP configuration page"),
    ("/web.config",         Severity.HIGH,   "IIS configuration file"),
    ("/.htaccess",          Severity.HIGH,   "Apache configuration file"),
    # Admin / management interfaces
    ("/admin",              Severity.MEDIUM, "admin panel"),
    ("/admin/",             Severity.MEDIUM, "admin panel"),
    ("/administrator",      Severity.MEDIUM, "Joomla / generic admin panel"),
    ("/wp-admin/",          Severity.MEDIUM, "WordPress admin panel"),
    ("/wp-login.php",       Severity.MEDIUM, "WordPress login"),
    ("/cpanel",             Severity.MEDIUM, "cPanel"),
    ("/server-status",      Severity.MEDIUM, "Apache server-status"),
    ("/server-info",        Severity.MEDIUM, "Apache server-info"),
    # API docs / developer tools
    ("/swagger-ui.html",    Severity.MEDIUM, "Swagger UI"),
    ("/swagger-ui/",        Severity.MEDIUM, "Swagger UI"),
    ("/api-docs",           Severity.MEDIUM, "API documentation"),
    ("/api/docs",           Severity.MEDIUM, "API documentation"),
    ("/graphql",            Severity.MEDIUM, "GraphQL endpoint"),
    ("/graphiql",           Severity.MEDIUM, "GraphiQL explorer"),
    # Spring Boot Actuator
    ("/actuator/env",       Severity.HIGH,   "Spring Boot environment endpoint"),
    ("/actuator",           Severity.MEDIUM, "Spring Boot Actuator index"),
    ("/actuator/beans",     Severity.MEDIUM, "Spring Boot beans endpoint"),
    ("/actuator/health",    Severity.LOW,    "Spring Boot health endpoint"),
]


def _probe(base_url: str, path: str) -> tuple[str, int | None]:
    """GET base_url+path without following redirects. Returns (path, status_code | None)."""
    try:
        resp = requests.get(
            base_url + path,
            timeout=TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": "perimeter-scanner/1.0"},
        )
        return path, resp.status_code
    except RequestException:
        return path, None


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)
    base_url = f"https://{domain}"

    # Probe all paths concurrently
    results: dict[str, int | None] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_probe, base_url, path): path for path, _, _ in PATHS}
        for future in as_completed(futures):
            path, status = future.result()
            results[path] = status

    # Build lookup: path -> (severity, label)
    path_meta = {path: (sev, label) for path, sev, label in PATHS}

    # Collect hits
    found_200: list[tuple[str, Severity, str]] = []
    found_403: list[str] = []

    for path, _, _ in PATHS:  # iterate in defined order
        status = results.get(path)
        if status == 200:
            sev, label = path_meta[path]
            found_200.append((path, sev, label))
        elif status == 403:
            found_403.append(path)

    if not found_200 and not found_403:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="No sensitive paths found",
            severity=Severity.PASS,
            summary="None of the probed paths returned a 200 or 403 response.",
            fix="",
            raw={"paths_checked": [p for p, _, _ in PATHS]},
        ))
        return result

    # One finding per 200 hit (severity varies per path)
    for path, sev, label in found_200:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"Accessible: {path}  ({label})",
            severity=sev,
            summary=(
                f"{domain}{path} returned HTTP 200. "
                f"This {label} is publicly readable and should not be."
            ),
            fix=f"Block or remove access to {path}. If the file is sensitive, delete it from the web root.",
            raw={"path": path, "status": 200, "label": label},
        ))

    # One grouped finding for all 403 hits
    if found_403:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"{len(found_403)} sensitive path(s) exist but return 403",
            severity=Severity.LOW,
            summary=(
                f"The following paths returned HTTP 403 (forbidden), indicating they exist "
                f"on the server but access is currently restricted: {', '.join(found_403)}. "
                "Access controls could be bypassed or misconfigured in future."
            ),
            fix="Remove these paths from the web root if they are not needed. A 404 is safer than a 403.",
            raw={"paths": found_403, "status": 403},
        ))

    return result
