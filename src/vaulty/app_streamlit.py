"""Vaulty Streamlit App (locally run DLP scanner UI)."""

from __future__ import annotations

import base64
import logging
import mimetypes
import time
from collections import Counter, namedtuple
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import streamlit as stream

# =============================================================================
# Dependency imports with safe fallbacks
# =============================================================================


try:
    from reporting import human_summary, to_json  # type: ignore[attr-defined]
except (ImportError, AttributeError):

    def human_summary(scan_findings: Iterable[Any]) -> str:
        """Fallback summary while reporting is under development."""
        finding_list = list(scan_findings)
        count = len(finding_list)
        return f"Scan complete. {count} finding(s). [stub summary]"

    def to_json(scan_findings: Iterable[Any], output_path: Path) -> None:
        """Fallback JSON writer while reporting is under development."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            '{"status": "stub", "findings": []}',
            encoding="utf-8",
        )


try:
    from scanner import scan_file  # type: ignore[attr-defined]
except (ImportError, AttributeError):

    def scan_file(input_path: Path) -> list[Any]:
        """Fallback scanner that returns no findings."""
        return []


try:
    from utils import get_logger, safe_filename  # type: ignore[attr-defined]
except (ImportError, AttributeError):

    def get_logger(logger_name: str) -> logging.Logger:
        """Fallback logger helper using the stdlib logging module."""
        return logging.getLogger(logger_name)

    def safe_filename(original_name: str) -> str:
        """Fallback filename sanitizer for uploads."""
        unsafe_chars = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
        safe_name = original_name
        for char in unsafe_chars:
            safe_name = safe_name.replace(char, "_")
        safe_name = safe_name.strip() or "upload"
        return safe_name


# =============================================================================
# Page setup and global styling
# =============================================================================


stream.set_page_config(page_title="Vaulty - DLP Scanner", layout="centered")

base_dir = Path(__file__).resolve().parent
css_path = base_dir / "static" / "style.css"

if css_path.exists():
    stream.markdown(
        f"<style>{css_path.read_text()}</style>",
        unsafe_allow_html=True,
    )
else:
    stream.warning(
        "⚠️ Missing static/style.css — using default Streamlit theme.",
    )

# =============================================================================
# Logo handling (shared between header and sidebar)
# =============================================================================


logo_path = base_dir / "static" / "image" / "Vaulty Logo.svg"
encoded_logo_svg: str | None

if logo_path.exists():
    encoded_logo_svg = base64.b64encode(logo_path.read_bytes()).decode("utf-8")
else:
    encoded_logo_svg = None
    stream.warning("⚠️ Logo file not found in static/image/.")

if encoded_logo_svg:
    stream.markdown(
        f"""
<div style="text-align:center; margin-top:10px; margin-bottom:10px;">
  <img src="data:image/svg+xml;base64,{encoded_logo_svg}" alt="Vaulty Logo"
       style="
         width:320px;
         max-width:95%;
         height:auto;
         filter: drop-shadow(0px 3px 6px rgba(0,0,0,0.10));
       ">
</div>
        """,
        unsafe_allow_html=True,
    )

stream.markdown(
    '<div class="vaulty-title">' "Vaulty 🔒 — Data Loss Prevention File Scanner" "</div>",
    unsafe_allow_html=True,
)
stream.markdown(
    '<div class="vaulty-subnav">Scan · Detect · Protect</div>',
    unsafe_allow_html=True,
)

# =============================================================================
# Sidebar: logo + recent scans for this session
# =============================================================================


with stream.sidebar:
    if encoded_logo_svg:
        stream.markdown(
            f"""
<div style="text-align:center; margin-top:10px; margin-bottom:20px;">
  <img src="data:image/svg+xml;base64,{encoded_logo_svg}" alt="Vaulty Logo"
       style="
         width:440px;
         max-width:90%;
         height:auto;
         filter: drop-shadow(0px 3px 6px rgba(0,0,0,0.15));
       ">
</div>
            """,
            unsafe_allow_html=True,
        )
    else:
        stream.warning("⚠️ Logo file not found in static/image/.")

    stream.header("Recent scans")
    recent_scan_items = stream.session_state.get("recent_scans", [])
    if not recent_scan_items:
        stream.caption("No scans yet.")
    else:
        for scan_entry in recent_scan_items[-10:][::-1]:
            stream.write(
                "• "
                f"`{scan_entry['name']}` — "
                f"{scan_entry['elapsed']:.1f}s, "
                f"{scan_entry['count']} finding(s)",
            )

# =============================================================================
# One-time privacy / onboarding notice
# =============================================================================


if "onboarded" not in stream.session_state:
    stream.session_state.onboarded = False

onboarding_placeholder = stream.empty()
if not stream.session_state.get("onboarded", False):
    with onboarding_placeholder.container(border=True):
        stream.subheader("Welcome to Vaulty 🔒")
        stream.write(
            "All scans are performed **locally**. " "No files or results leave your device.",
        )
        stream.write(
            "You can adjust detection via **Scan options ⚙️** below.",
        )
        if stream.button("Got it", type="primary", key="welcome_ok"):
            stream.session_state.onboarded = True
            onboarding_placeholder.empty()
            stream.rerun()

# =============================================================================
# Scan options (toggle which signals we look for)
# =============================================================================


scan_options = stream.session_state.setdefault(
    "options",
    {"anonymize": True, "include_ipv4": False, "include_phone": False},
)


def render_scan_options() -> None:
    """Render the scan options controls."""
    stream.caption("Adjust what Vaulty looks for (local-only).")
    scan_options["anonymize"] = stream.toggle(
        "Anonymize any sample snippets",
        value=scan_options["anonymize"],
        key="opt_anon",
    )
    scan_options["include_ipv4"] = stream.toggle(
        "Detect IPv4 addresses",
        value=scan_options["include_ipv4"],
        key="opt_ipv4",
    )
    scan_options["include_phone"] = stream.toggle(
        "Detect phone numbers",
        value=scan_options["include_phone"],
        key="opt_phone",
    )


if hasattr(stream, "popover"):
    try:
        with stream.popover(
            "Scan options ⚙️",
            use_container_width=True,
        ):
            # Popover is available in this Streamlit version.
            render_scan_options()
    except TypeError:
        # Fallback for older Streamlit builds.
        with stream.popover("Scan options ⚙️"):
            render_scan_options()
else:
    with stream.expander("Scan options ⚙️"):
        render_scan_options()

# =============================================================================
# File uploader card + clear state
# =============================================================================


if "uploader_key" not in stream.session_state:
    stream.session_state.uploader_key = 0

with stream.container():
    stream.markdown('<div class="vaulty-card">', unsafe_allow_html=True)
    stream.markdown('<div class="uicon">⬆️</div>', unsafe_allow_html=True)
    stream.markdown(
        '<div class="uhelp">' "Upload a TXT, CSV, or PDF file (≤ 5 MB)" "</div>",
        unsafe_allow_html=True,
    )

    uploaded_file = stream.file_uploader(
        "Upload a TXT, CSV, or PDF file (5 MB or less).",
        type=["txt", "csv", "pdf"],
        key=f"uploader_{stream.session_state.uploader_key}",
        label_visibility="collapsed",
    )

    column_left, column_scan, column_spacer, column_clear, column_right = stream.columns(
        [1, 1, 0.5, 1, 1]
    )
    with column_scan:
        scan_button_clicked = stream.button(
            "Scan Now",
            type="primary",
            use_container_width=True,
            key="btn_scan",
        )
    with column_clear:
        clear_button_clicked = stream.button(
            "Clear File",
            use_container_width=True,
            key="btn_clear",
        )

    stream.markdown("</div>", unsafe_allow_html=True)

if clear_button_clicked:
    stream.session_state.uploader_key += 1
    stream.toast("Cleared.", icon="🧹")
    stream.rerun()

# =============================================================================
# Demo mode toggle (for UI preview with dummy data)
# =============================================================================


demo_mode_enabled = stream.toggle(
    "💡 Demo Mode",
    value=False,
    help="Preview the UI with dummy scan data (no real scanning).",
)

if demo_mode_enabled:
    stream.toast("Running Vaulty in demo mode (no real scan).", icon="🧩")

# Prepare variables for later UI use so type checkers are happy.
scan_findings: list[Any] = []
scan_elapsed_seconds: float = 0.0
scan_safe_name: str = "scan"
scan_report_path: Path | None = None

# =============================================================================
# Scan engine (real or demo)
# =============================================================================


if (uploaded_file and scan_button_clicked) or demo_mode_enabled:
    if demo_mode_enabled:
        DemoFinding = namedtuple("DemoFinding", ["detector", "text"])
        scan_findings = [
            DemoFinding("email", "user@example.com"),
            DemoFinding("ssn", "123-45-6789"),
            DemoFinding("card", "4111 1111 1111 1111"),
            DemoFinding("email", "contact@company.org"),
            DemoFinding("ssn", "999-99-9999"),
        ]
        scan_elapsed_seconds = 1.23
        scan_safe_name = "demo_file.txt"

        reports_dir = Path("data/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        scan_report_path = reports_dir / scan_safe_name
        to_json(scan_findings, scan_report_path)

    else:
        max_megabytes = 5
        max_bytes = max_megabytes * 1024 * 1024
        file_bytes = uploaded_file.read()

        if len(file_bytes) > max_bytes:
            stream.error(
                "File too large. " f"Please upload a file under {max_megabytes} MB.",
            )
            stream.toast("That file exceeds the size limit.", icon="⚠️")
            stream.stop()

        allowed_mime_types = {
            "text/plain",
            "text/csv",
            "application/pdf",
        }
        mime_type, _ = mimetypes.guess_type(uploaded_file.name or "")
        if mime_type not in allowed_mime_types:
            stream.error("Unsupported file type.")
            stream.stop()

        scan_safe_name = safe_filename(uploaded_file.name or "upload")
        reports_dir = Path("data/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        with stream.status("Preparing to scan…", expanded=True) as status_ctx:
            scan_started_at = time.perf_counter()

            stream.write("• Saving upload to a secure temp file")
            with NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(file_bytes)
                temp_path = Path(temp_file.name)

            progress_bar = stream.progress(0)
            stream.write("• Extracting text & running detectors")
            progress_bar.progress(30)

            try:
                scan_findings = scan_file(temp_path)
            except Exception:
                get_logger("vaulty").exception(
                    "scan_failed file=%s",
                    scan_safe_name,
                )
                stream.error(
                    "Scan failed. The file may be encrypted or malformed.",
                )
                scan_findings = []
            finally:
                with suppress(Exception):
                    temp_path.unlink(missing_ok=True)

            scan_elapsed_seconds = time.perf_counter() - scan_started_at
            status_ctx.update(
                label=f"Scan complete in {scan_elapsed_seconds:.1f}s",
                state="complete",
            )
            progress_bar.progress(100)

        scan_report_path = reports_dir / f"{scan_safe_name}.json"
        to_json(scan_findings, scan_report_path)

    # -------------------------------------------------------------------------
    # Shared UI for both real and demo scans
    # -------------------------------------------------------------------------

    detector_counts = (
        Counter(finding.detector for finding in scan_findings) if scan_findings else Counter()
    )

    recent_scan_items = stream.session_state.setdefault("recent_scans", [])
    recent_scan_items.append(
        {
            "name": scan_safe_name,
            "elapsed": scan_elapsed_seconds,
            "count": len(scan_findings),
        },
    )
    if len(recent_scan_items) > 10:
        del recent_scan_items[:-10]

    tab_results, tab_findings, tab_report = stream.tabs(
        ["Results", "Findings", "Report"],
    )

    with tab_results:
        stream.subheader("Results")

        @stream.cache_data(ttl=30, show_spinner=False)
        def cached_summary(findings_input: Iterable[Any]) -> str:
            """Cache summary calls for short-term performance."""
            return human_summary(findings_input)

        stream.code(cached_summary(scan_findings))

    with tab_findings:
        stream.markdown("### Findings Summary")
        stream.markdown(
            f"""
            <div class="findings-wrap">
              <div class="frow">
                <div class="badge">
                  <span class="pill email">✉︎</span> Email
                </div>
                <div class="count">
                  {detector_counts.get('email', 0)}
                </div>
              </div>
              <div class="frow">
                <div class="badge">
                  <span class="pill ssn">◎</span> SSN
                </div>
                <div class="count">
                  {detector_counts.get('ssn', 0)}
                </div>
              </div>
              <div class="frow">
                <div class="badge">
                  <span class="pill card">■</span> Credit Card
                </div>
                <div class="count">
                  {detector_counts.get('card', 0)}
                </div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with tab_report:
        if scan_findings and scan_report_path is not None:
            stream.download_button(
                "⬇️ Download JSON Report",
                data=scan_report_path.read_bytes(),
                file_name=scan_report_path.name,
                mime="application/json",
                use_container_width=True,
                key="btn_download",
            )
            stream.toast(
                "Report ready. Stored only on your device.",
                icon="✅",
            )
        else:
            stream.info("No findings — nothing to report this time 🎉")

    stream.markdown(
        f'<div class="status-ok"><span class="checkbox"></span>'
        f" Scan completed in {scan_elapsed_seconds:.1f} seconds — "
        "No raw PII displayed.</div>",
        unsafe_allow_html=True,
    )
    stream.markdown(
        '<div class="privacy" style="max-width:600px;'
        'margin:8px auto 0 auto;">'
        "All scans processed locally — no data leaves your device."
        "</div>",
        unsafe_allow_html=True,
    )
