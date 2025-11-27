"""Vaulty Streamlit App (locally run DLP scanner UI).

This UI is designed for non-technical users:

1. Upload a TXT / CSV / PDF file.
2. Vaulty scans the file locally (no network calls).
3. The app shows a high-level summary and lets users download a JSON report.

Privacy:
    - No raw PII is shown in the UI.
    - All processing happens on the local machine.
    - JSON reports are written to data/reports/ only.
"""

from __future__ import annotations

import base64
import mimetypes
import time
from collections import Counter
from contextlib import suppress
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import streamlit as stream
from PIL import Image

from vaulty.detectors import Finding
from vaulty.reporting import human_summary, to_json
from vaulty.scanner import scan_file
from vaulty.utils import get_logger, safe_filename

# --- Caching Function Definition (Place this near the top with imports) ---


@stream.cache_resource
def load_static_image(path: Path):
    """Load a static image resource once and cache the result."""
    if path.exists():
        try:
            # Use PIL to open the image
            return Image.open(path)
        except Exception:
            # Return an emoji fallback if loading fails
            return "🔒"
    return "🔒"


# =============================================================================
# Page setup and global styling
# =============================================================================

base_dir = Path(__file__).resolve().parent
favicon_path = base_dir / "static" / "image" / "vaulty_favicon.png"

# 🛑 CRITICAL CHANGE: Assign the result of the cached function call
page_icon: Any = load_static_image(favicon_path)

# 🗑️ DELETE THE ORIGINAL LOADING BLOCK!
# You should remove the entire block below, as it is replaced by the cached function:
# if favicon_path.exists():
#     try:
#         page_icon = Image.open(favicon_path)
#     except Exception:
#         # Fall back to emoji if icon fails to load
#         page_icon = "🔒"

stream.set_page_config(
    page_title="Vaulty - DLP Scanner",
    page_icon=page_icon,
    layout="wide",
)

log = get_logger("vaulty")

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
# Scan options (UI-only toggles for now)
# =============================================================================

scan_options = stream.session_state.setdefault(
    "options",
    {"anonymize": True, "include_ipv4": False, "include_phone": True},
)


def render_scan_options() -> None:
    """Render the scan options controls (UI-only for now)."""
    stream.caption("Adjust what Vaulty looks for (local-only).")
    scan_options["anonymize"] = stream.toggle(
        "Anonymize any sample snippets (future redaction mode)",
        value=scan_options["anonymize"],
        key="opt_anon",
    )
    scan_options["include_ipv4"] = stream.toggle(
        "Detect IPv4 addresses (future rule set)",
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
            render_scan_options()
    except TypeError:
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
        '<div class="uhelp">Upload a TXT, CSV, or PDF file (≤ 5 MB)</div>',
        unsafe_allow_html=True,
    )

    uploaded_file = stream.file_uploader(
        "Upload a TXT, CSV, or PDF file (5 MB or less).",
        type=["txt", "csv", "pdf"],
        key=f"uploader_{stream.session_state.uploader_key}",
        label_visibility="collapsed",
    )

    col_left, col_scan, col_spacer, col_clear, col_right = stream.columns(
        [1, 1, 0.5, 1, 1],
    )
    with col_scan:
        scan_button_clicked = stream.button(
            "Scan Now",
            type="primary",
            use_container_width=True,
            key="btn_scan",
        )
    with col_clear:
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
# Demo mode toggle (uses real Finding objects, no real file)
# =============================================================================

demo_mode_enabled = stream.toggle(
    "💡 Demo Mode",
    value=False,
    help="Preview the UI with dummy scan data (no real file scan).",
)

if demo_mode_enabled:
    stream.toast("Running Vaulty in demo mode (no real scan).", icon="🧩")

# Prepare variables for later UI use so type checkers are happy.
scan_findings: list[Finding] = []
scan_elapsed_seconds: float = 0.0
scan_safe_name: str = "scan"
scan_report_path: Path | None = None

# =============================================================================
# Scan engine (real or demo)
# =============================================================================

if (uploaded_file and scan_button_clicked) or demo_mode_enabled:
    reports_dir = Path("data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    if demo_mode_enabled:
        # Demo mode: fabricate a few realistic findings using the real model.
        scan_safe_name = "demo_file.txt"
        scan_elapsed_seconds = 1.23
        scan_findings = [
            Finding(
                detector="email",
                match="user@example.com",
                start=10,
                end=26,
                risk_score=2.0,
                why="base=2.0 + context_boost=0.0",
            ),
            Finding(
                detector="ssn_us",
                match="123-45-6789",
                start=40,
                end=51,
                risk_score=4.0,
                why="base=4.0 + context_boost=0.0",
            ),
            Finding(
                detector="credit_card",
                match="4111 1111 1111 1111",
                start=80,
                end=99,
                risk_score=4.5,
                why="base=4.0 + context_boost=0.5",
            ),
        ]
        scan_report_path = reports_dir / f"{scan_safe_name}.json"
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

        with stream.status("Preparing to scan…", expanded=True) as status_ctx:
            scan_started_at = time.perf_counter()

            stream.write("• Saving upload to a secure temp file")

            # 🔧 IMPORTANT FIX: preserve original suffix so scanner picks extractor
            original_suffix = Path(uploaded_file.name or "upload").suffix
            with NamedTemporaryFile(
                delete=False,
                suffix=original_suffix,
            ) as temp_file:
                temp_file.write(file_bytes)
                temp_path = Path(temp_file.name)

            progress_bar = stream.progress(0)
            stream.write("• Extracting text & running detectors")
            progress_bar.progress(30)

            try:
                scan_findings = scan_file(temp_path)
            except Exception:
                log.exception("scan_failed file=%s", scan_safe_name)
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

    detector_counts = Counter(finding.detector for finding in scan_findings)

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
        stream.code(human_summary(scan_findings))

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
                  <span class="pill ssn">◎</span> SSN (US)
                </div>
                <div class="count">
                  {detector_counts.get('ssn_us', 0)}
                </div>
              </div>
              <div class="frow">
                <div class="badge">
                  <span class="pill card">■</span> Credit Card
                </div>
                <div class="count">
                  {detector_counts.get('credit_card', 0)}
                </div>
              </div>
              <div class="frow">
                <div class="badge">
                  <span class="pill phone">☎︎</span> Phone
                </div>
                <div class="count">
                  {detector_counts.get('phone', 0)}
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
