"""Vaulty Streamlit App (locally run DLP scanner UI)."""

from __future__ import annotations

import base64
import gc
import time
from contextlib import suppress
from pathlib import Path
from tempfile import NamedTemporaryFile

import streamlit as stream

# Core imports
from vaulty.detectors import Finding
from vaulty.reporting import human_summary, to_json
from vaulty.scanner import scan_file
from vaulty.utils import get_logger, safe_filename

# --- Caching Functions ---


@stream.cache_resource
def load_and_encode_logo(logo_path: Path) -> str | None:
    """Load the logo and return the base64 encoded string once, safely."""
    if logo_path.exists():
        try:
            return base64.b64encode(logo_path.read_bytes()).decode("utf-8")
        except Exception:
            return None
    return None


@stream.cache_resource
def get_cached_logger(name: str):
    """Initializes and caches the logger."""
    return get_logger(name)


# --- Main Application Logic Wrapped in a Function ---


def main():
    # 1. Page Config
    stream.set_page_config(
        page_title="Vaulty - DLP Scanner",
        page_icon="🔒",
        layout="wide",
    )

    # 2. Logger & Styles
    log = get_cached_logger("vaulty")
    base_dir = Path(__file__).resolve().parent

    css_path = base_dir / "static" / "style.css"
    if css_path.exists():
        stream.markdown(
            f"<style>{css_path.read_text()}</style>",
            unsafe_allow_html=True,
        )

    # 3. Logo Handling
    logo_path = base_dir / "static" / "image" / "Vaulty Logo.svg"
    encoded_logo_svg = load_and_encode_logo(logo_path)

    if encoded_logo_svg:
        # Split long style string to satisfy linter
        img_style = (
            "width:320px; max-width:95%; height:auto; "
            "filter: drop-shadow(0px 3px 6px rgba(0,0,0,0.10));"
        )
        logo_html = f"""
        <div style="text-align:center; margin-top:10px; margin-bottom:10px;">
          <img src="data:image/svg+xml;base64,{encoded_logo_svg}" alt="Vaulty Logo"
               style="{img_style}">
        </div>
        """
        stream.markdown(logo_html, unsafe_allow_html=True)
        with stream.sidebar:
            stream.markdown(logo_html, unsafe_allow_html=True)

    stream.markdown(
        '<div class="vaulty-title">' "Vaulty 🔒 — Data Loss Prevention File Scanner</div>",
        unsafe_allow_html=True,
    )
    stream.markdown(
        '<div class="vaulty-subnav">Scan · Detect · Protect</div>',
        unsafe_allow_html=True,
    )

    # 4. Sidebar Recent Scans
    with stream.sidebar:
        stream.header("Recent scans")
        recent_scan_items = stream.session_state.get("recent_scans", [])
        if not recent_scan_items:
            stream.caption("No scans yet.")
        else:
            for scan_entry in recent_scan_items[-10:][::-1]:
                stream.write(
                    f"• `{scan_entry['name']}` — "
                    f"{scan_entry['elapsed']:.1f}s, "
                    f"{scan_entry['count']} finding(s)"
                )

    # 5. Session State Init
    if "onboarded" not in stream.session_state:
        stream.session_state.onboarded = False
    if "uploader_key" not in stream.session_state:
        stream.session_state.uploader_key = 0

    # 6. Onboarding / Main UI
    if not stream.session_state.get("onboarded", False):
        with stream.container(border=True):
            stream.subheader("Welcome to Vaulty 🔒")
            stream.write(
                "All scans are performed **locally**. " "No files or results leave your device."
            )
            stream.write("You can adjust detection via **Scan options ⚙️** below.")
            if stream.button("Got it", type="primary", key="welcome_ok"):
                stream.session_state.onboarded = True
                stream.rerun()
        # Return here so we don't render the rest of the app until onboarded
        return

    # 7. Scan Options
    scan_options = stream.session_state.setdefault(
        "options",
        {"anonymize": True, "include_ipv4": False, "include_phone": True},
    )

    with stream.expander("Scan options ⚙️"):
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

    # 8. File Uploader
    with stream.container():
        stream.markdown(
            '<div class="vaulty-card"><div class="uicon">⬆️</div>'
            '<div class="uhelp">Upload a TXT, CSV, or PDF file (≤ 5 MB)</div>',
            unsafe_allow_html=True,
        )

        uploaded_file = stream.file_uploader(
            "Upload a TXT, CSV, or PDF file",
            type=["txt", "csv", "pdf"],
            key=f"uploader_{stream.session_state.uploader_key}",
            label_visibility="collapsed",
        )

        col1, col2 = stream.columns([1, 1])
        with col1:
            scan_clicked = stream.button(
                "Scan Now",
                type="primary",
                use_container_width=True,
                key="btn_scan",
            )
        with col2:
            clear_clicked = stream.button(
                "Clear File",
                use_container_width=True,
                key="btn_clear",
            )

        stream.markdown("</div>", unsafe_allow_html=True)

    if clear_clicked:
        stream.session_state.uploader_key += 1
        stream.toast("Cleared.", icon="🧹")
        gc.collect()
        stream.rerun()

    # 9. Demo Mode
    demo_mode_enabled = stream.toggle(
        "💡 Demo Mode",
        value=False,
        help="Preview the UI with dummy scan data.",
    )
    if demo_mode_enabled:
        stream.toast("Running Vaulty in demo mode (no real scan).", icon="🧩")

    # 10. Scan Logic
    scan_findings = []
    scan_elapsed_seconds = 0.0
    scan_safe_name = "scan"

    if (uploaded_file and scan_clicked) or demo_mode_enabled:
        reports_dir = Path("data/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        if demo_mode_enabled:
            # Demo Logic
            scan_safe_name = "demo_file.txt"
            scan_elapsed_seconds = 1.23
            scan_findings = [
                Finding("email", "user@example.com", 10, 26, 2.0, "base=2.0"),
                Finding("ssn_us", "123-45-6789", 40, 51, 4.0, "base=4.0"),
                Finding(
                    "credit_card",
                    "4111 1111 1111 1111",
                    80,
                    99,
                    4.5,
                    "base=4.0+boost",
                ),
            ]
            scan_report_path = reports_dir / f"{scan_safe_name}.json"
            to_json(scan_findings, scan_report_path)

        else:
            # Real File Scan
            try:
                # File Size Check
                file_bytes = uploaded_file.getvalue()
                if len(file_bytes) > 5 * 1024 * 1024:
                    stream.error("File too large (>5MB).")
                    stream.stop()

                scan_safe_name = safe_filename(uploaded_file.name)

                with stream.status("Scanning...", expanded=True):
                    start_time = time.perf_counter()

                    # Save to temp file
                    suffix = Path(uploaded_file.name).suffix
                    tmp_path = None
                    try:
                        with NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                            tmp.write(file_bytes)
                            tmp_path = Path(tmp.name)

                        # RUN SCAN
                        scan_findings = scan_file(tmp_path)

                    except Exception as e:
                        log.exception("Scan failed")
                        stream.error(f"Scan failed: {e}")
                        scan_findings = []
                    finally:
                        if tmp_path:
                            with suppress(Exception):
                                tmp_path.unlink()
                        gc.collect()  # Force cleanup immediately

                    scan_elapsed_seconds = time.perf_counter() - start_time

                scan_report_path = reports_dir / f"{scan_safe_name}.json"
                to_json(scan_findings, scan_report_path)

            except Exception as e:
                stream.error(f"Critical error: {e}")

        # 11. Results Display

        # Update Recent Scans
        recent = stream.session_state.setdefault("recent_scans", [])
        recent.append(
            {
                "name": scan_safe_name,
                "elapsed": scan_elapsed_seconds,
                "count": len(scan_findings),
            }
        )
        if len(recent) > 10:
            del recent[:-10]

        # Tabs
        tab_res, tab_find, tab_rep = stream.tabs(["Results", "Findings", "Report"])

        with tab_res:
            stream.subheader("Results")
            stream.code(human_summary(scan_findings))

        with tab_find:
            for f in scan_findings:
                stream.json(f.to_dict())

        with tab_rep:
            if scan_findings and scan_report_path:
                # Use updated reporting function if possible, or read bytes
                stream.download_button(
                    "⬇️ Download JSON Report",
                    data=scan_report_path.read_bytes(),
                    file_name=f"{scan_safe_name}.json",
                    mime="application/json",
                    use_container_width=True,
                )
            else:
                stream.info("No findings.")

        gc.collect()


if __name__ == "__main__":
    main()
