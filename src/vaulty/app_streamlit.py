"""Vaulty Streamlit App (locally run DLP scanner UI)."""

from __future__ import annotations

import base64
import gc
import time
from collections import Counter
from contextlib import suppress
from pathlib import Path
from tempfile import NamedTemporaryFile

import altair as alt
import pandas as pd
import streamlit as stream

from vaulty.detectors import Finding
from vaulty.reporting import to_json
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


def redact_text(text: str, findings: list[Finding]) -> str:
    """Replace sensitive findings in text with [REDACTED]."""
    # Sort findings by start index descending to avoid slice offset issues
    sorted_findings = sorted(findings, key=lambda x: x.start, reverse=True)
    chars = list(text)
    for f in sorted_findings:
        # Safety check indices
        if f.start >= 0 and f.end <= len(chars):
            # Replace the slice with a redaction marker
            replacement = list(f"[REDACTED: {f.detector.upper()}]")
            chars[f.start : f.end] = replacement
    return "".join(chars)


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

    # 4. Sidebar Recent Scans (Executive Style)
    with stream.sidebar:
        # System Status Badge
        stream.success("🟢 System Online")
        stream.divider()

        stream.header("Your Session")
        recent_scan_items = stream.session_state.get("recent_scans", [])

        if not recent_scan_items:
            stream.caption("No files scanned yet.")
        else:
            stream.caption(f"Total Scans: {len(recent_scan_items)}")
            for scan_entry in recent_scan_items[-5:][::-1]:
                # Card style for history
                with stream.container(border=True):
                    stream.markdown(f"**{scan_entry['name']}**")
                    stream.markdown(
                        f"⏱️ {scan_entry['elapsed']:.2f}s | " f"🚩 {scan_entry['count']} Hits"
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
        return

    # 7. Scan Options
    scan_options = stream.session_state.setdefault(
        "options",
        {"anonymize": True, "include_ipv4": False, "include_phone": True},
    )

    with stream.expander("Scan options ⚙️"):
        stream.caption("Adjust what Vaulty looks for (local-only).")
        col_opt1, col_opt2 = stream.columns(2)
        with col_opt1:
            scan_options["anonymize"] = stream.toggle(
                "Anonymize sample snippets",
                value=scan_options["anonymize"],
                key="opt_anon",
            )
            scan_options["include_ipv4"] = stream.toggle(
                "Detect IPv4 addresses",
                value=scan_options["include_ipv4"],
                key="opt_ipv4",
            )
        with col_opt2:
            scan_options["include_phone"] = stream.toggle(
                "Detect phone numbers",
                value=scan_options["include_phone"],
                key="opt_phone",
            )

    # 8. File Uploader (Secure Gateway Style)
    with stream.container(border=True):
        col_icon, col_text = stream.columns([1, 8])
        with col_icon:
            # Large lock icon
            stream.markdown("<h1>🛡️</h1>", unsafe_allow_html=True)
        with col_text:
            stream.markdown("### Secure File Gateway")
            stream.caption(
                "Files are processed in ephemeral memory and "
                "discarded immediately after scanning."
            )

        uploaded_file = stream.file_uploader(
            "Drag and drop your file here",
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
    extracted_text = ""

    if (uploaded_file and scan_clicked) or demo_mode_enabled:
        reports_dir = Path("data/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        if demo_mode_enabled:
            # Demo Logic
            scan_safe_name = "demo_file.txt"
            scan_elapsed_seconds = 1.23
            scan_findings = [
                Finding(
                    "email", "user@example.com", 10, 26, 2.0, "Detected email address in document"
                ),
                Finding("ssn_us", "123-45-6789", 40, 51, 4.0, "Dectected what appears to be a SSN"),
                Finding(
                    "credit_card",
                    "4111 1111 1111 1111",
                    80,
                    99,
                    4.5,
                    "Risk elevated: Found sensitive context keyword 'visa' nearby.",
                ),
                Finding(
                    "aws_key",
                    "AKIAIOSFODNN7EXAMPLE",
                    150,
                    170,
                    10.0,
                    "Critical: High-entropy pattern matches known secret format.",
                ),
            ]
            extracted_text = (
                "This is a demo file. Contact user@example.com or use "
                "SSN 123-45-6789. Card: 4111 1111 1111 1111. "
                "AWS Key: AKIAIOSFODNN7EXAMPLE end."
            )
            scan_report_path = reports_dir / f"{scan_safe_name}.json"
            to_json(scan_findings, scan_report_path)

        else:
            # Real File Scan
            try:
                file_bytes = uploaded_file.getvalue()
                if len(file_bytes) > 5 * 1024 * 1024:
                    stream.error("File too large (>5MB).")
                    stream.stop()

                scan_safe_name = safe_filename(uploaded_file.name)

                with stream.status("Scanning...", expanded=True):
                    start_time = time.perf_counter()

                    suffix = Path(uploaded_file.name).suffix
                    tmp_path = None
                    try:
                        with NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                            tmp.write(file_bytes)
                            tmp_path = Path(tmp.name)

                        scan_findings, extracted_text = scan_file(tmp_path)

                    except Exception as e:
                        log.exception("Scan failed")
                        stream.error(f"Scan failed: {e}")
                        scan_findings = []
                        extracted_text = ""
                    finally:
                        if tmp_path:
                            with suppress(Exception):
                                tmp_path.unlink()
                        gc.collect()

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
        tab_res, tab_find, tab_ctx, tab_rep = stream.tabs(
            ["Overview 📊", "Findings 🔍", "Sanitize 🛡️", "JSON Report 📥"]
        )

        # Tab 1: Overview (Executive Donut Chart)
        with tab_res:
            stream.subheader("Scan Overview")

            col_m1, col_m2 = stream.columns(2)
            col_m1.metric("Total Findings", len(scan_findings))
            col_m1.metric("Scan Time", f"{scan_elapsed_seconds:.2f}s")

            stream.divider()

            counts = Counter(f.detector for f in scan_findings)

            if counts:
                # Pretty Labels Mapping
                label_map = {
                    "email": "📧 Email Addresses",
                    "ssn_us": "🇺🇸 Social Security Numbers",
                    "credit_card": "💳 Credit Card Numbers",
                    "phone": "☎️ Phone Numbers",
                    "aws_key": "🔑 AWS Access Keys",
                    "api_key": "🛡️ Generic API Secrets",
                }

                data = []
                for key, count in counts.items():
                    clean_label = label_map.get(key, key.replace("_", " ").title())
                    data.append({"Risk Type": clean_label, "Count": count})

                df = pd.DataFrame(data)

                # --- High-End Donut Chart ---
                base = alt.Chart(df).encode(theta=alt.Theta("Count", stack=True))

                pie = base.mark_arc(outerRadius=120, innerRadius=80).encode(
                    color=alt.Color(
                        "Risk Type",
                        scale=alt.Scale(scheme="reds"),
                        legend=alt.Legend(title="Risk Categories", orient="right"),
                    ),
                    order=alt.Order("Count", sort="descending"),
                    tooltip=["Risk Type", "Count"],
                )

                # Center Text (Total)
                text = (
                    alt.Chart(pd.DataFrame({"text": [sum(counts.values())]}))
                    .mark_text(
                        align="center",
                        fontSize=30,
                        fontWeight="bold",
                        color="#ff4b4b",
                    )
                    .encode(text="text")
                )

                # Center Label ("Risks")
                subtext = (
                    alt.Chart(pd.DataFrame({"text": ["Risks"]}))
                    .mark_text(align="center", dy=20, fontSize=14, color="gray")
                    .encode(text="text")
                )

                chart = (pie + text + subtext).properties(title="")
                stream.altair_chart(chart, use_container_width=True)

            else:
                stream.info("No sensitive data found! 🎉")

        # Tab 2: Findings List (Risk Thermometer)
        with tab_find:
            if scan_findings:
                stream.write("### Detailed Findings")
                for f in scan_findings:
                    # Determine color/icon based on score
                    if f.risk_score >= 8.0:
                        risk_color = "🔴"
                        risk_label = "CRITICAL"
                    elif f.risk_score >= 4.0:
                        risk_color = "🟠"
                        risk_label = "HIGH"
                    else:
                        risk_color = "🟡"
                        risk_label = "MEDIUM"

                    header_text = (
                        f"{risk_color} [{risk_label}] {f.detector.upper()} "
                        f"— Found at index {f.start}"
                    )

                    with stream.expander(header_text):
                        col_a, col_b = stream.columns([3, 1])
                        with col_a:
                            stream.markdown(f"**Match:** `{f.match}`")
                            stream.markdown(f"**Context:** Found near index {f.start}")
                            stream.caption(f"Detector Logic: {f.why}")
                        with col_b:
                            stream.metric("Risk Score", f"{f.risk_score}/10")
                            # Visual danger meter
                            stream.progress(min(f.risk_score / 10.0, 1.0))
            else:
                stream.info("No findings to list.")

        # Tab 3: Context & Redaction
        with tab_ctx:
            if extracted_text and scan_findings:
                stream.write("### Sanitized Preview")
                stream.caption("Below is a preview of your file with sensitive " "data redacted.")

                redacted_content = redact_text(extracted_text, scan_findings)

                stream.text_area(
                    "Preview",
                    value=redacted_content[:2000] + ("..." if len(redacted_content) > 2000 else ""),
                    height=250,
                    disabled=True,
                )

                stream.download_button(
                    "⬇️ Download Redacted File (.txt)",
                    data=redacted_content,
                    file_name=f"REDACTED_{scan_safe_name}.txt",
                    mime="text/plain",
                )
            elif not extracted_text:
                stream.warning("Text extraction failed or was empty.")
            else:
                stream.success("File is clean! No redaction needed.")

        # Tab 4: JSON Report
        with tab_rep:
            if scan_findings and scan_report_path:
                stream.download_button(
                    "⬇️ Download Full JSON Report",
                    data=scan_report_path.read_bytes(),
                    file_name=f"{scan_safe_name}.json",
                    mime="application/json",
                    use_container_width=True,
                )
                stream.json([f.to_dict() for f in scan_findings])
            else:
                stream.info("No report generated.")

        gc.collect()


if __name__ == "__main__":
    main()
