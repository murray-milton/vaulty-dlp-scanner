"""Vaulty Streamlit App (Locally ran DLP scanner UI)."""

import streamlit as stream

"""This will be the basic page set-up for Vaulty demostration"""

stream.set_page_config(page_title="Vaulty - DLP Scanner", layout="centered")
stream.title("Vaulty 🔒")
stream.caption("Scan. Detect. Protect.")

""""""
doc_uploaded = stream.file_uploader(
    "Please upload a TXT, CSV, or PDF file (10MB or less).",
    type=["txt", "csv", "pdf"],
)
