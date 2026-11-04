"""
PrivWatch 3.0 - Unit Tests for JSON, PDF, and CSV Exporters
"""

import json
import os
from pathlib import Path
import pytest

from core.models import Finding, Severity, SystemPosture
from reports.json_exporter import JSONExporter
from reports.pdf_generator import PDFGenerator
from reports.csv_exporter import CSVExporter


def test_json_exporter_produces_valid_json(temp_dir, sample_findings):
    out_file = str(temp_dir / "report.json")
    path = JSONExporter.export_findings(sample_findings, out_file, mode="red")

    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data['report_metadata']['platform'] == "PrivWatch"
    assert data['report_metadata']['version'] == "3.0.0"
    assert data['report_metadata']['total_findings'] == len(sample_findings)
    assert len(data['findings']) == len(sample_findings)


def test_pdf_generator_creates_valid_pdf_file(temp_dir, sample_findings):
    out_file = str(temp_dir / "report.pdf")
    path = PDFGenerator.generate_report(sample_findings, out_file, mode="red")

    assert os.path.exists(path)
    assert os.path.getsize(path) > 500

    # If ReportLab was used, file starts with %PDF-
    if path.endswith(".pdf"):
        with open(path, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"


def test_csv_exporter_creates_valid_csv(temp_dir, sample_findings):
    out_file = str(temp_dir / "report.csv")
    path = CSVExporter.export_findings(sample_findings, out_file)

    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    assert len(lines) == len(sample_findings) + 1  # Header + rows
    assert "finding_id,vector,severity" in lines[0]


def test_single_item_json_and_pdf_export(temp_dir, sample_findings):
    finding = sample_findings[0]

    # JSON export
    json_out = str(temp_dir / "single_finding.json")
    json_path = JSONExporter.export_item_json(finding, json_out)
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["report_metadata"]["platform"] == "UATU"
    assert data["report_metadata"]["item_type"] == "finding"
    assert "collection_limitations" in data["report_metadata"]
    assert data["evidence_hash"] is not None

    # PDF export
    pdf_out = str(temp_dir / "single_finding.pdf")
    pdf_path = PDFGenerator.generate_item_report(finding, pdf_out)
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 200


