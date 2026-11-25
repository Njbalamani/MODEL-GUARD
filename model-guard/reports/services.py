import hashlib
from io import BytesIO

from django.core.files.base import ContentFile
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from assessments.services import recalculate_assessment, visible_findings
from audit.notifications import notify
from reports.models import GeneratedReport
from reports.signing import sign_bytes


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="MGHeading", parent=styles["Heading1"], textColor=colors.HexColor("#0B1220"), fontSize=20))
    styles.add(ParagraphStyle(name="MGBody", parent=styles["BodyText"], alignment=TA_LEFT, fontSize=9, leading=12))
    styles.add(ParagraphStyle(name="MGSmall", parent=styles["BodyText"], fontSize=8, leading=10))
    return styles


def build_pdf_bytes(assessment):
    buffer = BytesIO()
    styles = _styles()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"ModelGuard Assessment {assessment.pk}",
    )
    story = []
    version = assessment.model_version
    story.append(Paragraph("ModelGuard Security Assessment", styles["MGHeading"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"Generated: {timezone.now().isoformat()}", styles["MGSmall"]))
    story.append(Spacer(1, 4 * mm))

    metadata = [
        ["Model", version.model.name],
        ["Version", version.version_label],
        ["Format", version.file_format],
        ["SHA-256", version.sha256],
        ["Assessment ID", str(assessment.pk)],
        ["Risk score", str(assessment.risk_score)],
        ["Status", assessment.status],
        ["Engine", assessment.engine_version],
    ]
    table = Table(metadata, colWidths=[38 * mm, 140 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8ECF3")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8C2D0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(table)
    story.append(Spacer(1, 5 * mm))

    findings = visible_findings(assessment)
    suppressed = assessment.findings.count() - len(findings)
    story.append(Paragraph("Findings", styles["Heading2"]))
    if not findings:
        story.append(Paragraph("No unsuppressed static or dynamic findings were recorded. This does not certify the model as secure.", styles["MGBody"]))
    else:
        rows = [["Severity", "Category", "Finding", "Recommendation"]]
        for item in findings:
            rows.append([
                item.severity,
                item.category,
                Paragraph(item.title, styles["MGSmall"]),
                Paragraph(item.recommendation, styles["MGSmall"]),
            ])
        finding_table = Table(rows, colWidths=[20 * mm, 28 * mm, 55 * mm, 75 * mm], repeatRows=1)
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16233A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8C2D0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))
        story.append(finding_table)
    if suppressed:
        story.append(Paragraph(f"{suppressed} suppressed finding(s) were excluded with approved expiring suppressions.", styles["MGSmall"]))

    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("Methodology", styles["Heading2"]))
    story.append(Paragraph(
        "Uploaded artifacts are inspected as bytes only. ModelGuard never deserializes or executes uploaded model files. "
        "Executable robustness, explainability and privacy demonstrations use synthetic data and a reconstructed model from a strictly validated descriptor.",
        styles["MGBody"],
    ))
    for test in assessment.robustness_tests.all():
        story.append(Paragraph(
            f"{test.attack}: status={test.status}, epsilon={test.epsilon}, steps={test.steps}, "
            f"accuracy {test.original_accuracy} to {test.perturbed_accuracy} (drop {test.accuracy_drop}).",
            styles["MGSmall"],
        ))
    if hasattr(assessment, "explainability"):
        story.append(Paragraph(f"Explainability method: {assessment.explainability.method}", styles["MGSmall"]))
    if hasattr(assessment, "privacy"):
        story.append(Paragraph(f"Privacy indicator: {assessment.privacy.indicator} (experimental)", styles["MGSmall"]))

    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Limitations", styles["Heading2"]))
    story.append(Paragraph(
        "Absence of findings is not proof of security. Results depend on descriptor validity, synthetic data quality and configured test parameters. "
        "Formal certification requires real data, isolated execution environments and manual review by qualified specialists.",
        styles["MGBody"],
    ))

    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Integrity", styles["Heading2"]))
    story.append(Paragraph(
        "The PDF body is hashed with SHA-256 and signed with an HMAC stored as metadata in ModelGuard. "
        "Use the report verification page to confirm that the stored file has not changed.",
        styles["MGSmall"],
    ))
    doc.build(story)
    data = buffer.getvalue()
    return data, hashlib.sha256(data).hexdigest()


def generate_report(assessment, generated_by):
    data, checksum = build_pdf_bytes(assessment)
    report = GeneratedReport(
        assessment=assessment,
        report_type="security-assessment",
        sha256=checksum,
        format="pdf",
        generated_by=generated_by,
        signature=sign_bytes(data),
        signature_algorithm="HMAC-SHA256",
        signed_at=timezone.now(),
    )
    report.file.save(f"modelguard-assessment-{assessment.pk}.pdf", ContentFile(data), save=True)
    recalculate_assessment(assessment)
    notify("report.generated", {
        "report_id": report.pk,
        "assessment_id": assessment.pk,
        "sha256": report.sha256,
        "signed": bool(report.signature),
    })
    return report
