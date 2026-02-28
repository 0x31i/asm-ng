"""Excel formatting and styling utilities for scan exports.

Provides openpyxl styling helpers, color definitions, and sheet builders
for producing professionally formatted Excel workbooks with tab colors,
severity color-coding, and an Executive Summary with grade visualization.
"""

import re

from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.chart import BarChart, Reference
from openpyxl.chart.series import DataPoint
from openpyxl.formatting.rule import DataBarRule
from openpyxl.worksheet.table import Table, TableStyleInfo

# Regex matching XML-illegal control characters that openpyxl rejects.
# Covers: 0x00-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F-0x84, 0x86-0x9F
_ILLEGAL_XML_CHARS_RE = re.compile(
    r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]'
)


def _safe_str(value) -> str:
    """Convert a value to a string safe for openpyxl worksheet cells.

    Strips illegal XML control characters that cause
    openpyxl.utils.exceptions.IllegalCharacterError.
    """
    s = str(value)
    return _ILLEGAL_XML_CHARS_RE.sub('', s)


# ============================================================================
# COLOR UTILITIES
# ============================================================================

def hex_to_argb(hex_color: str) -> str:
    """Convert '#RRGGBB' or 'RRGGBB' to openpyxl ARGB string 'FFRRGGBB'."""
    c = hex_color.lstrip('#')
    return f"FF{c.upper()}"


def set_tab_color(ws, hex_color: str):
    """Set the worksheet tab color.

    Args:
        ws: openpyxl Worksheet
        hex_color: '#RRGGBB' or 'RRGGBB' hex color string
    """
    ws.sheet_properties.tabColor = hex_color.lstrip('#')


# ============================================================================
# SEVERITY / RISK COLORS (mirrors CSS .sev-* classes)
# ============================================================================

SEVERITY_COLORS = {
    'CRITICAL': '#8b5cf6',
    'HIGH':     '#ef4444',
    'MEDIUM':   '#f59e0b',
    'LOW':      '#3b82f6',
    'INFO':     '#22c55e',
}

SEVERITY_TEXT_COLORS = {
    'CRITICAL': '#FFFFFF',
    'HIGH':     '#FFFFFF',
    'MEDIUM':   '#000000',
    'LOW':      '#FFFFFF',
    'INFO':     '#FFFFFF',
}

RISK_COLORS = {
    'CRITICAL':  '#8b5cf6',
    'HIGH':     '#ef4444',
    'MEDIUM':   '#f59e0b',
    'LOW':      '#3b82f6',
    'INFO':     '#22c55e',
}

GRADE_METRIC_COLORS = {
    'A': '#22c55e',
    'B': '#3b82f6',
    'C': '#f59e0b',
    'D': '#f97316',
    'F': '#ef4444',
}

# ============================================================================
# COMMON STYLE ELEMENTS
# ============================================================================

HEADER_FONT = Font(name='Calibri', size=11, bold=True, color='FFFFFFFF')
HEADER_FILL = PatternFill(start_color='FF1F2937', end_color='FF1F2937', fill_type='solid')
HEADER_ALIGNMENT = Alignment(horizontal='left', vertical='center', wrap_text=True)

THIN_BORDER = Border(
    bottom=Side(style='thin', color='FFE5E7EB'),
)

DATA_FONT = Font(name='Calibri', size=10)
DATA_ALIGNMENT = Alignment(horizontal='left', vertical='top', wrap_text=True)

ALT_ROW_FILL = PatternFill(start_color='FFF9FAFB', end_color='FFF9FAFB', fill_type='solid')
DEFAULT_FONT = Font()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def apply_header_row(ws, headers: list, row: int = 1):
    """Apply dark header styling to a row of cells."""
    for col_num, header_text in enumerate(headers, 1):
        cell = ws.cell(row=row, column=col_num, value=header_text)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.alignment = HEADER_ALIGNMENT
        cell.border = THIN_BORDER


def apply_severity_fill(cell, severity: str):
    """Apply severity-appropriate background fill and font color to a cell."""
    sev = severity.upper().strip()
    bg = SEVERITY_COLORS.get(sev)
    fg = SEVERITY_TEXT_COLORS.get(sev)
    if bg:
        cell.fill = PatternFill(
            start_color=hex_to_argb(bg),
            end_color=hex_to_argb(bg),
            fill_type='solid',
        )
    if fg:
        cell.font = Font(name='Calibri', size=10, bold=True, color=hex_to_argb(fg))


def freeze_header(ws, row: int = 2):
    """Freeze panes below a header row."""
    ws.freeze_panes = f'A{row}'


def apply_alternating_rows(ws, start_row: int, end_row: int):
    """Apply subtle alternating row fill for readability.

    Only applies to even rows and skips cells that already have an
    explicit fill (e.g., severity color-coding).
    """
    for row_idx in range(start_row, end_row + 1):
        if row_idx % 2 == 0:
            for cell in ws[row_idx]:
                # Skip cells that already have an explicit fill applied.
                # A cell with no explicit fill has fill_type=None.
                if cell.fill.fill_type is None:
                    cell.fill = ALT_ROW_FILL


def _make_table_name(base_name: str) -> str:
    """Create a valid Excel table displayName from a base string.

    Table names must start with a letter/underscore and contain only
    alphanumeric characters, underscores, and periods.
    """
    name = ''.join(c if c.isalnum() or c == '_' else '_' for c in base_name)
    if not name or name[0].isdigit():
        name = f"T_{name}"
    return name[:255]


def add_data_table(ws, header_row: int, num_data_rows: int, num_columns: int):
    """Add an Excel Table (ListObject) for sorting and filtering.

    Creates a proper Excel table starting at the header row, which enables
    column sorting, auto-filter dropdowns, and structured references.
    Uses a minimal table style so our manual cell formatting is preserved.

    Args:
        ws: openpyxl Worksheet
        header_row: 1-indexed row number where the headers are
        num_data_rows: number of data rows (excluding the header row)
        num_columns: total number of columns
    """
    if num_data_rows < 1:
        return

    try:
        last_row = header_row + num_data_rows
        last_col = get_column_letter(num_columns)
        ref = f"A{header_row}:{last_col}{last_row}"

        table_name = _make_table_name(ws.title)

        style = TableStyleInfo(
            name="TableStyleLight1",
            showFirstColumn=False,
            showLastColumn=False,
            showRowStripes=False,
            showColumnStripes=False,
        )

        table = Table(displayName=table_name, ref=ref)
        table.tableStyleInfo = style
        ws.add_table(table)
    except Exception:
        pass  # Non-fatal: table is cosmetic, data is still there


# ============================================================================
# EXECUTIVE SUMMARY SHEET BUILDER
# ============================================================================

def build_executive_summary(ws, grade_data: dict, scan_info: dict,
                            findings_rows: list = None,
                            correlation_rows: list = None,
                            snapshot_data: dict = None):
    """Build the Executive Summary worksheet with grade visualization.

    Args:
        ws: openpyxl Worksheet (should be the active/first sheet)
        grade_data: output from calculate_full_grade() -- must contain
                    'overall_grade', 'overall_score', 'overall_grade_color',
                    'overall_grade_bg', and 'categories' dict
        scan_info: dict with keys 'name', 'target', 'date'
        findings_rows: list of finding rows for summary statistics
        correlation_rows: list of correlation rows for summary statistics
        snapshot_data: dict with trend data for the SNAPSHOT panel (optional)
    """
    findings_rows = findings_rows or []
    correlation_rows = correlation_rows or []

    set_tab_color(ws, '16a34a')

    dark_fill = PatternFill(start_color='FF1F2937', end_color='FF1F2937', fill_type='solid')
    subtle_border = Border(bottom=Side(style='thin', color='FFD1D5DB'))
    section_border = Border(bottom=Side(style='medium', color='FF9CA3AF'))
    label_font = Font(name='Calibri', size=10, bold=True, color='FF6B7280')
    value_font = Font(name='Calibri', size=10, color='FF374151')

    # ── Row 1: Title banner ──────────────────────────────────────────────
    ws.merge_cells('A1:G1')
    title_cell = ws['A1']
    title_cell.value = 'EXECUTIVE SUMMARY'
    title_cell.font = Font(name='Calibri', size=18, bold=True, color='FFFFFFFF')
    title_cell.fill = dark_fill
    title_cell.alignment = Alignment(horizontal='left', vertical='center')
    ws.row_dimensions[1].height = 36
    for c in range(2, 8):
        ws.cell(row=1, column=c).fill = dark_fill

    # ── Row 2: Scan metadata (single row) ────────────────────────────────
    ws.row_dimensions[2].height = 22
    ws.cell(row=2, column=1, value='Target:').font = label_font
    ws.cell(row=2, column=2, value=scan_info.get('target', '')).font = value_font
    ws.cell(row=2, column=4, value='Scan:').font = label_font
    ws.cell(row=2, column=5, value=scan_info.get('name', '')).font = value_font
    ws.cell(row=2, column=6, value='Date:').font = label_font
    ws.cell(row=2, column=7, value=scan_info.get('date', '')).font = value_font
    for c in range(1, 8):
        ws.cell(row=2, column=c).border = subtle_border

    # ── Rows 3-5: Grade block ────────────────────────────────────────────
    overall_grade = grade_data.get('overall_grade', '-')
    overall_score = grade_data.get('overall_score', 0)
    grade_color = grade_data.get('overall_grade_color', '#6b7280')
    grade_bg = grade_data.get('overall_grade_bg', '#f3f4f6')

    ws.row_dimensions[3].height = 8  # spacer

    ws.merge_cells('A4:A6')
    grade_cell = ws['A4']
    grade_cell.value = overall_grade
    grade_cell.font = Font(name='Calibri', size=36, bold=True, color=hex_to_argb(grade_color))
    grade_cell.fill = PatternFill(
        start_color=hex_to_argb(grade_bg),
        end_color=hex_to_argb(grade_bg),
        fill_type='solid',
    )
    grade_cell.alignment = Alignment(horizontal='center', vertical='center')
    grade_bdr = Border(
        left=Side(style='thick', color=hex_to_argb(grade_color)),
        right=Side(style='thick', color=hex_to_argb(grade_color)),
        top=Side(style='thick', color=hex_to_argb(grade_color)),
        bottom=Side(style='thick', color=hex_to_argb(grade_color)),
    )
    grade_cell.border = grade_bdr
    for ri in range(4, 7):
        ws.row_dimensions[ri].height = 22

    ws.cell(row=4, column=2, value='Overall Score').font = Font(
        name='Calibri', size=9, color='FF9CA3AF')
    ws.cell(row=5, column=2, value=overall_score).font = Font(
        name='Calibri', size=20, bold=True, color=hex_to_argb(grade_color))
    ws.cell(row=5, column=2).number_format = '0.0'

    # Per-category mini scores beside the grade
    cat_results = grade_data.get('categories', {})
    sorted_cats = sorted(
        cat_results.items(),
        key=lambda x: (-x[1].get('weight', 0), x[0]),
    )
    if sorted_cats:
        col = 3
        for cat_name, cat_data in sorted_cats:
            if col > 7:
                break
            cat_c = cat_data.get('color', '#6b7280')
            cat_g = cat_data.get('grade', '-')
            ws.cell(row=4, column=col, value=cat_name).font = Font(
                name='Calibri', size=8, color=hex_to_argb(cat_c))
            ws.cell(row=4, column=col).alignment = Alignment(horizontal='center')
            grade_badge = ws.cell(row=5, column=col, value=cat_g)
            grade_badge.font = Font(name='Calibri', size=11, bold=True,
                                    color=hex_to_argb(cat_data.get('grade_color', '#6b7280')))
            grade_badge.fill = PatternFill(
                start_color=hex_to_argb(cat_data.get('grade_bg', '#ffffff')),
                end_color=hex_to_argb(cat_data.get('grade_bg', '#ffffff')),
                fill_type='solid',
            )
            grade_badge.alignment = Alignment(horizontal='center')
            sc = ws.cell(row=6, column=col, value=cat_data.get('score', 0))
            sc.font = Font(name='Calibri', size=8, color='FF9CA3AF')
            sc.number_format = '0.0'
            sc.alignment = Alignment(horizontal='center')
            col += 1

    # ── Row 7: Section divider ───────────────────────────────────────────
    ws.row_dimensions[7].height = 6
    for c in range(1, 8):
        ws.cell(row=7, column=c).border = section_border

    # ── FINDINGS SECTION (rows 8-12) ─────────────────────────────────────
    r = 8
    # Findings banner
    ws.merge_cells(f'A{r}:G{r}')
    findings_banner = ws.cell(row=r, column=1, value=f'FINDINGS  ({len(findings_rows)} total)')
    findings_banner.font = Font(name='Calibri', size=12, bold=True, color='FFFFFFFF')
    findings_banner.fill = PatternFill(start_color='FF111827', end_color='FF111827', fill_type='solid')
    findings_banner.alignment = Alignment(horizontal='left', vertical='center')
    for c in range(2, 8):
        ws.cell(row=r, column=c).fill = PatternFill(
            start_color='FF111827', end_color='FF111827', fill_type='solid')
    ws.row_dimensions[r].height = 26
    r += 1

    # Severity counts for findings
    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for row in findings_rows:
        sev = str(row[0]).upper().strip() if row else ''
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Row of severity labels
    sev_col = 1
    for sev_name in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        badge = ws.cell(row=r, column=sev_col, value=sev_name)
        badge.font = Font(name='Calibri', size=9, bold=True,
                          color=hex_to_argb(SEVERITY_TEXT_COLORS[sev_name]))
        badge.fill = PatternFill(
            start_color=hex_to_argb(SEVERITY_COLORS[sev_name]),
            end_color=hex_to_argb(SEVERITY_COLORS[sev_name]),
            fill_type='solid',
        )
        badge.alignment = Alignment(horizontal='center')
        sev_col += 1
    ws.row_dimensions[r].height = 20
    r += 1

    # Row of severity counts
    sev_col = 1
    for sev_name in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        cnt = ws.cell(row=r, column=sev_col, value=sev_counts[sev_name])
        cnt.font = Font(name='Calibri', size=14, bold=True, color='FF1F2937')
        cnt.alignment = Alignment(horizontal='center')
        cnt.border = subtle_border
        sev_col += 1
    ws.row_dimensions[r].height = 24
    r += 1

    # Spacer
    ws.row_dimensions[r].height = 10
    r += 1

    # ── CORRELATIONS SECTION (rows 12-16) ────────────────────────────────
    # Correlations banner - distinct color (dark slate/purple tint)
    ws.merge_cells(f'A{r}:G{r}')
    corr_banner = ws.cell(row=r, column=1, value=f'CORRELATIONS  ({len(correlation_rows)} total)')
    corr_banner.font = Font(name='Calibri', size=12, bold=True, color='FFFFFFFF')
    corr_banner.fill = PatternFill(start_color='FF374151', end_color='FF374151', fill_type='solid')
    corr_banner.alignment = Alignment(horizontal='left', vertical='center')
    for c in range(2, 8):
        ws.cell(row=r, column=c).fill = PatternFill(
            start_color='FF374151', end_color='FF374151', fill_type='solid')
    ws.row_dimensions[r].height = 26
    r += 1

    # Risk counts for correlations
    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for row in correlation_rows:
        risk = str(row[2]).upper().strip() if len(row) > 2 else ''
        if risk in risk_counts:
            risk_counts[risk] += 1

    # Row of risk labels
    risk_col = 1
    for risk_name in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        badge = ws.cell(row=r, column=risk_col, value=risk_name)
        badge.font = Font(name='Calibri', size=9, bold=True, color='FFFFFFFF')
        badge.fill = PatternFill(
            start_color=hex_to_argb(RISK_COLORS[risk_name]),
            end_color=hex_to_argb(RISK_COLORS[risk_name]),
            fill_type='solid',
        )
        badge.alignment = Alignment(horizontal='center')
        risk_col += 1
    ws.row_dimensions[r].height = 20
    r += 1

    # Row of risk counts
    risk_col = 1
    for risk_name in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        cnt = ws.cell(row=r, column=risk_col, value=risk_counts[risk_name])
        cnt.font = Font(name='Calibri', size=14, bold=True, color='FF1F2937')
        cnt.alignment = Alignment(horizontal='center')
        cnt.border = subtle_border
        risk_col += 1
    ws.row_dimensions[r].height = 24
    r += 1

    # Spacer + section divider
    ws.row_dimensions[r].height = 6
    for c in range(1, 8):
        ws.cell(row=r, column=c).border = section_border
    r += 1

    # ── Top Risks ──────────────────────────────────────────────────────
    ws.merge_cells(f'A{r}:G{r}')
    ws.cell(row=r, column=1, value='TOP RISKS').font = Font(
        name='Calibri', size=11, bold=True, color='FFDC2626')
    ws.cell(row=r, column=1).border = Border(
        bottom=Side(style='thin', color='FFDC2626'))
    for c in range(2, 8):
        ws.cell(row=r, column=c).border = Border(
            bottom=Side(style='thin', color='FFDC2626'))
    ws.row_dimensions[r].height = 22
    r += 1

    if sorted_cats:
        worst_cats = sorted(sorted_cats, key=lambda x: x[1].get('score', 100))[:3]
        for i, (cname, cdata) in enumerate(worst_cats):
            cscore = cdata.get('score', 0)
            cgrade = cdata.get('grade', '-')
            ccolor = cdata.get('color', '#6b7280')
            cgrade_color = cdata.get('grade_color', '#6b7280')
            cgrade_bg = cdata.get('grade_bg', '#ffffff')

            ws.cell(row=r, column=1, value=f'{i + 1}.').font = Font(
                name='Calibri', size=10, bold=True, color='FF9CA3AF')
            ws.cell(row=r, column=2, value=cname).font = Font(
                name='Calibri', size=10, bold=True, color=hex_to_argb(ccolor))
            ws.cell(row=r, column=3, value=cscore).font = Font(
                name='Calibri', size=10, color='FF6B7280')
            ws.cell(row=r, column=3).number_format = '0.0'
            g_cell = ws.cell(row=r, column=4, value=cgrade)
            g_cell.font = Font(name='Calibri', size=10, bold=True,
                               color=hex_to_argb(cgrade_color))
            g_cell.fill = PatternFill(
                start_color=hex_to_argb(cgrade_bg),
                end_color=hex_to_argb(cgrade_bg),
                fill_type='solid',
            )
            g_cell.alignment = Alignment(horizontal='center')
            desc = cdata.get('description', '')
            if desc:
                ws.merge_cells(start_row=r, start_column=5, end_row=r, end_column=7)
                ws.cell(row=r, column=5, value=desc).font = Font(
                    name='Calibri', size=8, italic=True, color='FF9CA3AF')
            for c in range(1, 8):
                ws.cell(row=r, column=c).border = subtle_border
            r += 1
    else:
        ws.cell(row=r, column=1, value='No category data available.').font = Font(
            name='Calibri', size=10, italic=True, color='FF9CA3AF')
        r += 1

    # ── Section divider ──────────────────────────────────────────────────
    ws.row_dimensions[r].height = 6
    for c in range(1, 8):
        ws.cell(row=r, column=c).border = section_border
    r += 1

    # ── Category Breakdown table ─────────────────────────────────────────
    ws.merge_cells(f'A{r}:G{r}')
    ws.cell(row=r, column=1, value='CATEGORY BREAKDOWN').font = Font(
        name='Calibri', size=11, bold=True, color='FF1F2937')
    ws.cell(row=r, column=1).border = Border(
        bottom=Side(style='thin', color='FF1F2937'))
    for c in range(2, 8):
        ws.cell(row=r, column=c).border = Border(
            bottom=Side(style='thin', color='FF1F2937'))
    ws.row_dimensions[r].height = 22
    r += 1

    cat_header_row = r
    if not cat_results or not grade_data.get('enabled', True):
        ws.merge_cells(f'A{r}:G{r}')
        ws.cell(row=r, column=1, value='Grading data not available for this scan.').font = Font(
            name='Calibri', size=10, italic=True, color='FF9CA3AF')
        r += 1
    else:
        cat_headers = ['Category', 'Weight', 'Score', 'Grade', '', '', '']
        for col_num, header_text in enumerate(cat_headers, 1):
            if not header_text:
                continue
            cell = ws.cell(row=r, column=col_num, value=header_text)
            cell.font = Font(name='Calibri', size=9, bold=True, color='FF6B7280')
            cell.border = Border(bottom=Side(style='thin', color='FFD1D5DB'))
        r += 1

        for cat_name, cat_data in sorted_cats:
            cat_color = cat_data.get('color', '#6b7280')
            cat_grade_color = cat_data.get('grade_color', '#6b7280')
            cat_grade_bg = cat_data.get('grade_bg', '#ffffff')

            # Color indicator + name
            name_cell = ws.cell(row=r, column=1, value=cat_name)
            name_cell.font = Font(name='Calibri', size=10, bold=True, color=hex_to_argb(cat_color))
            name_cell.border = Border(
                left=Side(style='thick', color=hex_to_argb(cat_color)),
                bottom=Side(style='thin', color='FFE5E7EB'),
            )

            ws.cell(row=r, column=2, value=cat_data.get('weight', 0)).font = DATA_FONT
            ws.cell(row=r, column=2).number_format = '0.0'
            ws.cell(row=r, column=2).border = subtle_border

            score_cell = ws.cell(row=r, column=3, value=cat_data.get('score', 0))
            score_cell.font = Font(name='Calibri', size=10, bold=True, color='FF374151')
            score_cell.number_format = '0.0'
            score_cell.border = subtle_border

            cat_grade_cell = ws.cell(row=r, column=4, value=cat_data.get('grade', '-'))
            cat_grade_cell.font = Font(name='Calibri', size=10, bold=True,
                                       color=hex_to_argb(cat_grade_color))
            cat_grade_cell.fill = PatternFill(
                start_color=hex_to_argb(cat_grade_bg),
                end_color=hex_to_argb(cat_grade_bg),
                fill_type='solid',
            )
            cat_grade_cell.alignment = Alignment(horizontal='center')
            cat_grade_cell.border = subtle_border

            r += 1

    # Data bars on Score column (cosmetic — non-fatal)
    if sorted_cats and r > cat_header_row + 1:
        try:
            score_range = f"C{cat_header_row + 1}:C{r - 1}"
            rule = DataBarRule(
                start_type='num', start_value=0,
                end_type='num', end_value=100,
                color='3B82F6',
            )
            ws.conditional_formatting.add(score_range, rule)
        except Exception:
            pass

    # ── Column widths (left side) ────────────────────────────────────────
    ws.column_dimensions['A'].width = 26
    ws.column_dimensions['B'].width = 12
    ws.column_dimensions['C'].width = 12
    ws.column_dimensions['D'].width = 10
    ws.column_dimensions['E'].width = 12
    ws.column_dimensions['F'].width = 12
    ws.column_dimensions['G'].width = 14

    # ── SNAPSHOT PANEL (right side, columns I-N) ─────────────────────────
    if snapshot_data and isinstance(snapshot_data, dict):
        _build_snapshot_panel(ws, snapshot_data, dark_fill, label_font, value_font, subtle_border)


# ============================================================================
# SNAPSHOT PANEL BUILDER (right side of Executive Summary)
# ============================================================================

def _build_snapshot_panel(ws, snapshot_data, dark_fill, label_font, value_font, subtle_border):
    """Render the SNAPSHOT trend panel on the right side of the Executive Summary.

    Occupies columns I-N (9-14), with column H (8) as a spacer.
    """
    import time as _time

    # Column widths for right side
    ws.column_dimensions['H'].width = 2   # spacer
    ws.column_dimensions['I'].width = 14
    ws.column_dimensions['J'].width = 10
    ws.column_dimensions['K'].width = 10
    ws.column_dimensions['L'].width = 14
    ws.column_dimensions['M'].width = 10
    ws.column_dimensions['N'].width = 10

    banner_fill = PatternFill(start_color='FF111827', end_color='FF111827', fill_type='solid')
    banner_font = Font(name='Calibri', size=12, bold=True, color='FFFFFFFF')
    card_label_font = Font(name='Calibri', size=9, bold=True, color='FF9CA3AF')
    card_value_font = Font(name='Calibri', size=14, bold=True)
    section_border = Border(bottom=Side(style='medium', color='FF9CA3AF'))

    def _grade_color(grade_letter):
        return GRADE_METRIC_COLORS.get(grade_letter, '#6b7280')

    def _fill_banner(row, col_start=9, col_end=14):
        for c in range(col_start, col_end + 1):
            ws.cell(row=row, column=c).fill = banner_fill

    def _merge_card(row, col_start, col_end):
        ws.merge_cells(
            start_row=row, start_column=col_start,
            end_row=row, end_column=col_end,
        )

    # ── Row 1: SECURITY POSTURE TREND banner ─────────────────────────────
    _merge_card(1, 9, 14)
    banner_cell = ws.cell(row=1, column=9, value='SECURITY POSTURE TREND')
    banner_cell.font = banner_font
    banner_cell.fill = banner_fill
    banner_cell.alignment = Alignment(horizontal='left', vertical='center')
    _fill_banner(1)

    # Row 2: spacer
    # (already exists from left side)

    # ── Rows 3-4: CHANGE + TREND cards ───────────────────────────────────
    overall_change = snapshot_data.get('overall_change', 0)
    trajectory = snapshot_data.get('trajectory', 'stable')

    # CHANGE card (I-K)
    _merge_card(3, 9, 11)
    ws.cell(row=3, column=9, value='CHANGE').font = card_label_font
    ws.cell(row=3, column=9).alignment = Alignment(horizontal='left')

    _merge_card(4, 9, 11)
    change_str = f"+{overall_change}" if overall_change > 0 else str(overall_change)
    change_color = '#22c55e' if overall_change > 0 else ('#ef4444' if overall_change < 0 else '#6b7280')
    change_cell = ws.cell(row=4, column=9, value=change_str)
    change_cell.font = Font(name='Calibri', size=14, bold=True, color=hex_to_argb(change_color))
    change_cell.alignment = Alignment(horizontal='left')
    change_cell.border = Border(left=Side(style='thick', color=hex_to_argb(change_color)))

    # TREND card (L-N)
    _merge_card(3, 12, 14)
    ws.cell(row=3, column=12, value='TREND').font = card_label_font
    ws.cell(row=3, column=12).alignment = Alignment(horizontal='left')

    _merge_card(4, 12, 14)
    trend_map = {
        'improving': ('#22c55e', 'IMPROVING'),
        'degrading': ('#ef4444', 'DEGRADING'),
        'stable': ('#6b7280', 'STABLE'),
    }
    trend_color, trend_label = trend_map.get(trajectory, ('#6b7280', 'STABLE'))
    trend_cell = ws.cell(row=4, column=12, value=trend_label)
    trend_cell.font = Font(name='Calibri', size=14, bold=True, color=hex_to_argb(trend_color))
    trend_cell.alignment = Alignment(horizontal='left')
    trend_cell.border = Border(left=Side(style='thick', color=hex_to_argb(trend_color)))

    # Row 5: spacer
    ws.row_dimensions[5].height = max(ws.row_dimensions[5].height or 8, 8)

    # ── Rows 6-7: WORST + BEST cards ─────────────────────────────────────
    worst = snapshot_data.get('worst_category') or {}
    best = snapshot_data.get('best_category') or {}

    # WORST card (I-K)
    _merge_card(6, 9, 11)
    ws.cell(row=6, column=9, value='WORST').font = card_label_font
    ws.cell(row=6, column=9).alignment = Alignment(horizontal='left')

    _merge_card(7, 9, 11)
    if worst:
        w_grade = worst.get('grade', '-')
        w_name = worst.get('name', '')
        w_color = _grade_color(w_grade)
        worst_cell = ws.cell(row=7, column=9, value=f"{w_grade} \u2014 {w_name}")
        worst_cell.font = Font(name='Calibri', size=11, bold=True, color=hex_to_argb(w_color))
        worst_cell.border = Border(left=Side(style='thick', color=hex_to_argb(w_color)))
    else:
        ws.cell(row=7, column=9, value='-').font = Font(name='Calibri', size=11, color='FF9CA3AF')

    # BEST card (L-N)
    _merge_card(6, 12, 14)
    ws.cell(row=6, column=12, value='BEST').font = card_label_font
    ws.cell(row=6, column=12).alignment = Alignment(horizontal='left')

    _merge_card(7, 12, 14)
    if best:
        b_grade = best.get('grade', '-')
        b_name = best.get('name', '')
        b_color = _grade_color(b_grade)
        best_cell = ws.cell(row=7, column=12, value=f"{b_grade} \u2014 {b_name}")
        best_cell.font = Font(name='Calibri', size=11, bold=True, color=hex_to_argb(b_color))
        best_cell.border = Border(left=Side(style='thick', color=hex_to_argb(b_color)))
    else:
        ws.cell(row=7, column=12, value='-').font = Font(name='Calibri', size=11, color='FF9CA3AF')

    # Row 8: spacer
    ws.row_dimensions[8].height = max(ws.row_dimensions[8].height or 8, 8)

    # ── Rows 9-10: TIMEFRAME + SCANS cards ───────────────────────────────
    snapshots = snapshot_data.get('snapshots', [])
    scan_count = snapshot_data.get('scan_count', len(snapshots))
    purple = '#8b5cf6'
    cyan = '#06b6d4'

    # TIMEFRAME card (I-K)
    _merge_card(9, 9, 11)
    ws.cell(row=9, column=9, value='TIMEFRAME').font = card_label_font
    ws.cell(row=9, column=9).alignment = Alignment(horizontal='left')

    _merge_card(10, 9, 11)
    if len(snapshots) >= 2:
        first_ts = snapshots[0].get('date', 0)
        last_ts = snapshots[-1].get('date', 0)
        if first_ts and last_ts:
            days = max(1, int((last_ts - first_ts) / 86400))
            tf_val = f"{days} days"
        else:
            tf_val = '-'
    else:
        tf_val = '-'
    tf_cell = ws.cell(row=10, column=9, value=tf_val)
    tf_cell.font = Font(name='Calibri', size=14, bold=True, color=hex_to_argb(purple))
    tf_cell.alignment = Alignment(horizontal='left')
    tf_cell.border = Border(left=Side(style='thick', color=hex_to_argb(purple)))

    # SCANS card (L-N)
    _merge_card(9, 12, 14)
    ws.cell(row=9, column=12, value='SCANS').font = card_label_font
    ws.cell(row=9, column=12).alignment = Alignment(horizontal='left')

    _merge_card(10, 12, 14)
    scans_cell = ws.cell(row=10, column=12, value=scan_count)
    scans_cell.font = Font(name='Calibri', size=14, bold=True, color=hex_to_argb(cyan))
    scans_cell.alignment = Alignment(horizontal='left')
    scans_cell.border = Border(left=Side(style='thick', color=hex_to_argb(cyan)))

    # ── Row 11: divider ──────────────────────────────────────────────────
    for c in range(9, 15):
        ws.cell(row=11, column=c).border = section_border

    # ── Row 12: SCAN HISTORY sub-banner ──────────────────────────────────
    _merge_card(12, 9, 14)
    hist_banner = ws.cell(row=12, column=9, value='SCAN HISTORY')
    hist_banner.font = Font(name='Calibri', size=11, bold=True, color='FFFFFFFF')
    hist_banner.fill = banner_fill
    hist_banner.alignment = Alignment(horizontal='left', vertical='center')
    _fill_banner(12)
    ws.row_dimensions[12].height = 24

    # ── Row 13: headers ──────────────────────────────────────────────────
    header_font = Font(name='Calibri', size=9, bold=True, color='FF6B7280')
    header_border = Border(bottom=Side(style='thin', color='FFD1D5DB'))

    ws.cell(row=13, column=9, value='DATE').font = header_font
    ws.cell(row=13, column=9).border = header_border
    _merge_card(13, 10, 11)
    ws.cell(row=13, column=10, value='GRADE').font = header_font
    ws.cell(row=13, column=10).border = header_border
    ws.cell(row=13, column=11).border = header_border
    _merge_card(13, 12, 14)
    ws.cell(row=13, column=12, value='SCORE').font = header_font
    ws.cell(row=13, column=12).border = header_border
    for c in range(13, 15):
        ws.cell(row=13, column=c).border = header_border

    # ── Rows 14+: scan history data (most recent first, up to 15) ────────
    display_snapshots = list(reversed(snapshots))[:15]
    sr = 14
    for snap in display_snapshots:
        # Date
        snap_date = snap.get('date', 0)
        if snap_date:
            try:
                date_str = _time.strftime('%b %d, %Y', _time.localtime(snap_date))
            except (OSError, ValueError):
                date_str = str(snap_date)
        else:
            date_str = '-'
        ws.cell(row=sr, column=9, value=date_str).font = Font(
            name='Calibri', size=9, color='FF374151')
        ws.cell(row=sr, column=9).border = Border(
            bottom=Side(style='thin', color='FFE5E7EB'))

        # Grade badge
        snap_grade = snap.get('overall_grade', '-')
        g_color = _grade_color(snap_grade)
        _merge_card(sr, 10, 11)
        g_cell = ws.cell(row=sr, column=10, value=snap_grade)
        g_cell.font = Font(name='Calibri', size=10, bold=True, color=hex_to_argb(g_color))
        g_cell.alignment = Alignment(horizontal='center')
        g_cell.border = Border(bottom=Side(style='thin', color='FFE5E7EB'))
        ws.cell(row=sr, column=11).border = Border(
            bottom=Side(style='thin', color='FFE5E7EB'))

        # Score
        snap_score = snap.get('overall_score', 0)
        _merge_card(sr, 12, 14)
        s_cell = ws.cell(row=sr, column=12, value=snap_score)
        s_cell.font = Font(name='Calibri', size=10, bold=True, color='FF374151')
        s_cell.number_format = '0.0'
        s_cell.border = Border(bottom=Side(style='thin', color='FFE5E7EB'))
        for c in range(13, 15):
            ws.cell(row=sr, column=c).border = Border(
                bottom=Side(style='thin', color='FFE5E7EB'))

        sr += 1


# ============================================================================
# FINDINGS SHEET BUILDER
# ============================================================================

def build_findings_sheet(ws, findings_rows: list):
    """Build the Findings worksheet with severity color-coding.

    Args:
        ws: openpyxl Worksheet
        findings_rows: list of [priority, category, tab, item, description, recommendation]
    """
    set_tab_color(ws, '000000')

    headers = ['Priority', 'Category', 'Tab', 'Item', 'Description', 'Recommendation']
    apply_header_row(ws, headers)
    freeze_header(ws)

    for row_num, row_data in enumerate(findings_rows, 2):
        for col_num, cell_value in enumerate(row_data, 1):
            cell = ws.cell(row=row_num, column=col_num, value=_safe_str(cell_value))
            cell.font = DATA_FONT
            cell.alignment = DATA_ALIGNMENT
            cell.border = THIN_BORDER

        # Color-code the Priority cell
        priority = str(row_data[0]).upper().strip() if row_data else ''
        if priority in SEVERITY_COLORS:
            apply_severity_fill(ws.cell(row=row_num, column=1), priority)

    # Alternating rows
    if findings_rows:
        apply_alternating_rows(ws, 2, len(findings_rows) + 1)

    # Excel Table for sort/filter
    add_data_table(ws, header_row=1, num_data_rows=len(findings_rows), num_columns=len(headers))

    col_widths = [12, 22, 18, 40, 50, 50]
    for i, w in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ============================================================================
# CORRELATIONS SHEET BUILDER
# ============================================================================

def build_correlations_sheet(ws, correlation_rows: list):
    """Build the Correlations worksheet with risk color-coding.

    Args:
        ws: openpyxl Worksheet
        correlation_rows: list of [title, rule_name, risk, description, rule_logic, event_count, event_types]
    """
    set_tab_color(ws, '374151')

    headers = ['Correlation', 'Rule Name', 'Risk', 'Description', 'Rule Logic', 'Event Count', 'Event Types']
    apply_header_row(ws, headers)
    freeze_header(ws)

    for row_num, row_data in enumerate(correlation_rows, 2):
        for col_num, cell_value in enumerate(row_data, 1):
            cell = ws.cell(row=row_num, column=col_num, value=_safe_str(cell_value))
            cell.font = DATA_FONT
            cell.alignment = DATA_ALIGNMENT
            cell.border = THIN_BORDER

        # Color-code the Risk cell (column 3)
        risk = str(row_data[2]).upper().strip() if len(row_data) > 2 else ''
        if risk in RISK_COLORS:
            risk_cell = ws.cell(row=row_num, column=3)
            bg = RISK_COLORS[risk]
            risk_cell.fill = PatternFill(
                start_color=hex_to_argb(bg),
                end_color=hex_to_argb(bg),
                fill_type='solid',
            )
            risk_cell.font = Font(name='Calibri', size=10, bold=True, color='FFFFFFFF')

    if correlation_rows:
        apply_alternating_rows(ws, 2, len(correlation_rows) + 1)

    # Excel Table for sort/filter
    add_data_table(ws, header_row=1, num_data_rows=len(correlation_rows), num_columns=len(headers))

    col_widths = [30, 25, 10, 50, 40, 12, 40]
    for i, w in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ============================================================================
# EXT-VULNS (NESSUS) SHEET BUILDER
# ============================================================================

def build_nessus_sheet(ws, nessus_rows: list):
    """Build the EXT-VULNS worksheet with severity color-coding and styled headers.

    Args:
        ws: openpyxl Worksheet
        nessus_rows: list of [severity, severity_number, plugin_name, plugin_id,
                     host_ip, host_name, operating_system, description, synopsis,
                     solution, see_also, service_name, port, protocol, request,
                     plugin_output, cvss3_base_score, tracking]
    """
    set_tab_color(ws, 'dc2626')  # red

    headers = [
        "Severity", "Severity Number", "Plugin Name", "Plugin ID",
        "Host IP", "Host Name", "Operating System", "Description",
        "Synopsis", "Solution", "See Also", "Service Name", "Port",
        "Protocol", "Request", "Plugin Output", "CVSS3 Base Score", "Tracking"
    ]
    apply_header_row(ws, headers)
    freeze_header(ws)

    for row_num, row_data in enumerate(nessus_rows, 2):
        for col_num, cell_value in enumerate(row_data, 1):
            cell = ws.cell(row=row_num, column=col_num, value=_safe_str(cell_value))
            cell.font = DATA_FONT
            cell.alignment = DATA_ALIGNMENT
            cell.border = THIN_BORDER

        # Color-code the Severity cell (column 1)
        severity = str(row_data[0]).upper().strip() if row_data else ''
        if severity in SEVERITY_COLORS:
            apply_severity_fill(ws.cell(row=row_num, column=1), severity)

    if nessus_rows:
        apply_alternating_rows(ws, 2, len(nessus_rows) + 1)

    # Excel Table for sort/filter
    add_data_table(ws, header_row=1, num_data_rows=len(nessus_rows), num_columns=len(headers))

    col_widths = [12, 8, 30, 10, 14, 20, 18, 50, 40, 40, 30, 12, 8, 8, 40, 40, 10, 10]
    for i, w in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ============================================================================
# WEBAPP-VULNS (BURP) SHEET BUILDER
# ============================================================================

def build_burp_sheet(ws, burp_rows: list):
    """Build the WEBAPP-VULNS worksheet with severity color-coding and styled headers.

    Args:
        ws: openpyxl Worksheet
        burp_rows: list of [severity, severity_number, host_ip, host_name,
                   plugin_name, issue_type, path, location, confidence,
                   issue_background, issue_detail, solutions, see_also,
                   references, vulnerability_classifications, request,
                   response, tracking]
    """
    set_tab_color(ws, 'ea580c')  # orange

    headers = [
        "Severity", "Severity Number", "Host IP", "Host Name",
        "Plugin Name", "Issue Type", "Path", "Location", "Confidence",
        "Issue Background", "Issue Detail", "Solutions", "See Also",
        "References", "Vulnerability Classifications",
        "Request", "Response", "Tracking"
    ]
    apply_header_row(ws, headers)
    freeze_header(ws)

    for row_num, row_data in enumerate(burp_rows, 2):
        for col_num, cell_value in enumerate(row_data, 1):
            cell = ws.cell(row=row_num, column=col_num, value=_safe_str(cell_value))
            cell.font = DATA_FONT
            cell.alignment = DATA_ALIGNMENT
            cell.border = THIN_BORDER

        # Color-code the Severity cell (column 1)
        severity = str(row_data[0]).upper().strip() if row_data else ''
        if severity in SEVERITY_COLORS:
            apply_severity_fill(ws.cell(row=row_num, column=1), severity)

    if burp_rows:
        apply_alternating_rows(ws, 2, len(burp_rows) + 1)

    # Excel Table for sort/filter
    add_data_table(ws, header_row=1, num_data_rows=len(burp_rows), num_columns=len(headers))

    col_widths = [12, 8, 14, 20, 30, 14, 30, 20, 12, 50, 50, 40, 30, 30, 30, 40, 40, 10]
    for i, w in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ============================================================================
# CATEGORY TAB BUILDER
# ============================================================================

def build_category_sheet(ws, cat_name: str, cat_color: str, cat_data: dict):
    """Build a per-category worksheet showing the grading detail breakdown.

    Args:
        ws: openpyxl Worksheet
        cat_name: category name (e.g. 'Network Security')
        cat_color: hex color for the tab (e.g. '#dc2626')
        cat_data: per-category dict from calculate_full_grade() containing
                  'score', 'grade', 'grade_color', 'grade_bg', 'weight',
                  'description', and 'details' list
    """
    set_tab_color(ws, cat_color)

    # Category title
    ws.merge_cells('A1:F1')
    title = ws['A1']
    score = cat_data.get('score', 0)
    grade = cat_data.get('grade', '-')
    title.value = f'{cat_name}  \u2014  Score: {score}  ({grade})'
    title.font = Font(name='Calibri', size=14, bold=True, color=hex_to_argb(cat_color))
    title.alignment = Alignment(horizontal='left', vertical='center')
    ws.row_dimensions[1].height = 30

    # Description
    desc = cat_data.get('description', '')
    if desc:
        ws.merge_cells('A2:F2')
        ws['A2'].value = desc
        ws['A2'].font = Font(name='Calibri', size=10, italic=True, color='FF6B7280')

    # Weight & score summary
    ws.cell(row=3, column=1, value='Weight:').font = Font(name='Calibri', size=10, bold=True)
    ws.cell(row=3, column=2, value=cat_data.get('weight', 0)).number_format = '0.0'
    ws.cell(row=3, column=3, value='Adj Score:').font = Font(name='Calibri', size=10, bold=True)
    ws.cell(row=3, column=4, value=cat_data.get('adj_score', 0)).number_format = '0.0'

    # Detail table header
    detail_header_row = 5
    detail_headers = ['Event Type', 'Count', 'Points', 'Logic', 'Rank']
    apply_header_row(ws, detail_headers, detail_header_row)
    freeze_header(ws, detail_header_row + 1)

    details = cat_data.get('details', [])
    current_row = detail_header_row + 1

    if not details:
        ws.merge_cells(f'A{current_row}:E{current_row}')
        ws.cell(row=current_row, column=1, value='No findings in this category.').font = Font(
            name='Calibri', size=10, italic=True, color='FF9CA3AF',
        )
        current_row += 1
    else:
        for detail in details:
            ws.cell(row=current_row, column=1, value=detail.get('type', '')).font = DATA_FONT
            ws.cell(row=current_row, column=2, value=detail.get('count', 0)).font = DATA_FONT

            pts = detail.get('points', 0)
            pts_cell = ws.cell(row=current_row, column=3, value=pts)
            if pts < 0:
                pts_cell.font = Font(name='Calibri', size=10, color='FFDC2626')
            else:
                pts_cell.font = DATA_FONT
            pts_cell.number_format = '0.0'

            ws.cell(row=current_row, column=4, value=detail.get('logic', '')).font = DATA_FONT
            ws.cell(row=current_row, column=5, value=detail.get('rank', 5)).font = DATA_FONT

            for col in range(1, 6):
                ws.cell(row=current_row, column=col).border = THIN_BORDER

            current_row += 1

        apply_alternating_rows(ws, detail_header_row + 1, current_row - 1)

    col_widths = [35, 10, 10, 20, 8]
    for i, w in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ============================================================================
# EVENT TYPE DATA TAB BUILDER
# ============================================================================

# Category → tab color mapping (mirrors grade_config DEFAULT_GRADE_CATEGORIES)
CATEGORY_TAB_COLORS = {
    'Network Security':           '#dc2626',
    'Web App Security':           '#ea580c',
    'Information Leakage':        '#eab308',
    'General Health':             '#3b82f6',
    'External Account Exposure':  '#06b6d4',
    'DNS Health':                 '#22c55e',
    'IP Reputation':              '#d946ef',
    'AI Security':                '#8b5cf6',
    'Information / Reference':    '#6b7280',
}


def build_event_type_sheet(ws, event_type_name: str, rows: list, tab_color: str = '#6b7280'):
    """Build a styled per-event-type data worksheet.

    Args:
        ws: openpyxl Worksheet
        event_type_name: human-readable event type (e.g. 'IP Address')
        rows: list of [Updated, Module, Source, F/P, Data]
        tab_color: hex color for the tab
    """
    set_tab_color(ws, tab_color)

    # Title row
    ws.merge_cells('A1:E1')
    title = ws['A1']
    title.value = f'{event_type_name}  ({len(rows)} results)'
    title.font = Font(name='Calibri', size=12, bold=True, color='FFFFFFFF')
    title.fill = HEADER_FILL
    title.alignment = Alignment(horizontal='left', vertical='center')
    for c in range(2, 6):
        ws.cell(row=1, column=c).fill = HEADER_FILL
    ws.row_dimensions[1].height = 28

    # Column headers
    headers = ['Updated', 'Module', 'Source', 'F/P', 'Data']
    apply_header_row(ws, headers, row=2)
    freeze_header(ws, row=3)

    # Data rows
    fp_labels = {0: '', 1: 'FP', 2: 'OK'}
    fp_fill_red = PatternFill(start_color='FFFEE2E2', end_color='FFFEE2E2', fill_type='solid')
    fp_font_red = Font(name='Calibri', size=9, bold=True, color='FFDC2626')
    fp_fill_green = PatternFill(start_color='FFDCFCE7', end_color='FFDCFCE7', fill_type='solid')
    fp_font_green = Font(name='Calibri', size=9, bold=True, color='FF16A34A')

    for row_num, row_data in enumerate(rows, 3):
        for col_num, cell_value in enumerate(row_data, 1):
            cell = ws.cell(row=row_num, column=col_num, value=_safe_str(cell_value))
            cell.font = DATA_FONT
            cell.alignment = DATA_ALIGNMENT
            cell.border = THIN_BORDER

        # Style the F/P column (column 4)
        fp_cell = ws.cell(row=row_num, column=4)
        fp_val = row_data[3] if len(row_data) > 3 else 0
        fp_cell.value = fp_labels.get(fp_val, str(fp_val))
        if fp_val == 1:
            fp_cell.fill = fp_fill_red
            fp_cell.font = fp_font_red
        elif fp_val == 2:
            fp_cell.fill = fp_fill_green
            fp_cell.font = fp_font_green
        fp_cell.alignment = Alignment(horizontal='center')

    # Alternating rows
    if rows:
        apply_alternating_rows(ws, 3, len(rows) + 2)

    # Excel Table for sort/filter (starts at row 2 header, below the title banner)
    add_data_table(ws, header_row=2, num_data_rows=len(rows), num_columns=len(headers))

    # Column widths
    col_widths = [18, 20, 40, 6, 60]
    for i, w in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


def sanitize_sheet_name(name: str) -> str:
    """Sanitize a string for use as an Excel sheet name.

    Excel sheet names cannot exceed 31 characters or contain: \\ / ? * [ ] :
    Leading single quotes are also prohibited.
    """
    for ch in ('\\', '/', '?', '*', '[', ']', ':'):
        name = name.replace(ch, '-')
    name = name.strip().lstrip("'")
    return name[:31] if name else 'Sheet'
