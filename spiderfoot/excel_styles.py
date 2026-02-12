"""Excel formatting and styling utilities for scan exports.

Provides openpyxl styling helpers, color definitions, and sheet builders
for producing professionally formatted Excel workbooks with tab colors,
severity color-coding, and an Executive Summary with grade visualization.
"""

from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter


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
    'HIGH':     '#ef4444',
    'MEDIUM':   '#f59e0b',
    'LOW':      '#3b82f6',
    'INFO':     '#22c55e',
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
    """Apply subtle alternating row fill for readability."""
    for row_idx in range(start_row, end_row + 1):
        if row_idx % 2 == 0:
            for cell in ws[row_idx]:
                if not cell.fill or cell.fill.start_color.index in (0, '00000000'):
                    cell.fill = ALT_ROW_FILL


# ============================================================================
# EXECUTIVE SUMMARY SHEET BUILDER
# ============================================================================

def build_executive_summary(ws, grade_data: dict, scan_info: dict):
    """Build the Executive Summary worksheet with grade visualization.

    Args:
        ws: openpyxl Worksheet (should be the active/first sheet)
        grade_data: output from calculate_full_grade() -- must contain
                    'overall_grade', 'overall_score', 'overall_grade_color',
                    'overall_grade_bg', and 'categories' dict
        scan_info: dict with keys 'name', 'target', 'date'
    """
    set_tab_color(ws, '16a34a')

    # -- Title row --
    ws.merge_cells('A1:H1')
    title_cell = ws['A1']
    title_cell.value = 'EXECUTIVE SUMMARY'
    title_cell.font = Font(name='Calibri', size=22, bold=True, color='FF1F2937')
    title_cell.alignment = Alignment(horizontal='left', vertical='center')
    ws.row_dimensions[1].height = 36

    # -- Scan metadata --
    label_font = Font(name='Calibri', size=11, bold=True, color='FF374151')
    value_font = Font(name='Calibri', size=11, color='FF6B7280')
    meta = [
        ('Target:', scan_info.get('target', '')),
        ('Scan:', scan_info.get('name', '')),
        ('Date:', scan_info.get('date', '')),
    ]
    for r, (label, val) in enumerate(meta, start=2):
        ws.cell(row=r, column=1, value=label).font = label_font
        ws.cell(row=r, column=2, value=val).font = value_font

    # -- Divider row --
    ws.row_dimensions[5].height = 8

    # -- Grade block (rows 6-10, columns A-B merged) --
    overall_grade = grade_data.get('overall_grade', '-')
    overall_score = grade_data.get('overall_score', 0)
    grade_color = grade_data.get('overall_grade_color', '#6b7280')
    grade_bg = grade_data.get('overall_grade_bg', '#f3f4f6')

    ws.merge_cells('A6:B10')
    grade_cell = ws['A6']
    grade_cell.value = overall_grade
    grade_cell.font = Font(name='Calibri', size=48, bold=True, color=hex_to_argb(grade_color))
    grade_cell.fill = PatternFill(
        start_color=hex_to_argb(grade_bg),
        end_color=hex_to_argb(grade_bg),
        fill_type='solid',
    )
    grade_cell.alignment = Alignment(horizontal='center', vertical='center')
    for row_idx in range(6, 11):
        ws.row_dimensions[row_idx].height = 22

    # Score text beside the grade block
    ws.merge_cells('C6:E6')
    ws['C6'].value = f'Overall Score: {overall_score}'
    ws['C6'].font = Font(name='Calibri', size=16, bold=True, color=hex_to_argb(grade_color))
    ws['C6'].alignment = Alignment(vertical='center')

    ws['C7'].value = f'Grade: {overall_grade}'
    ws['C7'].font = Font(name='Calibri', size=12, color='FF6B7280')

    # -- Category breakdown table (row 12+) --
    cat_header_row = 12
    cat_results = grade_data.get('categories', {})

    if not cat_results or not grade_data.get('enabled', True):
        ws.merge_cells(f'A{cat_header_row}:F{cat_header_row}')
        ws.cell(row=cat_header_row, column=1, value='Grading data not available for this scan.').font = Font(
            name='Calibri', size=11, italic=True, color='FF9CA3AF',
        )
    else:
        cat_headers = ['Category', 'Weight', 'Raw Score', 'Adj Score', 'Score', 'Grade']
        apply_header_row(ws, cat_headers, cat_header_row)

    sorted_cats = sorted(
        cat_results.items(),
        key=lambda x: (-x[1].get('weight', 0), x[0]),
    )

    current_row = cat_header_row + 1
    for cat_name, cat_data in sorted_cats:
        cat_color = cat_data.get('color', '#6b7280')
        cat_grade_color = cat_data.get('grade_color', '#6b7280')
        cat_grade_bg = cat_data.get('grade_bg', '#ffffff')

        name_cell = ws.cell(row=current_row, column=1, value=cat_name)
        name_cell.font = Font(name='Calibri', size=10, bold=True, color=hex_to_argb(cat_color))

        ws.cell(row=current_row, column=2, value=cat_data.get('weight', 0)).number_format = '0.0'
        ws.cell(row=current_row, column=3, value=cat_data.get('raw_score', 0)).number_format = '0.0'
        ws.cell(row=current_row, column=4, value=cat_data.get('adj_score', 0)).number_format = '0.0'

        score_cell = ws.cell(row=current_row, column=5, value=cat_data.get('score', 0))
        score_cell.number_format = '0.0'

        grade_cell = ws.cell(row=current_row, column=6, value=cat_data.get('grade', '-'))
        grade_cell.font = Font(name='Calibri', size=10, bold=True, color=hex_to_argb(cat_grade_color))
        grade_cell.fill = PatternFill(
            start_color=hex_to_argb(cat_grade_bg),
            end_color=hex_to_argb(cat_grade_bg),
            fill_type='solid',
        )
        grade_cell.alignment = Alignment(horizontal='center')

        for col in range(1, 7):
            c = ws.cell(row=current_row, column=col)
            c.border = THIN_BORDER
            if c.font == Font():
                c.font = DATA_FONT

        current_row += 1

    # -- Column widths --
    ws.column_dimensions['A'].width = 28
    ws.column_dimensions['B'].width = 10
    ws.column_dimensions['C'].width = 14
    ws.column_dimensions['D'].width = 14
    ws.column_dimensions['E'].width = 10
    ws.column_dimensions['F'].width = 10
    ws.column_dimensions['G'].width = 4
    ws.column_dimensions['H'].width = 4


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
            cell = ws.cell(row=row_num, column=col_num, value=str(cell_value))
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
        correlation_rows: list of [title, rule_name, risk, description, rule_logic, event_count]
    """
    set_tab_color(ws, '374151')

    headers = ['Correlation', 'Rule Name', 'Risk', 'Description', 'Rule Logic', 'Event Count']
    apply_header_row(ws, headers)
    freeze_header(ws)

    for row_num, row_data in enumerate(correlation_rows, 2):
        for col_num, cell_value in enumerate(row_data, 1):
            cell = ws.cell(row=row_num, column=col_num, value=str(cell_value))
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

    col_widths = [30, 25, 10, 50, 40, 12]
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


def sanitize_sheet_name(name: str) -> str:
    """Sanitize a string for use as an Excel sheet name.

    Excel sheet names cannot exceed 31 characters or contain: \\ / ? * [ ] :
    Leading single quotes are also prohibited.
    """
    for ch in ('\\', '/', '?', '*', '[', ']', ':'):
        name = name.replace(ch, '-')
    name = name.strip().lstrip("'")
    return name[:31] if name else 'Sheet'
