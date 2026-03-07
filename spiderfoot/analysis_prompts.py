"""Helper module for reading bundled analysis pipeline files."""

import os

_DATA_DIR = os.path.join(os.path.dirname(__file__), 'analysis_data')

ANALYSIS_FILES = {
    'prompts/PRODUCTION_GROUP1.txt': 'prompts/PRODUCTION_GROUP1.txt',
    'prompts/PRODUCTION_GROUP2.txt': 'prompts/PRODUCTION_GROUP2.txt',
    'prompts/PRODUCTION_GROUP3.txt': 'prompts/PRODUCTION_GROUP3.txt',
    'prompts/PRODUCTION_GROUP4.txt': 'prompts/PRODUCTION_GROUP4.txt',
    'prompts/PRODUCTION_GROUP5.txt': 'prompts/PRODUCTION_GROUP5.txt',
    'prompts/PRODUCTION_GROUP6.txt': 'prompts/PRODUCTION_GROUP6.txt',
    'prompts/PRODUCTION_GROUP7.txt': 'prompts/PRODUCTION_GROUP7.txt',
    'prompts/FINAL_CONSOLIDATION.txt': 'prompts/FINAL_CONSOLIDATION.txt',
    'reference/data_structure_reference.csv': 'reference/data_structure_reference.csv',
    'reference/analysis_requirements_PRODUCTION.txt': 'reference/analysis_requirements_PRODUCTION.txt',
    'reference/analysis_progress_tracker_TEMPLATE.md': 'reference/analysis_progress_tracker_TEMPLATE.md',
    'scripts/obfuscate-asm-data.py': 'scripts/obfuscate-asm-data.py',
    'scripts/run_all_groups.py': 'scripts/run_all_groups.py',
    'scripts/final_consolidation.py': 'scripts/final_consolidation.py',
    'scripts/finding_enrichment.py': 'scripts/finding_enrichment.py',
    'scripts/inject_nessus_burp.py': 'scripts/inject_nessus_burp.py',
}


def get_analysis_file(relative_path: str) -> str:
    """Read a single analysis pipeline file.

    Args:
        relative_path: path relative to analysis_data/ directory

    Returns:
        str: file contents
    """
    path = os.path.join(_DATA_DIR, relative_path)
    with open(path, 'r') as f:
        return f.read()


def get_analysis_file_bytes(relative_path: str) -> bytes:
    """Read a single analysis pipeline file as bytes.

    Args:
        relative_path: path relative to analysis_data/ directory

    Returns:
        bytes: file contents
    """
    path = os.path.join(_DATA_DIR, relative_path)
    with open(path, 'rb') as f:
        return f.read()


def get_all_analysis_files() -> dict:
    """Return {zip_path: content} for all pipeline files."""
    return {k: get_analysis_file(v) for k, v in ANALYSIS_FILES.items()}
