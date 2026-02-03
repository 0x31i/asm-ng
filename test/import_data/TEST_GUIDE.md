# Legacy Scan Import - Test Guide

## Prerequisites
- SpiderFoot server should be running
- Database should be accessible

## Test 1: Dry Run (Validation Only)

Run the import in dry-run mode to validate the CSV format without making changes:

```bash
python3 tools/import_legacy_csv.py --csv test/import_data/test_import_basic.csv --dry-run
```

**Expected Output:**
- Detected CSV format: single
- Shows column mapping
- Rows to import: 6
- No database changes made

## Test 2: Import Basic CSV (Numeric Status Values)

Import the first test file with numeric F/P values (0, 1, 2):

```bash
python3 tools/import_legacy_csv.py \
    --csv test/import_data/test_import_basic.csv \
    --name "Test Import - Numeric Status" \
    --target "example.com"
```

**Expected Output:**
- Scan ID: (UUID displayed)
- Rows imported: 6
- Rows skipped: 0
- False positives saved: 2 (10.0.0.1, test.example.com)
- Validated items saved: 2 (203.0.113.50, api.example.com)

**Verification Steps:**
1. Note the Scan ID from the output
2. Open SpiderFoot web UI (http://localhost:5001)
3. Navigate to Scans and find "Test Import - Numeric Status"
4. Click Browse and select any event type (e.g., IP_ADDRESS)
5. Verify the Status column shows:
   - 192.168.1.1 = GREY "UNVALIDATED" badge
   - 10.0.0.1 = ORANGE "FALSE POSITIVE" badge
   - 203.0.113.50 = BLUE "VALIDATED" badge

## Test 3: Import CSV with Text Status Values

Import the second test file with text-based status values:

```bash
python3 tools/import_legacy_csv.py \
    --csv test/import_data/test_import_text_status.csv \
    --name "Test Import - Text Status" \
    --target "testcorp.com"
```

**Expected Output:**
- Rows imported: 4
- False positives saved: 1 (127.0.0.1)
- Validated items saved: 2 (8.8.8.8, www.testcorp.com)

## Test 4: Verify Database Tables

Connect to the SQLite database and verify the data:

```bash
sqlite3 ~/.spiderfoot/spiderfoot.db
```

**Check scan results:**
```sql
-- See all imported results with their status
SELECT data, type, false_positive
FROM tbl_scan_results
WHERE scan_instance_id LIKE '%'
ORDER BY generated DESC
LIMIT 20;
```

**Check target-level false positives:**
```sql
SELECT * FROM tbl_target_false_positives WHERE target = 'example.com';
```

**Check target-level validated entries:**
```sql
SELECT * FROM tbl_target_validated WHERE target = 'example.com';
```

## Test 5: UI Validation Status Actions

After importing, test the UI actions:

1. **Mark as Validated:**
   - Select an UNVALIDATED row (checkbox)
   - Click the green "Validated" button in the floating toolbar
   - Verify the status changes to BLUE "VALIDATED" badge
   - Refresh and verify it persists

2. **Mark as False Positive:**
   - Select a row
   - Click the orange "False Positive" button
   - Verify the status changes to ORANGE "FALSE POSITIVE" badge

3. **Mark as Unvalidated:**
   - Select a validated or FP row
   - Click the grey "Unvalidated" button
   - Verify the status changes to GREY badge

4. **Dropdown Menu:**
   - Select one or more rows
   - Click the validation dropdown (circle icon in toolbar)
   - Test each option:
     - "Mark as Validated" (green icon)
     - "Mark as False Positive" (orange icon)
     - "Mark as Unvalidated" (grey icon)

## Test 6: Persistence Verification

1. Mark some items as Validated (with persistence enabled)
2. Create a new scan against the same target
3. After the new scan completes, browse the results
4. Verify that items matching the saved validated entries show:
   - BLUE "VALIDATED" badge (or "VALIDATED LEGACY" if from previous scan)
   - A small repeat icon indicating "Saved as validated for future scans"

## Test 7: Export and Re-Import

1. Export scan results to CSV from the UI
2. Verify the exported CSV contains the F/P column with values 0, 1, 2
3. Import the exported CSV back
4. Verify all status values are preserved

## Cleanup

To remove test data after testing:

```bash
# Remove test scans from database (use scan IDs from import output)
sqlite3 ~/.spiderfoot/spiderfoot.db "DELETE FROM tbl_scan_results WHERE scan_instance_id IN (SELECT guid FROM tbl_scan_instance WHERE name LIKE 'Test Import%');"
sqlite3 ~/.spiderfoot/spiderfoot.db "DELETE FROM tbl_scan_instance WHERE name LIKE 'Test Import%';"

# Remove test target-level entries
sqlite3 ~/.spiderfoot/spiderfoot.db "DELETE FROM tbl_target_false_positives WHERE target IN ('example.com', 'testcorp.com');"
sqlite3 ~/.spiderfoot/spiderfoot.db "DELETE FROM tbl_target_validated WHERE target IN ('example.com', 'testcorp.com');"
```

## Status Value Reference

| Value | Text Aliases | Color | Meaning |
|-------|--------------|-------|---------|
| 0 | (empty) | GREY badge | Unvalidated - not yet reviewed |
| 1 | true, yes, fp, false positive | ORANGE box | False Positive - doesn't belong |
| 2 | validated, valid, confirmed | BLUE box | Validated - confirmed belongs to org |

**Note:** Items detected from previous scan persistence will show "LEGACY" suffix (e.g., "FALSE POSITIVE LEGACY" or "VALIDATED LEGACY").
