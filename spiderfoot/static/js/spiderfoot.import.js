// SpiderFoot Import Page Handler

$(document).ready(function() {

    // Store form data between dry-run and actual import
    var pendingFormData = null;

    // Help blurbs for selective CSV types
    var csvTypeHelp = {
        'scan_results': 'Core scan event data including discovery paths, FP/validated flags, tracking status, and confidence/visibility/risk scores. <strong>Required</strong> to create a new scan. All other files are optional supplements.',
        'findings': 'Analyst findings (CRITICAL/HIGH/MEDIUM/LOW/INFO). <strong>Replaces</strong> all existing findings for the selected scan.',
        'ext_vulns': 'Nessus external vulnerability scan results. <strong>Replaces</strong> all existing Nessus data for the selected scan. Preserves tracking status (OPEN/CLOSED/TICKETED).',
        'webapp_vulns': 'Burp web application vulnerability results. <strong>Replaces</strong> all existing Burp data for the selected scan. Preserves tracking status.',
        'correlations': 'Cross-event correlation results with linked event hashes and rule definitions. Adds new correlations to the selected scan.',
        'target_fps': 'Target-level false positive entries. <strong>Adds</strong> to existing FPs (does not replace). Applied automatically to future scans of this target.',
        'target_validated': 'Target-level validated entries. <strong>Adds</strong> to existing entries. Applied automatically to future scans of this target.',
        'type_comments': 'Analyst comments attached to event types (e.g., a note on all DOMAIN_NAME results). <strong>Overwrites</strong> existing comments for matching types.',
        'row_notes': 'Analyst notes attached to individual data rows. <strong>Overwrites</strong> existing notes for matching rows.',
        'known_assets': 'Known asset entries (IPs, domains, emails, etc.). <strong>Adds</strong> new assets, ignores duplicates.',
        'asset_tags': 'Asset tag definitions with colors. <strong>Adds</strong> new tags, ignores duplicates.',
        'grade_snapshots': 'Historical grade snapshot data. Stores/updates grade records for the scan.',
    };

    // Target-scoped types (don't need scan_id, just target)
    var targetScopedTypes = ['target_fps', 'target_validated', 'type_comments', 'row_notes', 'known_assets', 'asset_tags'];

    // Custom file input - click the hidden input when button is clicked
    $('#btn-browse').on('click', function() {
        $('#import-file').trigger('click');
    });

    // Update filename display when file is selected
    $('#import-file').on('change', function() {
        var fileName = this.files && this.files[0] ? this.files[0].name : '';
        if (fileName) {
            $('#import-file-name').text(fileName).addClass('has-file');
        } else {
            $('#import-file-name').text('NO FILE SELECTED').removeClass('has-file');
        }
    });

    // File type configuration per import type
    var fileTypeConfig = {
        'legacy':      { accept: '.csv', hint: 'ACCEPTED FORMAT: CSV' },
        'scan':        { accept: '.csv', hint: 'ACCEPTED FORMAT: CSV' },
        'fullrestore': { accept: '.zip', hint: 'ACCEPTED FORMAT: ZIP (Full Backup)' },
        'selective':   { accept: '.csv', hint: 'ACCEPTED FORMAT: CSV' }
    };

    // Card click handlers
    $('.import-card').on('click', function() {
        var importType = $(this).data('import-type');

        // Disabled cards show alert
        if ($(this).hasClass('import-card-disabled')) {
            alertify.warning($(this).find('.import-card-title').text() + ' IMPORT IS COMING SOON.');
            return;
        }

        // Highlight selected card
        $('.import-card').removeClass('import-card-selected');
        $(this).addClass('import-card-selected');

        // Set form values based on type
        $('#import-type').val(importType);

        // Update form title
        var title = $(this).find('.import-card-title').text();
        $('#import-form-title').text('IMPORT: ' + title);

        // Update file accept type and hint
        var config = fileTypeConfig[importType] || fileTypeConfig['legacy'];
        $('#import-file').attr('accept', config.accept);
        $('#import-file-hint').text(config.hint);

        // Show/hide selective restore controls
        if (importType === 'selective') {
            $('#selective-csv-type-row').slideDown(200);
            loadScanSelector();
        } else {
            $('#selective-csv-type-row').slideUp(200);
        }

        // Show/hide name+target fields
        if (importType === 'fullrestore' || importType === 'selective') {
            // For fullrestore: always show (pre-populated from manifest after dry-run)
            // For selective: show only when "CREATE NEW SCAN" is selected
            if (importType === 'fullrestore') {
                $('#import-name-target-row').show();
            } else {
                updateNameTargetVisibility();
            }
        } else {
            $('#import-name-target-row').show();
        }

        // Show the form, hide preview/results
        $('#import-form-section').slideDown(200);
        $('#import-preview-section').hide();
        $('#import-results-section').hide();

        // Reset form
        $('#import-file').val('');
        $('#import-file-name').text('NO FILE SELECTED').removeClass('has-file');
        $('#import-scan-name').val('');
        $('#import-target').val('');
        $('#selective-csv-type').val('');
        $('#csv-type-help').html('');

        // Reset button state
        $('#btn-import').prop('disabled', false).html('<i class="glyphicon glyphicon-import"></i> IMPORT');

        pendingFormData = null;
    });

    // Selective CSV type change - update help blurb
    $('#selective-csv-type').on('change', function() {
        var type = $(this).val();
        var help = csvTypeHelp[type] || '';
        $('#csv-type-help').html(help);
        updateNameTargetVisibility();
    });

    // Selective scan selector change - show/hide name+target
    $('#selective-scan-selector').on('change', function() {
        updateNameTargetVisibility();
    });

    function updateNameTargetVisibility() {
        var importType = $('#import-type').val();
        if (importType !== 'selective') return;

        var scanId = $('#selective-scan-selector').val();
        var csvType = $('#selective-csv-type').val();
        var isTargetScoped = targetScopedTypes.indexOf(csvType) >= 0;

        if (scanId) {
            // Attaching to existing scan - hide name, show target only for target-scoped
            $('#import-scan-name').closest('.col-sm-4').hide();
            if (isTargetScoped) {
                $('#import-target').closest('.col-sm-4').show();
                $('#import-name-target-row').show();
            } else {
                $('#import-target').closest('.col-sm-4').hide();
                $('#import-name-target-row').hide();
            }
        } else {
            // Creating new scan - show both
            $('#import-scan-name').closest('.col-sm-4').show();
            $('#import-target').closest('.col-sm-4').show();
            $('#import-name-target-row').show();
        }
    }

    // Load scans for the selective restore scan selector
    function loadScanSelector() {
        var $sel = $('#selective-scan-selector');
        // Keep the first "create new" option
        $sel.find('option:not(:first)').remove();

        $.ajax({
            url: docroot + '/scanslistjson',
            type: 'GET',
            dataType: 'json',
            success: function(data) {
                if (data && data.length) {
                    for (var i = 0; i < data.length; i++) {
                        var s = data[i];
                        var label = s.name + ' (' + s.target + ') [' + s.status + ']';
                        $sel.append('<option value="' + s.id + '">' + label + '</option>');
                    }
                }
            },
            error: function() {
                alertify.warning('Failed to load scan list.');
            }
        });
    }

    // Cancel button (form section)
    $('#btn-import-cancel').on('click', function() {
        $('#import-form-section').slideUp(200);
        $('.import-card').removeClass('import-card-selected');
        pendingFormData = null;
    });

    // Cancel button (preview section)
    $('#btn-preview-cancel').on('click', function() {
        $('#import-preview-section').slideUp(200);
        $('#import-form-section').slideDown(200);
        pendingFormData = null;
    });

    // Form submission - always does dry-run first
    $('#import-form').on('submit', function(e) {
        e.preventDefault();

        var importType = $('#import-type').val();
        var fileInput = $('#import-file')[0];
        if (!fileInput.files || !fileInput.files[0]) {
            alertify.error('PLEASE SELECT A FILE TO IMPORT.');
            return;
        }

        // Determine endpoint and build form data
        var url, formData = new FormData();
        formData.append('importfile', fileInput.files[0]);
        formData.append('dry_run', '1');

        if (importType === 'fullrestore') {
            url = docroot + '/scanfullrestore';
            formData.append('scan_name', $('#import-scan-name').val().trim());
            formData.append('target', $('#import-target').val().trim());
        } else if (importType === 'selective') {
            url = docroot + '/scanrestoreselective';
            var csvType = $('#selective-csv-type').val();
            if (!csvType) {
                alertify.error('PLEASE SELECT A CSV TYPE.');
                return;
            }
            formData.append('import_type', csvType);
            var scanId = $('#selective-scan-selector').val();
            if (scanId) {
                formData.append('scan_id', scanId);
            }
            formData.append('scan_name', $('#import-scan-name').val().trim());
            formData.append('target', $('#import-target').val().trim());
        } else {
            // Legacy / scan import
            url = docroot + '/processimport';
            formData.append('import_type', importType);

            var scanName = $('#import-scan-name').val().trim();
            if (!scanName) {
                alertify.error('PLEASE ENTER A SCAN NAME.');
                $('#import-scan-name').focus();
                return;
            }
            var target = $('#import-target').val().trim();
            if (!target) {
                alertify.error('PLEASE ENTER A TARGET.');
                $('#import-target').focus();
                return;
            }
            formData.append('scan_name', scanName);
            formData.append('target', target);
        }

        // Disable button and show loading
        var $btn = $('#btn-import');
        $btn.prop('disabled', true).html('<i class="glyphicon glyphicon-refresh spinning"></i> VALIDATING...');

        $.ajax({
            url: url,
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            dataType: 'json',
            success: function(data) {
                $btn.prop('disabled', false).html('<i class="glyphicon glyphicon-import"></i> IMPORT');
                if (data.success) {
                    showPreview(data, importType);
                } else {
                    showPreviewError(data);
                }
            },
            error: function(xhr) {
                $btn.prop('disabled', false).html('<i class="glyphicon glyphicon-import"></i> IMPORT');
                var msg = 'VALIDATION FAILED.';
                try {
                    var resp = JSON.parse(xhr.responseText);
                    if (resp.message) msg = resp.message;
                } catch(ex) {}
                alertify.error(msg);
            }
        });
    });

    function showPreview(data, importType) {
        var $content = $('#import-preview-content');
        $content.empty();

        var html = '<div class="alert alert-info">';
        html += '<h4>VALIDATION PASSED</h4>';
        html += '<p>' + data.message + '</p>';
        html += '</div>';

        // Stats table
        html += '<table class="table table-condensed import-stats-table">';

        // For full restore, show manifest details and per-file counts
        if (importType === 'fullrestore' && data.manifest) {
            html += '<tr><td><strong>SCAN NAME</strong></td><td>' + (data.scan_name || '') + '</td></tr>';
            html += '<tr><td><strong>TARGET</strong></td><td>' + (data.target || '') + '</td></tr>';
            html += '<tr><td><strong>ORIGINAL STATUS</strong></td><td>' + (data.manifest.scan_status || '') + '</td></tr>';

            if (data.file_counts) {
                html += '<tr><td colspan="2"><strong>FILES IN BACKUP:</strong></td></tr>';
                for (var fname in data.file_counts) {
                    html += '<tr><td style="padding-left: 20px;">' + fname + '</td><td>' + data.file_counts[fname] + ' rows</td></tr>';
                }
            }
        }

        html += '<tr><td><strong>TOTAL ROWS</strong></td><td>' + (data.rows_read || 0) + '</td></tr>';
        html += '</table>';

        // Pre-populate scan name and target from manifest
        if (importType === 'fullrestore' && data.scan_name) {
            if (!$('#import-scan-name').val().trim()) {
                $('#import-scan-name').val(data.scan_name);
            }
            if (!$('#import-target').val().trim()) {
                $('#import-target').val(data.target || '');
            }
        }

        if (data.errors && data.errors.length > 0) {
            html += '<div class="alert alert-warning"><h5>WARNINGS (' + data.errors.length + ')</h5><ul>';
            for (var i = 0; i < Math.min(data.errors.length, 10); i++) {
                html += '<li>' + data.errors[i] + '</li>';
            }
            if (data.errors.length > 10) {
                html += '<li>... AND ' + (data.errors.length - 10) + ' MORE</li>';
            }
            html += '</ul></div>';
        }

        $content.html(html);

        // Show preview section, hide form
        $('#import-form-section').slideUp(200);
        $('#import-preview-section').slideDown(200);
        $('#import-results-section').hide();

        // Show the confirm button
        $('#btn-confirm-import').show();
    }

    function showPreviewError(data) {
        var $content = $('#import-preview-content');
        $content.empty();
        $content.html('<div class="alert alert-danger"><h4>VALIDATION FAILED</h4><p>' + (data.message || 'UNKNOWN ERROR') + '</p></div>');

        $('#import-form-section').slideUp(200);
        $('#import-preview-section').slideDown(200);
        $('#btn-confirm-import').hide();
    }

    // Confirm Import button - performs the actual import
    $('#btn-confirm-import').on('click', function() {
        var importType = $('#import-type').val();
        var fileInput = $('#import-file')[0];
        if (!fileInput.files || !fileInput.files[0]) {
            alertify.error('FILE REFERENCE LOST. PLEASE RE-SELECT THE FILE.');
            $('#import-preview-section').hide();
            $('#import-form-section').slideDown(200);
            return;
        }

        // Determine endpoint and build form data
        var url, formData = new FormData();
        formData.append('importfile', fileInput.files[0]);
        // No dry_run flag = actual import

        if (importType === 'fullrestore') {
            url = docroot + '/scanfullrestore';
            formData.append('scan_name', $('#import-scan-name').val().trim());
            formData.append('target', $('#import-target').val().trim());
        } else if (importType === 'selective') {
            url = docroot + '/scanrestoreselective';
            formData.append('import_type', $('#selective-csv-type').val());
            var scanId = $('#selective-scan-selector').val();
            if (scanId) {
                formData.append('scan_id', scanId);
            }
            formData.append('scan_name', $('#import-scan-name').val().trim());
            formData.append('target', $('#import-target').val().trim());
        } else {
            url = docroot + '/processimport';
            formData.append('import_type', importType);
            formData.append('scan_name', $('#import-scan-name').val().trim());
            formData.append('target', $('#import-target').val().trim());
        }

        var $btn = $('#btn-confirm-import');
        $btn.prop('disabled', true).html('<i class="glyphicon glyphicon-refresh spinning"></i> IMPORTING...');

        $.ajax({
            url: url,
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            dataType: 'json',
            success: function(data) {
                $btn.prop('disabled', false).html('<i class="glyphicon glyphicon-ok"></i> CONFIRM IMPORT');
                showImportResults(data, importType);
            },
            error: function(xhr) {
                $btn.prop('disabled', false).html('<i class="glyphicon glyphicon-ok"></i> CONFIRM IMPORT');
                var msg = 'IMPORT FAILED.';
                try {
                    var resp = JSON.parse(xhr.responseText);
                    if (resp.message) msg = resp.message;
                } catch(ex) {}
                alertify.error(msg);
            }
        });
    });

    function showImportResults(data, importType) {
        var $results = $('#import-results-content');
        $results.empty();

        // Hide preview
        $('#import-preview-section').slideUp(200);

        if (data.success) {
            var html = '<div class="alert alert-success">';
            html += '<h4>IMPORT SUCCESSFUL</h4>';
            html += '<p>' + data.message + '</p>';
            html += '</div>';

            // Stats table
            html += '<table class="table table-condensed import-stats-table">';
            if (data.scan_id) {
                html += '<tr><td><strong>SCAN ID</strong></td><td><code>' + data.scan_id + '</code></td></tr>';
            }

            // Full restore: show per-layer stats
            if (importType === 'fullrestore' && data.stats) {
                for (var key in data.stats) {
                    if (data.stats[key] > 0) {
                        var label = key.replace(/_/g, ' ').toUpperCase();
                        html += '<tr><td><strong>' + label + '</strong></td><td>' + data.stats[key] + '</td></tr>';
                    }
                }
            } else {
                html += '<tr><td><strong>ROWS READ</strong></td><td>' + (data.rows_read || 0) + '</td></tr>';
                html += '<tr><td><strong>ROWS IMPORTED</strong></td><td>' + (data.rows_imported || 0) + '</td></tr>';
                html += '<tr><td><strong>ROWS SKIPPED</strong></td><td>' + (data.rows_skipped || 0) + '</td></tr>';
            }

            if (data.fps_imported) {
                html += '<tr><td><strong>FALSE POSITIVES SAVED</strong></td><td>' + data.fps_imported + '</td></tr>';
            }
            if (data.validated_imported) {
                html += '<tr><td><strong>VALIDATED ITEMS SAVED</strong></td><td>' + data.validated_imported + '</td></tr>';
            }
            html += '</table>';

            if (data.errors && data.errors.length > 0) {
                html += '<div class="alert alert-warning"><h5>WARNINGS (' + data.errors.length + ')</h5><ul>';
                for (var i = 0; i < Math.min(data.errors.length, 10); i++) {
                    html += '<li>' + data.errors[i] + '</li>';
                }
                if (data.errors.length > 10) {
                    html += '<li>... AND ' + (data.errors.length - 10) + ' MORE</li>';
                }
                html += '</ul></div>';
            }

            if (data.scan_id) {
                html += '<a href="' + docroot + '/scaninfo?id=' + data.scan_id + '" class="btn btn-info">';
                html += '<i class="glyphicon glyphicon-eye-open"></i> VIEW IMPORTED SCAN</a>';
            }

            $results.html(html);
        } else {
            $results.html('<div class="alert alert-danger"><h4>IMPORT FAILED</h4><p>' + (data.message || 'UNKNOWN ERROR') + '</p></div>');
        }

        $('#import-results-section').slideDown(200);
    }
});
