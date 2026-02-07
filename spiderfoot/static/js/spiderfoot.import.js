// SpiderFoot Import Page Handler

$(document).ready(function() {

    // Store form data between dry-run and actual import
    var pendingFormData = null;

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
        'legacy':    { accept: '.csv', hint: 'ACCEPTED FORMAT: CSV' },
        'scan':      { accept: '.csv', hint: 'ACCEPTED FORMAT: CSV' }
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

        // Show the form, hide preview/results
        $('#import-form-section').slideDown(200);
        $('#import-preview-section').hide();
        $('#import-results-section').hide();

        // Reset form
        $('#import-file').val('');
        $('#import-file-name').text('NO FILE SELECTED').removeClass('has-file');
        $('#import-scan-name').val('');
        $('#import-target').val('');

        // Reset button state
        $('#btn-import').prop('disabled', false).html('<i class="glyphicon glyphicon-import"></i> IMPORT');

        pendingFormData = null;
    });

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

        var fileInput = $('#import-file')[0];
        if (!fileInput.files || !fileInput.files[0]) {
            alertify.error('PLEASE SELECT A FILE TO IMPORT.');
            return;
        }

        var formData = new FormData();
        formData.append('importfile', fileInput.files[0]);
        formData.append('import_type', $('#import-type').val());

        var scanName = $('#import-scan-name').val().trim();
        if (scanName) {
            formData.append('scan_name', scanName);
        }

        var target = $('#import-target').val().trim();
        if (target) {
            formData.append('target', target);
        }

        // Always dry-run first
        formData.append('dry_run', '1');

        // Disable button and show loading
        var $btn = $('#btn-import');
        $btn.prop('disabled', true).html('<i class="glyphicon glyphicon-refresh spinning"></i> VALIDATING...');

        $.ajax({
            url: docroot + '/processimport',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            dataType: 'json',
            success: function(data) {
                $btn.prop('disabled', false).html('<i class="glyphicon glyphicon-import"></i> IMPORT');
                if (data.success) {
                    showPreview(data);
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

    function showPreview(data) {
        var $content = $('#import-preview-content');
        $content.empty();

        var html = '<div class="alert alert-info">';
        html += '<h4>VALIDATION PASSED</h4>';
        html += '<p>' + data.message + '</p>';
        html += '</div>';

        // Stats table
        html += '<table class="table table-condensed import-stats-table">';
        html += '<tr><td><strong>ROWS READ</strong></td><td>' + (data.rows_read || 0) + '</td></tr>';
        html += '<tr><td><strong>ROWS TO IMPORT</strong></td><td>' + (data.rows_imported || 0) + '</td></tr>';
        html += '<tr><td><strong>ROWS SKIPPED</strong></td><td>' + (data.rows_skipped || 0) + '</td></tr>';
        html += '<tr><td><strong>EVENT TYPES</strong></td><td>' + (data.event_types_count || 0) + '</td></tr>';
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
        var fileInput = $('#import-file')[0];
        if (!fileInput.files || !fileInput.files[0]) {
            alertify.error('FILE REFERENCE LOST. PLEASE RE-SELECT THE FILE.');
            $('#import-preview-section').hide();
            $('#import-form-section').slideDown(200);
            return;
        }

        var formData = new FormData();
        formData.append('importfile', fileInput.files[0]);
        formData.append('import_type', $('#import-type').val());

        var scanName = $('#import-scan-name').val().trim();
        if (scanName) {
            formData.append('scan_name', scanName);
        }

        var target = $('#import-target').val().trim();
        if (target) {
            formData.append('target', target);
        }

        // No dry_run flag = actual import

        var $btn = $('#btn-confirm-import');
        $btn.prop('disabled', true).html('<i class="glyphicon glyphicon-refresh spinning"></i> IMPORTING...');

        $.ajax({
            url: docroot + '/processimport',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            dataType: 'json',
            success: function(data) {
                $btn.prop('disabled', false).html('<i class="glyphicon glyphicon-ok"></i> CONFIRM IMPORT');
                showImportResults(data);
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

    function showImportResults(data) {
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
            html += '<tr><td><strong>ROWS READ</strong></td><td>' + (data.rows_read || 0) + '</td></tr>';
            html += '<tr><td><strong>ROWS IMPORTED</strong></td><td>' + (data.rows_imported || 0) + '</td></tr>';
            html += '<tr><td><strong>ROWS SKIPPED</strong></td><td>' + (data.rows_skipped || 0) + '</td></tr>';
            html += '<tr><td><strong>FALSE POSITIVES SAVED</strong></td><td>' + (data.fps_imported || 0) + '</td></tr>';
            html += '<tr><td><strong>VALIDATED ITEMS SAVED</strong></td><td>' + (data.validated_imported || 0) + '</td></tr>';
            html += '<tr><td><strong>EVENT TYPES</strong></td><td>' + (data.event_types_count || 0) + '</td></tr>';
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
