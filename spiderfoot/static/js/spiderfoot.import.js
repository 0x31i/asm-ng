// SpiderFoot Import Page Handler

$(document).ready(function() {

    // Card click handlers
    $('.import-card').on('click', function() {
        var importType = $(this).data('import-type');

        // Disabled cards show alert
        if ($(this).hasClass('import-card-disabled')) {
            alertify.warning($(this).find('.import-card-title').text() + ' import is coming soon.');
            return;
        }

        // Highlight selected card
        $('.import-card').removeClass('import-card-selected');
        $(this).addClass('import-card-selected');

        // Set form values based on type
        $('#import-type').val(importType);

        // Update form title
        var title = $(this).find('.import-card-title').text();
        $('#import-form-title').text('Import: ' + title);

        // Show the form
        $('#import-form-section').slideDown(200);
        $('#import-results-section').hide();

        // Reset form
        $('#import-file').val('');
        $('#import-scan-name').val('');
        $('#import-target').val('');
        $('#import-dry-run').prop('checked', false);
    });

    // Cancel button
    $('#btn-import-cancel').on('click', function() {
        $('#import-form-section').slideUp(200);
        $('.import-card').removeClass('import-card-selected');
    });

    // Form submission
    $('#import-form').on('submit', function(e) {
        e.preventDefault();

        var fileInput = $('#import-file')[0];
        if (!fileInput.files || !fileInput.files[0]) {
            alertify.error('Please select a file to import.');
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

        if ($('#import-dry-run').is(':checked')) {
            formData.append('dry_run', '1');
        }

        // Disable button and show loading
        var $btn = $('#btn-import');
        var originalText = $btn.html();
        $btn.prop('disabled', true).html('<i class="glyphicon glyphicon-refresh spinning"></i> Importing...');

        $.ajax({
            url: docroot + '/processimport',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            dataType: 'json',
            success: function(data) {
                $btn.prop('disabled', false).html(originalText);
                showImportResults(data);
            },
            error: function(xhr) {
                $btn.prop('disabled', false).html(originalText);
                var msg = 'Import failed.';
                try {
                    var resp = JSON.parse(xhr.responseText);
                    if (resp.message) msg = resp.message;
                } catch(e) {}
                alertify.error(msg);
            }
        });
    });

    function showImportResults(data) {
        var $results = $('#import-results-content');
        $results.empty();

        var isDryRun = data.dry_run || false;
        var titlePrefix = isDryRun ? 'Dry Run Results' : 'Import Results';
        $('#import-results-title').text(titlePrefix);

        if (data.success) {
            var alertClass = isDryRun ? 'alert-info' : 'alert-success';
            var html = '<div class="alert ' + alertClass + '">';
            html += '<h4>' + (isDryRun ? 'Validation Passed' : 'Import Successful') + '</h4>';
            html += '<p>' + data.message + '</p>';
            html += '</div>';

            // Stats table
            html += '<table class="table table-condensed" style="max-width: 500px;">';
            if (data.scan_id) {
                html += '<tr><td><strong>Scan ID</strong></td><td><code>' + data.scan_id + '</code></td></tr>';
            }
            html += '<tr><td><strong>Rows Read</strong></td><td>' + (data.rows_read || 0) + '</td></tr>';
            html += '<tr><td><strong>Rows Imported</strong></td><td>' + (data.rows_imported || 0) + '</td></tr>';
            html += '<tr><td><strong>Rows Skipped</strong></td><td>' + (data.rows_skipped || 0) + '</td></tr>';
            html += '<tr><td><strong>False Positives Saved</strong></td><td>' + (data.fps_imported || 0) + '</td></tr>';
            html += '<tr><td><strong>Validated Items Saved</strong></td><td>' + (data.validated_imported || 0) + '</td></tr>';
            html += '<tr><td><strong>Event Types</strong></td><td>' + (data.event_types_count || 0) + '</td></tr>';
            html += '</table>';

            if (data.errors && data.errors.length > 0) {
                html += '<div class="alert alert-warning"><h5>Warnings (' + data.errors.length + ')</h5><ul>';
                for (var i = 0; i < Math.min(data.errors.length, 10); i++) {
                    html += '<li>' + data.errors[i] + '</li>';
                }
                if (data.errors.length > 10) {
                    html += '<li>... and ' + (data.errors.length - 10) + ' more</li>';
                }
                html += '</ul></div>';
            }

            if (!isDryRun && data.scan_id) {
                html += '<a href="' + docroot + '/scaninfo?id=' + data.scan_id + '" class="btn btn-info">';
                html += '<i class="glyphicon glyphicon-eye-open"></i> View Imported Scan</a>';
            }

            $results.html(html);
        } else {
            $results.html('<div class="alert alert-danger"><h4>Import Failed</h4><p>' + (data.message || 'Unknown error') + '</p></div>');
        }

        $('#import-results-section').slideDown(200);
    }
});
