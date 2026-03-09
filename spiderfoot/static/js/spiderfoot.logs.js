// spiderfoot.logs.js — Centralized Log Management UI
// Loaded on Settings page (opts.tmpl) when Logs tab is active

var LogsUI = (function() {
    'use strict';

    var currentLogTab = 'activity';
    var autoRefreshTimer = null;

    // --- Sub-tab toggling ---
    function switchLogTab(tab) {
        currentLogTab = tab;
        var tabs = ['activity', 'scanlogs', 'apiaccess', 'system', 'requests'];
        for (var i = 0; i < tabs.length; i++) {
            var el = document.getElementById('logpane_' + tabs[i]);
            var tabEl = document.getElementById('logtab_' + tabs[i]);
            if (el) el.style.display = (tabs[i] === tab) ? 'block' : 'none';
            if (tabEl) {
                if (tabs[i] === tab) tabEl.classList.add('active');
                else tabEl.classList.remove('active');
            }
        }
        // Load data for the selected tab
        if (tab === 'activity') loadAuditLog(0);
        else if (tab === 'scanlogs') loadScanLogs(0);
        else if (tab === 'apiaccess') loadApiLogs(0);
        else if (tab === 'system') loadSystemLog('debug');
        else if (tab === 'requests') loadRequestLog(0);
    }

    // --- Audit Log ---
    function loadAuditLog(offset) {
        var limit = 50;
        var params = 'limit=' + limit + '&offset=' + offset;
        var action = $('#log-filter-action').val();
        var user = $('#log-filter-user').val();
        var search = $('#log-filter-search').val();
        var dateFrom = $('#log-filter-datefrom').val();
        var dateTo = $('#log-filter-dateto').val();

        if (action) params += '&action=' + encodeURIComponent(action);
        if (user) params += '&username=' + encodeURIComponent(user);
        if (search) params += '&search=' + encodeURIComponent(search);
        if (dateFrom) params += '&date_from=' + new Date(dateFrom).getTime();
        if (dateTo) params += '&date_to=' + (new Date(dateTo).getTime() + 86400000);

        $.getJSON(docroot + '/auditlogapi?' + params, function(data) {
            renderAuditTable(data);
            renderPagination('#audit-pagination', data.total, data.limit, data.offset, loadAuditLog);
        });
    }

    function renderAuditTable(data) {
        var actionClasses = {
            'LOGIN': 'label-success',
            'LOGIN_FAILED': 'label-danger',
            'LOGOUT': 'label-default',
            'SCAN_START': 'label-primary',
            'SCAN_STOP': 'label-warning',
            'SCAN_DELETE': 'label-danger',
            'SCAN_VIEW': 'label-default',
            'SETTINGS_SAVE': 'label-info',
            'SETTINGS_RESET': 'label-warning',
            'DATA_EXPORT': 'label-primary',
            'DATA_IMPORT': 'label-info',
            'DATA_MODIFY': 'label-warning',
            'ANALYST_NOTE': 'label-info',
            'ANALYST_COMMENT': 'label-info',
            'FP_ADD': 'label-warning',
            'FP_REMOVE': 'label-default',
            'DB_MAINTENANCE': 'label-default',
            'USER_CREATE': 'label-success',
            'USER_UPDATE': 'label-primary',
            'USER_DELETE': 'label-danger',
            'PASSWORD_CHANGE': 'label-warning',
            'EXT_KEY_CREATE': 'label-success',
            'EXT_KEY_REVOKE': 'label-danger',
            'EXT_KEY_REINSTATE': 'label-primary',
            'EXT_KEY_REVEAL': 'label-warning',
            'EXT_KEY_UPDATE': 'label-info',
            'EXT_REQUEST': 'label-primary',
            'EXT_AUTH_DENIED': 'label-danger',
            'EXT_RATE_LIMIT': 'label-warning',
            'SCAN_STATUS_OVERRIDE': 'label-warning',
            'RESOURCE_TIER': 'label-info',
            'UPDATE_CHECK': 'label-default',
            'UPDATE_APPLY': 'label-info',
            'LAUNCH_CODE_SET': 'label-info'
        };
        var rows = '';
        var entries = data.entries || [];
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            var cls = actionClasses[e.action] || 'label-default';
            rows += '<tr>' +
                '<td><span class="text-muted">' + escHtml(e.time_str || '') + '</span></td>' +
                '<td><strong>' + escHtml(e.username) + '</strong></td>' +
                '<td><span class="label ' + cls + '">' + escHtml(e.action) + '</span></td>' +
                '<td>' + escHtml(e.detail || '') + '</td>' +
                '<td><code>' + escHtml(e.ip_address || '') + '</code></td>' +
                '</tr>';
        }
        if (!entries.length) {
            rows = '<tr><td colspan="5" class="text-center text-muted" style="padding:30px;">No entries found.</td></tr>';
        }
        $('#audit-log-body').html(rows);
        $('#audit-log-count').text(data.total || 0);
    }

    // --- Scan Logs ---
    function loadScanLogs(offset) {
        var limit = 100;
        var params = 'limit=' + limit + '&offset=' + offset;
        var scanId = $('#scanlog-filter-scan').val();
        var logType = $('#scanlog-filter-type').val();
        var component = $('#scanlog-filter-component').val();
        var search = $('#scanlog-filter-search').val();

        if (scanId) params += '&scan_id=' + encodeURIComponent(scanId);
        if (logType) params += '&log_type=' + encodeURIComponent(logType);
        if (component) params += '&component=' + encodeURIComponent(component);
        if (search) params += '&search=' + encodeURIComponent(search);

        $.getJSON(docroot + '/scanlogsglobal?' + params, function(data) {
            var rows = '';
            var entries = data.entries || [];
            var typeClasses = {'ERROR': 'label-danger', 'WARNING': 'label-warning', 'STATUS': 'label-info', 'PROGRESS': 'label-default', 'DEBUG': 'label-default'};
            for (var i = 0; i < entries.length; i++) {
                var e = entries[i];
                var cls = typeClasses[e.type] || 'label-default';
                rows += '<tr>' +
                    '<td><span class="text-muted">' + escHtml(e.time_str || '') + '</span></td>' +
                    '<td>' + escHtml(e.scan_name || e.scan_id || '') + '</td>' +
                    '<td>' + escHtml(e.component || '') + '</td>' +
                    '<td><span class="label ' + cls + '">' + escHtml(e.type) + '</span></td>' +
                    '<td style="max-width:500px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escHtml(e.message || '') + '</td>' +
                    '</tr>';
            }
            if (!entries.length) {
                rows = '<tr><td colspan="5" class="text-center text-muted" style="padding:30px;">No scan logs found.</td></tr>';
            }
            $('#scanlog-body').html(rows);
            $('#scanlog-count').text(data.total || 0);
            renderPagination('#scanlog-pagination', data.total, data.limit, data.offset, loadScanLogs);
        });
    }

    // --- API Access Logs ---
    function loadApiLogs(offset) {
        var limit = 50;
        var params = 'limit=' + limit + '&offset=' + offset + '&action=EXT_*';
        $.getJSON(docroot + '/auditlogapi?' + params, function(data) {
            var rows = '';
            var entries = data.entries || [];
            var actionClasses = {
                'EXT_REQUEST': 'label-primary', 'EXT_AUTH_DENIED': 'label-danger',
                'EXT_RATE_LIMIT': 'label-warning', 'EXT_KEY_CREATE': 'label-success',
                'EXT_KEY_REVOKE': 'label-danger', 'EXT_KEY_REINSTATE': 'label-primary',
                'EXT_KEY_REVEAL': 'label-warning', 'EXT_KEY_UPDATE': 'label-info'
            };
            for (var i = 0; i < entries.length; i++) {
                var e = entries[i];
                var cls = actionClasses[e.action] || 'label-default';
                rows += '<tr>' +
                    '<td><span class="text-muted">' + escHtml(e.time_str || '') + '</span></td>' +
                    '<td><strong>' + escHtml(e.username) + '</strong></td>' +
                    '<td><span class="label ' + cls + '">' + escHtml(e.action) + '</span></td>' +
                    '<td>' + escHtml(e.detail || '') + '</td>' +
                    '<td><code>' + escHtml(e.ip_address || '') + '</code></td>' +
                    '</tr>';
            }
            if (!entries.length) {
                rows = '<tr><td colspan="5" class="text-center text-muted" style="padding:30px;">No API access entries found.</td></tr>';
            }
            $('#api-access-body').html(rows);
            $('#api-access-count').text(data.total || 0);
            renderPagination('#api-pagination', data.total, data.limit, data.offset, loadApiLogs);
        });
    }

    // --- System Log ---
    function loadSystemLog(logfile) {
        var lines = $('#syslog-lines').val() || '200';
        $.getJSON(docroot + '/systemlog?logfile=' + logfile + '&lines=' + lines, function(data) {
            var content = (data.lines || []).join('\n');
            $('#syslog-content').text(content);
            $('#syslog-filename').text(data.filename || '');
            // Scroll to bottom
            var pre = document.getElementById('syslog-content');
            if (pre) pre.scrollTop = pre.scrollHeight;
        });
    }

    // --- Request Log ---
    function loadRequestLog(offset) {
        var limit = 50;
        var params = 'limit=' + limit + '&offset=' + offset;
        var user = $('#reqlog-filter-user').val();
        var path = $('#reqlog-filter-path').val();

        if (user) params += '&username=' + encodeURIComponent(user);
        if (path) params += '&path=' + encodeURIComponent(path);

        $.getJSON(docroot + '/requestlogapi?' + params, function(data) {
            var rows = '';
            var entries = data.entries || [];
            for (var i = 0; i < entries.length; i++) {
                var e = entries[i];
                var statusCls = '';
                if (e.status_code >= 400) statusCls = 'text-danger';
                else if (e.status_code >= 300) statusCls = 'text-warning';
                rows += '<tr>' +
                    '<td><span class="text-muted">' + escHtml(e.time_str || '') + '</span></td>' +
                    '<td><strong>' + escHtml(e.username) + '</strong></td>' +
                    '<td><code>' + escHtml(e.method) + '</code></td>' +
                    '<td>' + escHtml(e.path) + '</td>' +
                    '<td class="' + statusCls + '">' + (e.status_code || '') + '</td>' +
                    '<td>' + (e.response_ms != null ? e.response_ms + 'ms' : '') + '</td>' +
                    '<td><code>' + escHtml(e.ip_address || '') + '</code></td>' +
                    '</tr>';
            }
            if (!entries.length) {
                rows = '<tr><td colspan="7" class="text-center text-muted" style="padding:30px;">No request log entries found.</td></tr>';
            }
            $('#reqlog-body').html(rows);
            $('#reqlog-count').text(data.total || 0);
            renderPagination('#reqlog-pagination', data.total, data.limit, data.offset, loadRequestLog);
        });
    }

    // --- Pagination Helper ---
    function renderPagination(selector, total, limit, offset, loadFn) {
        var pages = Math.ceil(total / limit);
        var currentPage = Math.floor(offset / limit);
        if (pages <= 1) { $(selector).html(''); return; }

        var html = '<nav><ul class="pagination pagination-sm">';
        // Previous
        if (currentPage > 0) {
            html += '<li><a href="javascript:void(0)" onclick="LogsUI._paginate(' + ((currentPage - 1) * limit) + ', \'' + selector + '\')">&laquo;</a></li>';
        } else {
            html += '<li class="disabled"><span>&laquo;</span></li>';
        }
        // Page numbers (show max 7 pages centered on current)
        var startPage = Math.max(0, currentPage - 3);
        var endPage = Math.min(pages - 1, startPage + 6);
        if (endPage - startPage < 6) startPage = Math.max(0, endPage - 6);
        for (var p = startPage; p <= endPage; p++) {
            if (p === currentPage) {
                html += '<li class="active"><span>' + (p + 1) + '</span></li>';
            } else {
                html += '<li><a href="javascript:void(0)" onclick="LogsUI._paginate(' + (p * limit) + ', \'' + selector + '\')">' + (p + 1) + '</a></li>';
            }
        }
        // Next
        if (currentPage < pages - 1) {
            html += '<li><a href="javascript:void(0)" onclick="LogsUI._paginate(' + ((currentPage + 1) * limit) + ', \'' + selector + '\')">&raquo;</a></li>';
        } else {
            html += '<li class="disabled"><span>&raquo;</span></li>';
        }
        html += '</ul></nav>';
        $(selector).html(html);
    }

    // Internal: dispatch paginate call to the right loader
    function _paginate(offset, selector) {
        if (selector === '#audit-pagination') loadAuditLog(offset);
        else if (selector === '#scanlog-pagination') loadScanLogs(offset);
        else if (selector === '#api-pagination') loadApiLogs(offset);
        else if (selector === '#reqlog-pagination') loadRequestLog(offset);
    }

    // --- CSV Export ---
    function exportLogCSV(logType) {
        var params = '';
        if (logType === 'audit') {
            var action = $('#log-filter-action').val();
            var user = $('#log-filter-user').val();
            var search = $('#log-filter-search').val();
            if (action) params += '&action=' + encodeURIComponent(action);
            if (user) params += '&username=' + encodeURIComponent(user);
            if (search) params += '&search=' + encodeURIComponent(search);
            window.location.href = docroot + '/auditlogexport?' + params;
        } else if (logType === 'scanlogs') {
            var scanId = $('#scanlog-filter-scan').val();
            var lt = $('#scanlog-filter-type').val();
            if (scanId) params += '&scan_id=' + encodeURIComponent(scanId);
            if (lt) params += '&log_type=' + encodeURIComponent(lt);
            window.location.href = docroot + '/scanlogexport?' + params;
        } else if (logType === 'requests') {
            var ru = $('#reqlog-filter-user').val();
            var rp = $('#reqlog-filter-path').val();
            if (ru) params += '&username=' + encodeURIComponent(ru);
            if (rp) params += '&path=' + encodeURIComponent(rp);
            window.location.href = docroot + '/requestlogexport?' + params;
        }
    }

    // --- Auto-refresh ---
    function toggleAutoRefresh(enabled) {
        if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
        if (enabled) {
            autoRefreshTimer = setInterval(function() {
                if (currentLogTab === 'system') loadSystemLog($('#syslog-select').val() || 'debug');
                else if (currentLogTab === 'activity') loadAuditLog(0);
            }, 10000);
        }
    }

    // --- Manual Purge ---
    function purgeLogsManual() {
        var auditDays = $('#retention-audit-days').val() || '';
        var scanDays = $('#retention-scan-days').val() || '';
        var requestDays = $('#retention-request-days').val() || '';

        if (!confirm('Are you sure you want to purge old log entries? This cannot be undone.')) return;

        var params = {};
        if (auditDays) params.audit_days = auditDays;
        if (scanDays) params.scan_days = scanDays;
        if (requestDays) params.request_days = requestDays;

        $.ajax({
            url: docroot + '/logpurge',
            type: 'GET',
            data: params,
            dataType: 'json',
            success: function(data) {
                if (data.success) {
                    var p = data.purged || {};
                    alert('Purge complete!\nAudit: ' + (p.audit || 0) + ' deleted\nScan: ' + (p.scan || 0) + ' deleted\nRequest: ' + (p.request || 0) + ' deleted');
                    // Reload current tab
                    switchLogTab(currentLogTab);
                } else {
                    alert('Purge failed: ' + (data.error || 'Unknown error'));
                }
            },
            error: function() { alert('Purge request failed.'); }
        });
    }

    // --- Save Retention Settings ---
    function saveRetentionSettings() {
        var params = {
            audit_days: $('#retention-audit-days').val(),
            scan_days: $('#retention-scan-days').val(),
            request_days: $('#retention-request-days').val()
        };
        $.ajax({
            url: docroot + '/logsettings',
            type: 'GET',
            data: params,
            dataType: 'json',
            success: function(data) {
                if (data.success) {
                    $('#retention-result').attr('class', 'alert alert-success').html('<strong>Saved!</strong> Retention settings updated.').show();
                } else {
                    $('#retention-result').attr('class', 'alert alert-danger').html('<strong>Error:</strong> ' + (data.error || 'Unknown')).show();
                }
                setTimeout(function(){ $('#retention-result').fadeOut(); }, 3000);
            }
        });
    }

    // --- Load filter dropdowns ---
    function loadFilterMeta() {
        $.getJSON(docroot + '/auditlogmeta', function(data) {
            var actionSel = $('#log-filter-action');
            actionSel.empty().append('<option value="">All Actions</option>');
            (data.actions || []).forEach(function(a) {
                actionSel.append('<option value="' + escHtml(a) + '">' + escHtml(a) + '</option>');
            });
            var userSel = $('#log-filter-user');
            userSel.empty().append('<option value="">All Users</option>');
            (data.users || []).forEach(function(u) {
                userSel.append('<option value="' + escHtml(u) + '">' + escHtml(u) + '</option>');
            });
        });
    }

    // --- HTML escape helper ---
    function escHtml(s) {
        if (!s) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(s));
        return div.innerHTML;
    }

    // --- Initialize ---
    function init() {
        loadFilterMeta();
        loadAuditLog(0);
    }

    // Public API
    return {
        switchLogTab: switchLogTab,
        loadAuditLog: loadAuditLog,
        loadScanLogs: loadScanLogs,
        loadApiLogs: loadApiLogs,
        loadSystemLog: loadSystemLog,
        loadRequestLog: loadRequestLog,
        exportLogCSV: exportLogCSV,
        toggleAutoRefresh: toggleAutoRefresh,
        purgeLogsManual: purgeLogsManual,
        saveRetentionSettings: saveRetentionSettings,
        init: init,
        _paginate: _paginate
    };
})();
