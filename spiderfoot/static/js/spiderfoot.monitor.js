/**
 * spiderfoot.monitor.js — Shared renderer functions for the scan monitoring dashboard.
 * Used by both the scan list page (expandable panel) and the scan detail page.
 */

var sfMonitor = (function() {
    'use strict';

    /**
     * Format a number as 1.2k, 3.4M, etc.
     */
    function formatNum(n) {
        if (n == null) return '0';
        n = parseInt(n, 10);
        if (isNaN(n)) return '0';
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
        return n.toString();
    }

    /**
     * Format seconds into a human-readable elapsed string, e.g. "1h 23m 45s".
     */
    function formatElapsed(seconds) {
        if (!seconds || seconds <= 0) return '—';
        seconds = Math.floor(seconds);
        var h = Math.floor(seconds / 3600);
        var m = Math.floor((seconds % 3600) / 60);
        var s = seconds % 60;
        if (h > 0) return h + 'h ' + m + 'm';
        if (m > 0) return m + 'm ' + s + 's';
        return s + 's';
    }

    /**
     * Strip the sfp_ prefix from module names for display.
     */
    function stripPrefix(name) {
        if (!name) return '';
        return name.replace(/^sfp_/, '');
    }

    /**
     * Render the module pipeline column.
     * modules: object { modName: { q: queueSize, r: isRunning, e: isErrored } }
     * Shows ALL modules (column scrolls); running first, then queued, then idle.
     */
    function renderModulePipeline(container, modules) {
        if (!container) return;
        var el = (typeof container === 'string') ? document.querySelector(container) : container;
        if (!el) return;

        var html = '<div class="monitor-col-header">MODULE PIPELINE</div>';

        if (!modules || Object.keys(modules).length === 0) {
            html += '<div class="mod-more">No module data yet</div>';
            el.innerHTML = html;
            return;
        }

        // Sort: running first, then queued, then errored, then idle (by queue desc)
        var entries = [];
        for (var name in modules) {
            if (!modules.hasOwnProperty(name)) continue;
            var m = modules[name];
            entries.push({
                name: name,
                q: m.q || 0,
                r: !!m.r,
                e: !!m.e
            });
        }

        entries.sort(function(a, b) {
            if (a.r && !b.r) return -1;
            if (!a.r && b.r) return 1;
            if (a.e && !b.e) return -1;
            if (!a.e && b.e) return 1;
            return b.q - a.q;
        });

        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            var state = 'idle';
            if (e.e) state = 'errored';
            else if (e.r) state = 'running';
            else if (e.q > 0) state = 'queued';

            html += '<div class="mod-item">';
            html += '<span class="mod-indicator ' + state + '"></span>';
            html += '<span class="mod-name">' + stripPrefix(e.name) + '</span>';
            if (e.q > 0) {
                html += '<span class="mod-queue-badge">' + formatNum(e.q) + '</span>';
            }
            html += '</div>';
        }

        el.innerHTML = html;
    }

    /**
     * Render the event type grid column.
     * eventTypes: array [{ type, descr, count, unique, color }]
     * Shows ALL event types with both total count and unique count.
     */
    function renderEventTypeGrid(container, eventTypes) {
        if (!container) return;
        var el = (typeof container === 'string') ? document.querySelector(container) : container;
        if (!el) return;

        var html = '<div class="monitor-col-header">LIVE EVENT TYPES</div>';

        if (!eventTypes || eventTypes.length === 0) {
            html += '<div class="evt-more">No events yet</div>';
            el.innerHTML = html;
            return;
        }

        for (var i = 0; i < eventTypes.length; i++) {
            var evt = eventTypes[i];
            html += '<div class="evt-pill">';
            html += '<span class="evt-pill-border" style="background:' + (evt.color || '#6b7280') + '"></span>';
            html += '<span class="evt-pill-count">' + formatNum(evt.count) + '</span>';
            if (evt.unique && evt.unique !== evt.count) {
                html += '<span class="evt-pill-uniq" title="' + evt.unique + ' unique values">' + formatNum(evt.unique) + 'u</span>';
            }
            html += '<span class="evt-pill-name" title="' + (evt.descr || evt.type) + '">' + (evt.descr || evt.type) + '</span>';
            html += '</div>';
        }

        el.innerHTML = html;
    }

    /**
     * Render the recent discoveries column.
     * recentEvents: array [{ time, type, descr, preview, module }]
     * Shows up to 100 items (most recent first); column scrolls.
     */
    function renderRecentDiscoveries(container, recentEvents) {
        if (!container) return;
        var el = (typeof container === 'string') ? document.querySelector(container) : container;
        if (!el) return;

        var html = '<div class="monitor-col-header">RECENT DISCOVERIES (' + (recentEvents ? recentEvents.length : 0) + ')</div>';

        if (!recentEvents || recentEvents.length === 0) {
            html += '<div class="recent-empty">Waiting for events...</div>';
            el.innerHTML = html;
            return;
        }

        for (var i = 0; i < recentEvents.length; i++) {
            var r = recentEvents[i];
            var preview = r.preview || '';
            // Escape HTML in preview
            preview = preview.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            if (preview.length > 80) preview = preview.substring(0, 80) + '…';

            var typeLabel = (r.type || '').replace(/_/g, ' ');
            var modLabel = r.module ? stripPrefix(r.module) : '';

            html += '<div class="recent-item">';
            html += '<span class="recent-time">' + (r.time || '') + '</span>';
            html += '<span class="recent-type" title="' + (r.descr || r.type) + '">' + typeLabel + '</span>';
            if (modLabel) {
                html += '<span class="recent-module" title="Module: ' + r.module + '">' + modLabel + '</span>';
            }
            html += '<span class="recent-data" title="' + preview + '">' + preview + '</span>';
            html += '</div>';
        }

        el.innerHTML = html;
    }

    /**
     * Render stat cards row for scan detail page.
     * progress: { modulesTotal, modulesRunning, modulesErrored, eventsQueued,
     *             totalEvents, eventsPerSecond, scanStarted }
     */
    function renderStatCards(container, progress) {
        if (!container) return;
        var el = (typeof container === 'string') ? document.querySelector(container) : container;
        if (!el) return;

        var elapsed = '—';
        if (progress.scanStarted && progress.scanStarted > 0) {
            var nowSec = Math.floor(Date.now() / 1000);
            elapsed = formatElapsed(nowSec - progress.scanStarted);
        }

        var cards = [
            { value: (progress.modulesWithResults || 0) + '/' + (progress.modulesTotal || 0), label: 'MODULES' },
            { value: (progress.weightedProgressPercent || 0) + '%', label: 'WEIGHTED' },
            { value: progress.modulesRunning || 0, label: 'RUNNING' },
            { value: formatNum(progress.eventsQueued), label: 'QUEUED' },
            { value: formatNum(progress.totalEvents), label: 'EVENTS' },
            { value: (progress.eventsPerSecond || 0) + '/s', label: 'RATE' },
            { value: progress.modulesErrored || 0, label: 'ERRORS' },
            { value: elapsed, label: 'ELAPSED' }
        ];

        var html = '';
        for (var i = 0; i < cards.length; i++) {
            html += '<div class="monitor-stat-card">';
            html += '<div class="stat-value">' + cards[i].value + '</div>';
            html += '<div class="stat-label">' + cards[i].label + '</div>';
            html += '</div>';
        }

        el.innerHTML = html;
    }

    /**
     * Build complete 3-column dashboard HTML structure.
     * Returns the container element ID suffix for targeting columns.
     */
    function buildDashboardHTML(idPrefix) {
        var html = '<div class="monitor-dashboard" id="' + idPrefix + '-dashboard">';
        html += '<div class="monitor-stat-row" id="' + idPrefix + '-stats"></div>';
        html += '<div class="monitor-columns">';
        html += '<div class="monitor-col" id="' + idPrefix + '-col-modules"></div>';
        html += '<div class="monitor-col" id="' + idPrefix + '-col-events"></div>';
        html += '<div class="monitor-col monitor-col-recent" id="' + idPrefix + '-col-recent"></div>';
        html += '</div>';
        html += '</div>';
        return html;
    }

    /**
     * Update a full monitoring dashboard with data from /scanmonitor.
     */
    function updateDashboard(idPrefix, data) {
        if (!data) return;

        var progress = data.progress || {};
        var modules = data.modules || {};
        var eventTypes = data.eventTypes || [];
        var recentEvents = data.recentEvents || [];

        renderStatCards('#' + idPrefix + '-stats', progress);
        renderModulePipeline('#' + idPrefix + '-col-modules', modules);
        renderEventTypeGrid('#' + idPrefix + '-col-events', eventTypes);
        renderRecentDiscoveries('#' + idPrefix + '-col-recent', recentEvents);
    }

    /**
     * Format seconds into a long elapsed string including days.
     * Returns "4d 2h" / "1h 23m" / "45m" / "--"
     */
    function formatElapsedLong(seconds) {
        if (!seconds || seconds <= 0) return '--';
        seconds = Math.floor(seconds);
        var d = Math.floor(seconds / 86400);
        var h = Math.floor((seconds % 86400) / 3600);
        var m = Math.floor((seconds % 3600) / 60);
        if (d > 0) return d + 'd ' + h + 'h';
        if (h > 0) return h + 'h ' + m + 'm';
        if (m > 0) return m + 'm';
        return seconds + 's';
    }

    /**
     * Render the dual-bar progress panel.
     * container: selector string or DOM element
     * progress: object from scanProgress() with new enriched fields
     */
    function renderProgressPanel(container, progress) {
        if (!container) return;
        var el = (typeof container === 'string') ? document.querySelector(container) : container;
        if (!el) return;

        var done = progress.modulesWithResults || 0;
        var total = progress.modulesTotal || 0;
        var weightedPct = progress.weightedProgressPercent || 0;
        var rate = progress.eventsPerSecond || 0;
        var phase = progress.currentPhase || '';
        var phaseNum = progress.phaseNumber || 0;
        var pace = progress.modulePace || 0;
        var prevDur = progress.previousScanDuration || 0;
        var status = progress.status || '';

        // Fallback: use simple module ratio if no weighted data
        var barPct = weightedPct;
        if (!barPct && total > 0) {
            barPct = Math.round((done / total) * 100);
        }

        // Terminal states
        var isTerminal = (status === 'FINISHED' || status === 'ABORTED' || status === 'ERROR-FAILED');
        if (isTerminal) {
            barPct = 100;
            phase = 'Complete';
            phaseNum = 3;
        }

        // Activity bar: log2(rate+1)*15, capped at 100
        var activityPct = rate > 0 ? Math.min(100, Math.round(Math.log2(rate + 1) * 15)) : 0;
        var activityClass = rate > 0 ? 'activity-alive' : 'activity-idle';
        if (isTerminal) {
            activityPct = 0;
            activityClass = 'activity-idle';
        }

        var html = '<div class="progress-dual">';
        // Bar 1: Modules (weighted)
        html += '<div class="progress-bar-row">';
        html += '<span class="progress-label">MODULES</span>';
        html += '<div class="progress-slim"><div class="progress-bar" style="width: ' + barPct + '%;"></div></div>';
        html += '<span class="progress-fraction">' + done + ' / ' + total + '</span>';
        html += '</div>';
        // Bar 2: Activity
        html += '<div class="progress-bar-row">';
        html += '<span class="progress-label">ACTIVITY</span>';
        html += '<div class="progress-slim progress-activity ' + activityClass + '"><div class="progress-bar" style="width: ' + activityPct + '%;"></div></div>';
        html += '<span class="progress-fraction">' + rate + '/s</span>';
        html += '</div>';
        html += '</div>';

        // Info row
        html += '<div class="progress-info-row">';
        if (phase) {
            var dotClass = 'phase-dot phase-' + phaseNum;
            html += '<span class="progress-phase"><span class="' + dotClass + '"></span>';
            if (phaseNum > 0 && !isTerminal) {
                html += 'Phase ' + phaseNum + ': ';
            }
            html += phase + '</span>';
        }

        // Elapsed
        if (progress.scanStarted && progress.scanStarted > 0) {
            var nowSec = Math.floor(Date.now() / 1000);
            var elapsed = formatElapsedLong(nowSec - progress.scanStarted);
            html += '<span class="progress-info-sep">|</span>';
            html += '<span class="progress-elapsed">Elapsed: ' + elapsed + '</span>';
        }

        // Modules done
        if (done > 0) {
            html += '<span class="progress-info-sep">|</span>';
            html += '<span class="progress-elapsed">' + done + ' modules done</span>';
        }

        // Pace
        if (pace > 0 && !isTerminal) {
            html += '<span class="progress-info-sep">|</span>';
            html += '<span class="progress-elapsed">~' + Math.round(pace) + ' modules/day</span>';
        }

        // Historical reference
        if (prevDur > 0) {
            html += '<span class="progress-info-sep">|</span>';
            html += '<span class="progress-historical">Previous scan: ' + formatElapsedLong(prevDur) + '</span>';
        }

        html += '</div>';

        el.innerHTML = html;
    }

    // Public API
    return {
        formatNum: formatNum,
        formatElapsed: formatElapsed,
        formatElapsedLong: formatElapsedLong,
        renderModulePipeline: renderModulePipeline,
        renderEventTypeGrid: renderEventTypeGrid,
        renderRecentDiscoveries: renderRecentDiscoveries,
        renderStatCards: renderStatCards,
        renderProgressPanel: renderProgressPanel,
        buildDashboardHTML: buildDashboardHTML,
        updateDashboard: updateDashboard
    };
})();
