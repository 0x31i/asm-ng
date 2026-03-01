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
     * Strip the sfp_ prefix from module names for display.
     */
    function stripPrefix(name) {
        if (!name) return '';
        return name.replace(/^sfp_/, '');
    }

    /**
     * Render the module pipeline column.
     * modules: object { modName: { q: queueSize, r: isRunning, e: isErrored } }
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

        // Sort: running first, then by queue desc, errored last among idle
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
            // Running first
            if (a.r && !b.r) return -1;
            if (!a.r && b.r) return 1;
            // Then errored
            if (a.e && !b.e) return -1;
            if (!a.e && b.e) return 1;
            // Then by queue size desc
            return b.q - a.q;
        });

        var maxShow = 15;
        var shown = Math.min(entries.length, maxShow);

        for (var i = 0; i < shown; i++) {
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

        if (entries.length > maxShow) {
            html += '<div class="mod-more">+' + (entries.length - maxShow) + ' more</div>';
        }

        el.innerHTML = html;
    }

    /**
     * Render the event type grid column.
     * eventTypes: array [{ type, descr, count, unique, color }]
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

        var maxShow = 12;
        var shown = Math.min(eventTypes.length, maxShow);

        for (var i = 0; i < shown; i++) {
            var evt = eventTypes[i];
            html += '<div class="evt-pill">';
            html += '<span class="evt-pill-border" style="background:' + (evt.color || '#6b7280') + '"></span>';
            html += '<span class="evt-pill-count">' + formatNum(evt.count) + '</span>';
            html += '<span class="evt-pill-name" title="' + (evt.descr || evt.type) + '">' + (evt.descr || evt.type) + '</span>';
            html += '</div>';
        }

        if (eventTypes.length > maxShow) {
            html += '<div class="evt-more">+' + (eventTypes.length - maxShow) + ' more types</div>';
        }

        el.innerHTML = html;
    }

    /**
     * Render the recent discoveries column.
     * recentEvents: array [{ time, type, descr, preview, module }]
     */
    function renderRecentDiscoveries(container, recentEvents) {
        if (!container) return;
        var el = (typeof container === 'string') ? document.querySelector(container) : container;
        if (!el) return;

        var html = '<div class="monitor-col-header">RECENT DISCOVERIES</div>';

        if (!recentEvents || recentEvents.length === 0) {
            html += '<div class="recent-empty">Waiting for events...</div>';
            el.innerHTML = html;
            return;
        }

        var maxShow = 8;
        var shown = Math.min(recentEvents.length, maxShow);

        for (var i = 0; i < shown; i++) {
            var r = recentEvents[i];
            var preview = r.preview || '';
            // Escape HTML in preview
            preview = preview.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            if (preview.length > 60) preview = preview.substring(0, 60) + '...';

            html += '<div class="recent-item">';
            html += '<span class="recent-time">' + (r.time || '') + '</span>';
            html += '<span class="recent-type" title="' + (r.descr || r.type) + '">' + (r.type || '').replace(/_/g, ' ').substring(0, 14) + '</span>';
            html += '<span class="recent-data">' + preview + '</span>';
            html += '</div>';
        }

        el.innerHTML = html;
    }

    /**
     * Render stat cards row for scan detail page.
     * progress: { modulesTotal, modulesRunning, modulesErrored, eventsQueued, totalEvents, eventsPerSecond }
     */
    function renderStatCards(container, progress) {
        if (!container) return;
        var el = (typeof container === 'string') ? document.querySelector(container) : container;
        if (!el) return;

        var cards = [
            { value: (progress.modulesWithResults || 0) + '/' + (progress.modulesTotal || 0), label: 'MODULES' },
            { value: progress.modulesRunning || 0, label: 'RUNNING' },
            { value: formatNum(progress.eventsQueued), label: 'QUEUED' },
            { value: formatNum(progress.totalEvents), label: 'EVENTS' },
            { value: (progress.eventsPerSecond || 0) + '/s', label: 'RATE' },
            { value: progress.modulesErrored || 0, label: 'ERRORS' }
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
        html += '<div class="monitor-col" id="' + idPrefix + '-col-recent"></div>';
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

    // Public API
    return {
        formatNum: formatNum,
        renderModulePipeline: renderModulePipeline,
        renderEventTypeGrid: renderEventTypeGrid,
        renderRecentDiscoveries: renderRecentDiscoveries,
        renderStatCards: renderStatCards,
        buildDashboardHTML: buildDashboardHTML,
        updateDashboard: updateDashboard
    };
})();
