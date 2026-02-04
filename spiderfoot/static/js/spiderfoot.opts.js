activeTab = "global";

function saveSettings() {
    var retarr = {}
    $(":input").each(function(i) {
        retarr[$(this).attr('id')] = $(this).val();
    });

    $("#allopts").val(JSON.stringify(retarr));
}

function clearSettings() {
    $("#allopts").val("RESET");
}

function switchTab(tab) {
    $("#optsect_"+activeTab).hide();
    $("#optsect_"+tab).show();
    $("#tab_"+activeTab).removeClass("active");
    $("#tab_"+tab).addClass("active");
    activeTab = tab;

    // Scroll the sticky content panel back to top
    var contentPanel = document.querySelector('.tab-content');
    if (contentPanel) {
        contentPanel.scrollTop = 0;
    }
}

function getFile(elemId) {
   var elem = document.getElementById(elemId);
   if(elem && document.createEvent) {
      var evt = document.createEvent("MouseEvents");
      evt.initEvent("click", true, false);
      elem.dispatchEvent(evt);
   }
}

// ============================================
// Change detection and toolbar state management
// ============================================
var settingsModified = false;
var originalValues = {};
var saveConfirmPending = false;
var discardConfirmPending = false;

function captureOriginalValues() {
    var form = document.getElementById('savesettingsform');
    if (!form) return;
    var elements = form.querySelectorAll('input[type="text"], select');
    elements.forEach(function(el) {
        if (!el.id || el.id === 'allopts' || el.id === 'token') return;
        originalValues[el.id] = el.value;
    });
}

function checkForChanges() {
    var form = document.getElementById('savesettingsform');
    if (!form) return;
    var hasChanges = false;
    var elements = form.querySelectorAll('input[type="text"], select');
    elements.forEach(function(el) {
        if (!el.id || el.id === 'allopts' || el.id === 'token') return;
        if (originalValues.hasOwnProperty(el.id) && el.value !== originalValues[el.id]) {
            hasChanges = true;
        }
    });

    if (hasChanges && !settingsModified) {
        settingsModified = true;
        showChangeToolbar();
    } else if (!hasChanges && settingsModified) {
        settingsModified = false;
        hideChangeToolbar();
    }
}

function showChangeToolbar() {
    document.getElementById('toolbar-default').style.display = 'none';
    document.getElementById('toolbar-changes').style.display = '';
    resetConfirmStates();
    // Push the sticky content panel down so the toolbar doesn't cover it
    var contentPanel = document.querySelector('.tabbable.tabs-left > .tab-content');
    if (contentPanel) {
        var bar = document.getElementById('toolbar-changes');
        var barHeight = bar ? bar.offsetHeight : 50;
        contentPanel.style.top = (barHeight + 10) + 'px';
    }
}

function hideChangeToolbar() {
    document.getElementById('toolbar-changes').style.display = 'none';
    document.getElementById('toolbar-default').style.display = '';
    resetConfirmStates();
    // Restore the content panel's original sticky position
    var contentPanel = document.querySelector('.tabbable.tabs-left > .tab-content');
    if (contentPanel) {
        contentPanel.style.top = '20px';
    }
}

function resetConfirmStates() {
    saveConfirmPending = false;
    discardConfirmPending = false;

    var saveBtn = document.getElementById('btn-save-changes');
    var discardBtn = document.getElementById('btn-discard-changes');

    if (saveBtn) {
        saveBtn.textContent = 'Save Changes';
        saveBtn.classList.remove('confirm-save');
    }
    if (discardBtn) {
        discardBtn.textContent = 'Discard Changes';
        discardBtn.classList.remove('confirm-discard');
    }
}

function handleSaveClick() {
    if (!saveConfirmPending) {
        // First click: enter confirm state
        saveConfirmPending = true;
        discardConfirmPending = false;

        var saveBtn = document.getElementById('btn-save-changes');
        var discardBtn = document.getElementById('btn-discard-changes');

        saveBtn.textContent = 'Confirm';
        saveBtn.classList.add('confirm-save');

        // Reset discard if it was in confirm state
        if (discardBtn) {
            discardBtn.textContent = 'Discard Changes';
            discardBtn.classList.remove('confirm-discard');
        }
    } else {
        // Second click: actually save
        saveSettings();
        document.getElementById('savesettingsform').submit();
    }
}

function handleDiscardClick() {
    if (!discardConfirmPending) {
        // First click: enter confirm state
        discardConfirmPending = true;
        saveConfirmPending = false;

        var discardBtn = document.getElementById('btn-discard-changes');
        var saveBtn = document.getElementById('btn-save-changes');

        discardBtn.textContent = 'Confirm';
        discardBtn.classList.add('confirm-discard');

        // Reset save if it was in confirm state
        if (saveBtn) {
            saveBtn.textContent = 'Save Changes';
            saveBtn.classList.remove('confirm-save');
        }
    } else {
        // Second click: revert all changes
        revertAllChanges();
    }
}

function revertAllChanges() {
    var form = document.getElementById('savesettingsform');
    if (!form) return;
    var elements = form.querySelectorAll('input[type="text"], select');
    elements.forEach(function(el) {
        if (!el.id || el.id === 'allopts' || el.id === 'token') return;
        if (originalValues.hasOwnProperty(el.id)) {
            el.value = originalValues[el.id];
        }
    });
    settingsModified = false;
    hideChangeToolbar();
}

// ============================================
// Unsaved changes warning - beforeunload & navigation interception
// ============================================
var pendingNavigationUrl = null;

function showUnsavedWarning(url) {
    pendingNavigationUrl = url || null;
    document.getElementById('unsaved-warning-overlay').style.display = '';
}

function hideUnsavedWarning() {
    document.getElementById('unsaved-warning-overlay').style.display = 'none';
    pendingNavigationUrl = null;
}

function handleWarningLeave() {
    // Discard changes and navigate away
    settingsModified = false;
    hideUnsavedWarning();
    if (pendingNavigationUrl) {
        window.location.href = pendingNavigationUrl;
    }
}

function handleWarningContinue() {
    // Close modal and return to editing
    hideUnsavedWarning();
    if (settingsModified) showChangeToolbar();
}

function handleWarningSaveAndLeave() {
    // Save settings then navigate away
    saveSettings();
    settingsModified = false;
    var url = pendingNavigationUrl;
    hideUnsavedWarning();
    document.getElementById('savesettingsform').submit();
}

$(document).ready(function() {
    // Wire up buttons
    $("#btn-save-changes").click(function(e) { e.preventDefault(); handleSaveClick(); return false; });
    $("#btn-discard-changes").click(function(e) { e.preventDefault(); handleDiscardClick(); return false; });
    $("#btn-import-config").click(function() { getFile("configFile"); return false; });
    $("#btn-reset-settings").click(function() { clearSettings(); });
    $("#btn-opt-export").click(function() { window.location.href=docroot + "/optsexport?pattern=api_key"; return false; });
    $("#tab_global").click(function() { switchTab("global"); });

    // Capture original values after DOM is ready
    captureOriginalValues();

    // Listen for changes on all form inputs and selects
    $('#savesettingsform').on('input change', 'input[type="text"], select', function() {
        checkForChanges();
    });

    // Click anywhere else resets confirm states (but not the toolbar)
    $(document).on('click', function(e) {
        if (!$(e.target).is('#btn-save-changes') && !$(e.target).is('#btn-discard-changes')) {
            if (saveConfirmPending || discardConfirmPending) {
                resetConfirmStates();
            }
        }
    });

    // Browser beforeunload warning (native dialog for tab close / refresh / address bar navigation)
    window.addEventListener('beforeunload', function(e) {
        if (settingsModified) {
            e.preventDefault();
            e.returnValue = '';
        }
    });

    // Intercept all link clicks to show custom warning modal
    $(document).on('click', 'a[href]', function(e) {
        if (!settingsModified) return;

        var href = $(this).attr('href');
        // Ignore javascript: links, anchors, and empty hrefs
        if (!href || href === '#' || href.indexOf('javascript:') === 0) return;

        e.preventDefault();
        e.stopPropagation();
        showUnsavedWarning(href);
    });

    // Wire up warning modal buttons
    $('#unsaved-warning-leave').click(function() { handleWarningLeave(); });
    $('#unsaved-warning-continue').click(function() { handleWarningContinue(); });
    $('#unsaved-warning-save').click(function() { handleWarningSaveAndLeave(); });

    // Close modal on overlay click (outside the modal box)
    $('#unsaved-warning-overlay').click(function(e) {
        if (e.target === this) {
            hideUnsavedWarning();
        }
    });

    // Close modal on Escape key
    $(document).on('keydown', function(e) {
        if (e.key === 'Escape' && document.getElementById('unsaved-warning-overlay').style.display !== 'none') {
            hideUnsavedWarning();
        }
    });
});

$(function () {
  $('[data-toggle="popover"]').popover()
  $('[data-toggle="popover"]').on("show.bs.popover", function() { $(this).data("bs.popover").tip().css("max-width", "600px") });
});

document.addEventListener('DOMContentLoaded', function () {
    var form = document.getElementById('savesettingsform');
    if (!form) return;

    form.addEventListener('submit', function (e) {
        // Collect all input and select values
        var opts = {};
        var elements = form.querySelectorAll('input, select');
        elements.forEach(function (el) {
            if (!el.id || el.id === 'allopts' || el.id === 'token' || el.type === 'file') return;
            if (el.type === 'checkbox') {
                opts[el.id] = el.checked;
            } else if (el.tagName.toLowerCase() === 'select') {
                // For bool selects, convert to boolean
                if (el.options.length === 2 &&
                    el.options[0].value === "1" && el.options[1].value === "0") {
                    opts[el.id] = el.value === "1";
                } else {
                    opts[el.id] = el.value;
                }
            } else {
                opts[el.id] = el.value;
            }
        });
        // Set the JSON string to the hidden allopts field
        document.getElementById('allopts').value = JSON.stringify(opts);
    });

    // Handle reset button to set allopts to "RESET"
    var resetBtn = document.getElementById('btn-reset-settings');
    if (resetBtn) {
        resetBtn.addEventListener('click', function (e) {
            e.preventDefault();
            document.getElementById('allopts').value = "RESET";
            form.submit();
        });
    }
});
