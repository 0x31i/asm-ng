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

// Track whether settings have been modified
var settingsModified = false;
var originalValues = {};

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
        showFloatingSaveBar();
    } else if (!hasChanges && settingsModified) {
        settingsModified = false;
        hideFloatingSaveBar();
    }
}

function showFloatingSaveBar() {
    var bar = document.getElementById('floating-save-bar');
    if (bar) {
        bar.classList.add('visible');
    }
}

function hideFloatingSaveBar() {
    var bar = document.getElementById('floating-save-bar');
    if (bar) {
        bar.classList.remove('visible');
    }
}

$(document).ready(function() {
    // Wire up static buttons
    $("#btn-save-changes").click(function() { saveSettings(); });
    $("#btn-save-floating").click(function() { saveSettings(); });
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

    // Optional: handle reset button to set allopts to "RESET"
    var resetBtn = document.getElementById('btn-reset-settings');
    if (resetBtn) {
        resetBtn.addEventListener('click', function (e) {
            e.preventDefault();
            document.getElementById('allopts').value = "RESET";
            form.submit();
        });
    }
});
