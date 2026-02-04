/**
 * spiderfoot.js
 * All the JavaScript code for the SpiderFoot aspects of the UI.
 * 
 * Author: Steve Micallef <steve@binarypool.com>
 * Created: 03/10/2012
 * Copyright: (c) Steve Micallef 2012
 * Licence: MIT
 */

// Toggler for theme
document.addEventListener("DOMContentLoaded", () => {
  const themeToggler = document.getElementById("theme-toggler");

  // Create theme transition overlay (hidden by default)
  var overlay = document.createElement('div');
  overlay.id = 'theme-transition-overlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:#1a1a2e;opacity:0;pointer-events:none;transition:opacity 0.15s ease;z-index:99999;';
  document.body.appendChild(overlay);

  // Set initial toggle state based on current theme
  if (localStorage.getItem("theme") === "dark-theme") {
    themeToggler.checked = true;
  } else {
    themeToggler.checked = false;
    overlay.style.background = '#ffffff';
  }

  themeToggler.addEventListener("click", () => {
    var themeLink = document.getElementById("theme-css");
    var isDark = localStorage.getItem("theme") === "dark-theme";
    var newHref;

    // Set overlay color based on target theme
    overlay.style.background = isDark ? '#ffffff' : '#1a1a2e';

    // Fade in overlay to hide the transition
    overlay.style.opacity = '1';
    overlay.style.pointerEvents = 'auto';

    // Small delay to let overlay fade in
    setTimeout(function() {
      if (isDark) {
        // Switch to light theme
        localStorage.removeItem("theme");
        newHref = docroot + "/static/css/spiderfoot.css?v=" + Date.now();
        document.body.classList.remove('dark-mode');
      } else {
        // Switch to dark theme
        localStorage.setItem("theme", "dark-theme");
        newHref = docroot + "/static/css/dark.css?v=" + Date.now();
        document.body.classList.add('dark-mode');
      }

      if (themeLink) {
        // Create new link element to preload CSS
        var newLink = document.createElement('link');
        newLink.rel = 'stylesheet';
        newLink.id = 'theme-css-new';
        newLink.href = newHref;

        // When new CSS loads, swap and fade out overlay
        newLink.onload = function() {
          themeLink.remove();
          newLink.id = 'theme-css';

          // Fade out overlay after CSS is applied
          setTimeout(function() {
            overlay.style.opacity = '0';
            overlay.style.pointerEvents = 'none';
          }, 50);
        };

        // Fallback in case onload doesn't fire
        newLink.onerror = function() {
          overlay.style.opacity = '0';
          overlay.style.pointerEvents = 'none';
        };

        // Insert new link after the old one
        themeLink.parentNode.insertBefore(newLink, themeLink.nextSibling);
      }

      // Dispatch custom event for components that need to react to theme change
      document.dispatchEvent(new CustomEvent('themeChanged', {
        detail: { isDark: !isDark }
      }));
    }, 150);
  });
});

var sf = {};

sf.replace_sfurltag = function (data) {
  if (data.toLowerCase().indexOf("&lt;sfurl&gt;") >= 0) {
    data = data.replace(
      RegExp("&lt;sfurl&gt;(.*)&lt;/sfurl&gt;", "img"),
      "<a target=_new href='$1'>$1</a>"
    );
  }
  if (data.toLowerCase().indexOf("<sfurl>") >= 0) {
    data = data.replace(
      RegExp("<sfurl>(.*)</sfurl>", "img"),
      "<a target=_new href='$1'>$1</a>"
    );
  }
  return data;
};

sf.remove_sfurltag = function (data) {
  if (data.toLowerCase().indexOf("&lt;sfurl&gt;") >= 0) {
    data = data
      .toLowerCase()
      .replace("&lt;sfurl&gt;", "")
      .replace("&lt;/sfurl&gt;", "");
  }
  if (data.toLowerCase().indexOf("<sfurl>") >= 0) {
    data = data.toLowerCase().replace("<sfurl>", "").replace("</sfurl>", "");
  }
  return data;
};

sf.search = function (scan_id, value, type, postFunc) {
  sf.fetchData(
    docroot + "/search",
    { id: scan_id, eventType: type, value: value },
    postFunc
  );
};

sf.deleteScan = function(scan_id, callback) {
    var req = $.ajax({
      type: "GET",
      url: docroot + "/scandelete?id=" + scan_id
    });
    req.done(function() {
        alertify.success('<i class="glyphicon glyphicon-ok-circle"></i> <b>Scans Deleted</b><br/><br/>' + scan_id.replace(/,/g, "<br/>"));
        sf.log("Deleted scans: " + scan_id);
        callback();
    });
    req.fail(function (hr, textStatus, errorThrown) {
        alertify.error('<i class="glyphicon glyphicon-minus-sign"></i> <b>Error</b><br/></br>' + hr.responseText);
        sf.log("Error deleting scans: " + scan_id + ": " + hr.responseText);
    });
};

sf.stopScan = function(scan_id, callback) {
    var req = $.ajax({
      type: "GET",
      url: docroot + "/stopscan?id=" + scan_id
    });
    req.done(function() {
        alertify.success('<i class="glyphicon glyphicon-ok-circle"></i> <b>Scans Aborted</b><br/><br/>' + scan_id.replace(/,/g, "<br/>"));
        sf.log("Aborted scans: " + scan_id);
        callback();
    });
    req.fail(function (hr, textStatus, errorThrown) {
        alertify.error('<i class="glyphicon glyphicon-minus-sign"></i> <b>Error</b><br/><br/>' + hr.responseText);
        sf.log("Error stopping scans: " + scan_id + ": " + hr.responseText);
    });
};

sf.fetchData = function (url, postData, postFunc) {
  var req = $.ajax({
    type: "POST",
    url: url,
    data: postData,
    cache: false,
    dataType: "json",
  });

  req.done(postFunc);
  req.fail(function (hr, status) {
      alertify.error('<i class="glyphicon glyphicon-minus-sign"></i> <b>Error</b><br/>' + status);
  });
};

sf.updateTooltips = function () {
  var tooltipElements = $("[rel=tooltip]");
  if (tooltipElements.length) {
    // Safely destroy existing tooltips to prevent duplicates
    tooltipElements.each(function() {
      var $el = $(this);
      // Only destroy if tooltip was previously initialized
      if ($el.data('bs.tooltip')) {
        $el.tooltip('destroy');
      }
      // Convert data-title to title for Bootstrap tooltip compatibility
      if ($el.attr('data-title') && !$el.attr('title')) {
        $el.attr('title', $el.attr('data-title'));
      }
    });
    // Initialize tooltips with trigger on hover only
    tooltipElements.tooltip({
      container: "body",
      trigger: "hover"
    });
    // Hide tooltip immediately on any click (use off first to prevent duplicates)
    tooltipElements.off('click.tooltipfix mousedown.tooltipfix').on('click.tooltipfix mousedown.tooltipfix', function () {
      $(this).tooltip('hide');
    });
  }
  // Global handler to hide all tooltips when any dropdown opens
  $(document).off('show.bs.dropdown.tooltipfix').on('show.bs.dropdown.tooltipfix', function () {
    $("[rel=tooltip]").tooltip('hide');
  });
};

sf.log = function (message) {
  if (typeof console == "object" && typeof console.log == "function") {
    var currentdate = new Date();
    var pad = function (n) {
      return ("0" + n).slice(-2);
    };
    var datetime =
      currentdate.getFullYear() +
      "-" +
      pad(currentdate.getMonth() + 1) +
      "-" +
      pad(currentdate.getDate()) +
      " " +
      pad(currentdate.getHours()) +
      ":" +
      pad(currentdate.getMinutes()) +
      ":" +
      pad(currentdate.getSeconds());
    console.log("[" + datetime + "] " + message);
  }
};

// Responsive design adjustments
window.addEventListener("resize", () => {
  const width = window.innerWidth;

  if (width < 576) {
    document.body.style.fontSize = "0.6rem";
  } else if (width < 768) {
    document.body.style.fontSize = "0.7rem";
  } else if (width < 992) {
    document.body.style.fontSize = "0.8rem";
  } else if (width < 1200) {
    document.body.style.fontSize = "0.9rem";
  } else {
    document.body.style.fontSize = "1rem";
  }
});
