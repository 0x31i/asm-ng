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
  const togglerText = document.getElementById("toggler-text");
  const themeLight = document.getElementById("theme-light");
  const themeDark = document.getElementById("theme-dark");

  // Set initial toggle state based on current theme
  if (localStorage.getItem("theme") === "dark-theme") {
    togglerText.innerText = "Light Mode";
    themeToggler.checked = true;
  } else {
    togglerText.innerText = "Dark Mode";
    themeToggler.checked = false;
  }

  themeToggler.addEventListener("click", () => {
    if (localStorage.getItem("theme") === "dark-theme") {
      // Switch to light theme
      localStorage.removeItem("theme");
      localStorage.setItem("mode", "Dark Mode");
      togglerText.innerText = "Dark Mode";
      themeLight.disabled = false;
      themeDark.disabled = true;
    } else {
      // Switch to dark theme
      localStorage.setItem("theme", "dark-theme");
      localStorage.setItem("mode", "Light Mode");
      togglerText.innerText = "Light Mode";
      themeLight.disabled = true;
      themeDark.disabled = false;
    }
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
  $(document).ready(function () {
    if ($("[rel=tooltip]").length) {
      $("[rel=tooltip]").tooltip({ container: "body" });
    }
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
