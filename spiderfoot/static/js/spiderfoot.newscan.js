    tabs = [ "use", "type", "module" ];
    activeTab = "use";

    function submitForm() {
        list = "";
        $("[id^="+activeTab+"_]").each(function() {
            if ($(this).is(":checked")) {
                list += $(this).attr('id') + ",";
            }
        });

        $("#"+activeTab+"list").val(list);
        for (i = 0; i < tabs.length; tabs++) {
            if (tabs[i] != activeTab) {
                $("#"+tabs[i]+"list").val("");
            }
        }

        // For non-admin users, show launch code modal instead of submitting
        if (typeof userRole !== 'undefined' && userRole !== 'admin') {
            $('#launch-code-error').hide();
            $('#launch-code-input').val('');
            $('#launchCodeModal').modal('show');
            return false;
        }
    }

    function switchTab(tabname) {
        $("#"+activeTab+"table").hide();
        $("#"+activeTab+"tab").removeClass("active");
        $("#"+tabname+"table").show();
        $("#"+tabname+"tab").addClass("active");
        activeTab = tabname;
        if (activeTab == "use") {
            $("#selectors").hide();
        } else {
            $("#selectors").show();
        }
    }

    function selectAll() {
        $("[id^="+activeTab+"_]").prop("checked", true);
    }

    function deselectAll() {
        $("[id^="+activeTab+"_]").prop("checked", false);
    }

$(document).ready(function() {
    $("#usetab").click(function() { switchTab("use"); });
    $("#typetab").click(function() { switchTab("type"); });
    $("#moduletab").click(function() { switchTab("module"); });
    $("#btn-select-all").click(function() { selectAll(); });
    $("#btn-deselect-all").click(function() { deselectAll(); });
    $("#btn-run-scan").click(function(e) {
        submitForm();
        // If submitForm returned false (non-admin), prevent form submission
        if (typeof userRole !== 'undefined' && userRole !== 'admin') {
            e.preventDefault();
            return false;
        }
    });

    // Launch code modal submit handler
    $('#launch-code-submit').click(function() {
        var code = $('#launch-code-input').val();
        if (!code) {
            $('#launch-code-error').text('Please enter the launch code.').show();
            return;
        }
        $('#launch_code').val(code);
        $('#launchCodeModal').modal('hide');
        $('form.form').submit();
    });

    $('#scantarget').popover({ 'html': true, 'animation': true, 'trigger': 'focus'});
});
