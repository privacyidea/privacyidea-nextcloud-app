import {generateUrl} from '@nextcloud/router';

const BASE_URL = '/apps/privacyidea/';

document.addEventListener("DOMContentLoaded", function ()
{
    /* Util functions */
    const getValue = function (key, callback) {
        $.get(generateUrl(BASE_URL + 'getValue'), {key: key}).done(
            function (result) {
                callback(result);
            }
        );
    };
    const setValue = function (key, value) {
        OC.msg.startSaving('#piSettingsMsg');
        $.post(generateUrl(BASE_URL + 'setValue'), {
            key: key,
            value: value
        }, function (data) {
            OC.msg.finishedSuccess('#piSettingsMsg', "Saved");
        });
    };

    /* Activate privacyIDEA */
    getValue("piActivatePI", function (piActivatePI)
    {
        $("#piSettings #piActivatePI").prop('checked', piActivatePI === "1");
    });
    document.getElementById("piActivatePI").addEventListener("change", function ()
    {
        setValue("piActivatePI", $(this).is(":checked") ? "1" : "0");
    });

    /* privacyIDEA instance URL */
    getValue("piURL", function (piURL)
    {
        $("#piSettings #piURL").val(piURL);
    });
    document.getElementById("piURL").addEventListener("change", function ()
    {
        console.log("pi: Saving URL");
        let value = $("#piSettings #piURL").val();
        console.log(value);
        setValue("piURL", value);
    });

    /* verify SSL (checkbox) */
    getValue("piSSLVerify", function (piSSLVerify)
    {
        /* NOTE: We check for `!== "0"` instead of `=== "1"` here in order to be consistent with the Provider. */
        $("#piSettings #piSSLVerify").prop('checked', piSSLVerify !== "0");
    });
    document.getElementById("piSSLVerify").addEventListener("change", function ()
    {
        setValue("piSSLVerify", $(this).is(":checked") ? "1" : "0");
    });

    /* privacyIDEA realm */
    getValue("piRealm", function (realm)
    {
        $("#piSettings #piRealm").val(realm);
    });
    document.getElementById("piRealm").addEventListener("change", function ()
    {
        // Always save the value
        console.log("pi: Saving Realm");
        let value = $("#piSettings #piRealm").val();
        console.log(value);
        setValue("piRealm", value);
    });

    /* Exclude given IPs from MFA */
    getValue("piExcludeIPs", function (excludeIPs)
    {
        $("#piSettings #piExcludeIPs").val(excludeIPs);
    });
    document.getElementById("piExcludeIPs").addEventListener("change", function ()
    {
        console.log("pi: Saving excluded IPs");
        let value = $("#piSettings #piExcludeIPs").val();
        setValue("piExcludeIPs", value);
    });

    /* Bypass Proxy (checkbox) */
    getValue("piNoProxy", function (piNoProxy)
    {
        $("#piSettings #piNoProxy").prop('checked', piNoProxy === "1");
    });
    document.getElementById("piNoProxy").addEventListener("change", function ()
    {
        setValue("piNoProxy", $(this).is(":checked") ? "1" : "0");
    });

    /* Forward client IP (checkbox) */
    getValue("piForwardClientIP", function (piForwardClientIP)
    {
        $("#piSettings #piForwardClientIP").prop('checked', piForwardClientIP === "1");
    });
    document.getElementById("piForwardClientIP").addEventListener("change", function ()
    {
        setValue("piForwardClientIP", $(this).is(":checked") ? "1" : "0");
    });

    /* Timeout */
    getValue("piTimeout", function (piTimeout)
    {
        $("#piSettings #piTimeout").val(piTimeout);
    });
    document.getElementById("piTimeout").addEventListener("change", function ()
    {
        console.log("pi: Saving Timeout");
        let value = $("#piSettings #piTimeout").val();
        setValue("piTimeout", value);
    });

    /* Include / Exclude nextCloud user groups */
    let radioInclude = document.getElementById('piIncludeGroups');
    let radioExclude = document.getElementById('piExcludeGroups');
    getValue("piInOrExSelected", function (piInOrExSelected)
    {
        $("#piSettings #piIncludeGroups").prop('checked', piInOrExSelected === "include");
        $("#piSettings #piExcludeGroups").prop('checked', piInOrExSelected === "exclude");
    });
    document.getElementById("piIncludeGroups").addEventListener("change", function ()
    {
        if (radioInclude.checked)
        {
            setValue("piInOrExSelected", "include");
        }
    });
    document.getElementById("piExcludeGroups").addEventListener("change", function ()
    {
        if (radioExclude.checked)
        {
            setValue("piInOrExSelected", "exclude");
        }
    });
    getValue("piInExGroupsField", function (piInExGroupsField)
    {
        $("#piSettings #piInExGroupsField").val(piInExGroupsField);
        OC.Settings.setupGroupsSelect($('#piSettings #piInExGroupsField'));
    });
    document.getElementById("piInExGroupsField").addEventListener("change", function ()
    {
        console.log("pi: Saving In/Excluded groups");
        let value = $("#piSettings #piInExGroupsField").val();
        setValue("piInExGroupsField", value);
    });

    /* Authentication flow */
    let radioAuthFlowDef = document.getElementById('piAuthFlowDefault');
    let radioAuthFlowTriggerChallenge = document.getElementById('piAuthFlowTriggerChallenge');
    let radioAuthFlowSeparateOTP = document.getElementById('piAuthFlowSeparateOTP');
    let radioAuthFlowSendStaticPass = document.getElementById('piAuthFlowSendStaticPass');
    getValue("piSelectedAuthFlow", function (piSelectedAuthFlow)
    {
        $("#piSettings #piAuthFlowDefault").prop('checked', piSelectedAuthFlow === "piAuthFlowDefault");
        $("#piSettings #piAuthFlowTriggerChallenge").prop('checked', piSelectedAuthFlow === "piAuthFlowTriggerChallenge");
        $("#piSettings #piAuthFlowSeparateOTP").prop('checked', piSelectedAuthFlow === "piAuthFlowSeparateOTP");
    });
    document.getElementById("piAuthFlowDefault").addEventListener("change", function ()
    {
        if (radioAuthFlowDef.checked)
        {
            setValue("piSelectedAuthFlow", "piAuthFlowDefault");
        }
    });
    document.getElementById("piAuthFlowTriggerChallenge").addEventListener("change", function ()
    {
        if (radioAuthFlowTriggerChallenge.checked)
        {
            setValue("piSelectedAuthFlow", "piAuthFlowTriggerChallenge");
        }
    });
    document.getElementById("piAuthFlowSeparateOTP").addEventListener("change", function ()
    {
        if (radioAuthFlowSeparateOTP.checked)
        {
            setValue("piSelectedAuthFlow", "piAuthFlowSeparateOTP");
        }
    });
    document.getElementById("piAuthFlowSendStaticPass").addEventListener("change", function ()
    {
        if (radioAuthFlowSendStaticPass.checked)
        {
            setValue("piSelectedAuthFlow", "piAuthFlowSendStaticPass");
        }
    });

    /* Service account name */
    getValue("piServiceName", function (piServiceName)
    {
        $("#piSettings #piServiceName").val(piServiceName);
    });
    document.getElementById("piServiceName").addEventListener("change", function ()
    {
        console.log("pi: Saving service account name");
        let value = $("#piSettings #piServiceName").val();
        setValue("piServiceName", value);
    });

    /* Service account pass */
    getValue("piServicePass", function (piServicePass)
    {
        $("#piSettings #piServicePass").val(piServicePass);
    });
    document.getElementById("piServicePass").addEventListener("change", function ()
    {
        console.log("pi: Saving service account pass");
        let value = $("#piSettings #piServicePass").val();
        setValue("piServicePass", value);
    });

    /* Service account realm */
    getValue("piServiceRealm", function (piServiceRealm)
    {
        $("#piSettings #piServiceRealm").val(piServiceRealm);
    });
    document.getElementById("piServiceRealm").addEventListener("change", function ()
    {
        console.log("pi: Saving service account realm");
        let value = $("#piSettings #piServiceRealm").val();
        setValue("piServiceRealm", value);
    });

    /* Static pass */
    getValue("piStaticPass", function (piStaticPass)
    {
        $("#piSettings #piStaticPass").val(piStaticPass);
    });
    document.getElementById("piStaticPass").addEventListener("change", function ()
    {
        console.log("pi: Saving static pass");
        let value = $("#piSettings #piStaticPass").val();
        setValue("piStaticPass", value);
    });

    /* Poll in browser */
    getValue("piPollInBrowser", function (piPollInBrowser)
    {
        $("#piSettings #piPollInBrowser").prop('checked', piPollInBrowser === "0");
    });
    document.getElementById("piPollInBrowser").addEventListener("change", function ()
    {
        let checked = $(this).is(":checked");
        setValue("piPollInBrowser", checked ? "1" : "0");
    });
    getValue("piPollInBrowserURL", function (piPollInBrowserURL)
    {
        $("#piSettings #piPollInBrowserURL").val(piPollInBrowserURL);
    });
    document.getElementById("piPollInBrowserURL").addEventListener("change", function ()
    {
        console.log("pi: Saving URL for poll in browser");
        let value = $("#piSettings #piPollInBrowserURL").val();
        setValue("piPollInBrowserURL", value);
    });

    /* Form-auto-submit after X digits entered */
    getValue("piActivateAutoSubmitOtpLength", function (piActivateAutoSubmitOtpLength)
    {
        $("#piSettings #piActivateAutoSubmitOtpLength").prop('checked', piActivateAutoSubmitOtpLength === "1");
    });
    document.getElementById("piActivateAutoSubmitOtpLength").addEventListener("change", function ()
    {
        setValue("piActivateAutoSubmitOtpLength", $(this).is(":checked") ? "1" : "0");
    });
    getValue("piAutoSubmitOtpLength", function (piAutoSubmitOtpLength)
    {
        $("#piSettings #piAutoSubmitOtpLength").val(piAutoSubmitOtpLength);
    });
    document.getElementById("piAutoSubmitOtpLength").addEventListener("change", function ()
    {
        console.log("pi: Saving OTP length for auto submit function");
        let value = $("#piSettings #piAutoSubmitOtpLength").val();
        setValue("piAutoSubmitOtpLength", value);
    });

    // todo add forward headers
    // todo add default message

    /* Let the user log in if the user is not found in privacyIDEA */
    /*getValue("piPassOnNoUser", function (piPassOnNoUser)
    {
        let value = (piPassOnNoUser === "1");
        $("#piSettings #piPassOnNoUser").prop('checked', value);
    });
    document.getElementById("piPassOnNoUser").addEventListener("change", function ()
    {
        let checked = $(this).is(":checked");
        setValue("piPassOnNoUser", checked ? "1" : "0");
    });*/
});