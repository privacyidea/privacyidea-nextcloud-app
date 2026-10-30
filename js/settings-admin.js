const BASE_URL = '/apps/privacyidea/';

document.addEventListener("DOMContentLoaded", function ()
{
    /* Util functions */
    // Plain fetch() instead of jQuery: Nextcloud 34+ no longer provides a global $.
    // jQuery added the CSRF token automatically, so send it here. Read it from the
    // page head on every call, because Nextcloud refreshes it there.
    const requestHeaders = function ()
    {
        return {requesttoken: document.head.dataset.requesttoken};
    };
    const getValue = function (key, callback)
    {
        fetch(OC.generateUrl(BASE_URL + 'getValue') + '?' + new URLSearchParams({key: key}), {
            headers: requestHeaders()
        }).then(function (response)
        {
            if (!response.ok)
            {
                throw new Error(response.statusText);
            }
            return response.json();
        }).then(callback);
    };
    const setValue = function (key, value)
    {
        OC.msg.startSaving('#piSettingsMsg');
        fetch(OC.generateUrl(BASE_URL + 'setValue'), {
            method: 'POST',
            headers: requestHeaders(),
            body: new URLSearchParams({key: key, value: value})
        }).then(function (response)
        {
            if (!response.ok)
            {
                throw new Error(response.statusText);
            }
            OC.msg.finishedSuccess('#piSettingsMsg', "Saved");
        }).catch(function ()
        {
            OC.msg.finishedError('#piSettingsMsg', "Saving failed");
        });
    };

    /* Activate privacyIDEA */
    getValue("piActivatePI", function (piActivatePI)
    {
        document.getElementById("piActivatePI").checked = piActivatePI === "1";
    });
    document.getElementById("piActivatePI").addEventListener("change", function ()
    {
        if (this.checked)
        {
            if (document.getElementById("piURL").value.length > 0)
            {
                setValue("piActivatePI", "1");
            }
            else
            {
                OC.msg.finishedError('#piSettingsMsg', "Cannot activate privacyIDEA without server URL provided.");
            }
        }
        else
        {
            setValue("piActivatePI", "0");
        }
    });

    /* privacyIDEA instance URL */
    getValue("piURL", function (piURL)
    {
        document.getElementById("piURL").value = piURL;
    });
    document.getElementById("piURL").addEventListener("change", function ()
    {
        let value = document.getElementById("piURL").value;
        console.log(value);
        setValue("piURL", value);
    });

    /* verify SSL (checkbox) */
    getValue("piSSLVerify", function (piSSLVerify)
    {
        /* NOTE: We check for `!== "0"` instead of `=== "1"` here in order to be consistent with the Provider. */
        document.getElementById("piSSLVerify").checked = piSSLVerify !== "0";
    });
    document.getElementById("piSSLVerify").addEventListener("change", function ()
    {
        setValue("piSSLVerify", this.checked ? "1" : "0");
    });

    /* privacyIDEA realm */
    getValue("piRealm", function (realm)
    {
        document.getElementById("piRealm").value = realm;
    });
    document.getElementById("piRealm").addEventListener("change", function ()
    {
        // Always save the value
        let value = document.getElementById("piRealm").value;
        console.log(value);
        setValue("piRealm", value);
    });

    /* Exclude given IPs from MFA */
    getValue("piExcludeIPs", function (excludeIPs)
    {
        document.getElementById("piExcludeIPs").value = excludeIPs;
    });
    document.getElementById("piExcludeIPs").addEventListener("change", function ()
    {
        let value = document.getElementById("piExcludeIPs").value;
        setValue("piExcludeIPs", value);
    });

    /* Bypass Proxy (checkbox) */
    getValue("piNoProxy", function (piNoProxy)
    {
        document.getElementById("piNoProxy").checked = piNoProxy === "1";
    });
    document.getElementById("piNoProxy").addEventListener("change", function ()
    {
        setValue("piNoProxy", this.checked ? "1" : "0");
    });

    /* Forward client IP (checkbox) */
    getValue("piForwardClientIP", function (piForwardClientIP)
    {
        document.getElementById("piForwardClientIP").checked = piForwardClientIP === "1";
    });
    document.getElementById("piForwardClientIP").addEventListener("change", function ()
    {
        setValue("piForwardClientIP", this.checked ? "1" : "0");
    });

    /* Timeout */
    getValue("piTimeout", function (piTimeout)
    {
        document.getElementById("piTimeout").value = piTimeout;
    });
    document.getElementById("piTimeout").addEventListener("change", function ()
    {
        let value = document.getElementById("piTimeout").value;
        setValue("piTimeout", value);
    });

    /* Include / Exclude nextCloud user groups */
    let radioInclude = document.getElementById('piIncludeGroups');
    let radioExclude = document.getElementById('piExcludeGroups');
    getValue("piInOrExSelected", function (piInOrExSelected)
    {
        document.getElementById("piIncludeGroups").checked = piInOrExSelected === "include";
        document.getElementById("piExcludeGroups").checked = piInOrExSelected === "exclude";
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
        document.getElementById("piInExGroupsField").value = piInExGroupsField;
    });
    document.getElementById("piInExGroupsField").addEventListener("change", function ()
    {
        let value = document.getElementById("piInExGroupsField").value;
        setValue("piInExGroupsField", value);
    });

    /* Authentication flow (behavior) + input layout (display) */
    let radioAuthFlowDef = document.getElementById('piAuthFlowDefault');
    let radioAuthFlowTriggerChallenge = document.getElementById('piAuthFlowTriggerChallenge');
    let radioAuthFlowSendPassword = document.getElementById('piAuthFlowSendPassword');
    let radioAuthFlowSendStaticPass = document.getElementById('piAuthFlowSendStaticPass');
    let radioLayoutOtpOnly = document.getElementById('piLayoutOtpOnly');
    let radioLayoutSeparate = document.getElementById('piLayoutSeparate');
    let layoutMigrated = false;

    getValue("piSelectedAuthFlow", function (piSelectedAuthFlow)
    {
        // Backward compatibility: the former "Separate OTP" flow is now the
        // "separate" input layout with no pre-render behaviour. Migrate it once.
        if (piSelectedAuthFlow === "piAuthFlowSeparateOTP")
        {
            setValue("piSelectedAuthFlow", "piAuthFlowDefault");
            setValue("piInputLayout", "separate");
            piSelectedAuthFlow = "piAuthFlowDefault";
            layoutMigrated = true;
            radioLayoutSeparate.checked = true;
            radioLayoutOtpOnly.checked = false;
        }
        radioAuthFlowDef.checked = piSelectedAuthFlow === "piAuthFlowDefault";
        radioAuthFlowTriggerChallenge.checked = piSelectedAuthFlow === "piAuthFlowTriggerChallenge";
        radioAuthFlowSendPassword.checked = piSelectedAuthFlow === "piAuthFlowSendPassword";
        radioAuthFlowSendStaticPass.checked = piSelectedAuthFlow === "piAuthFlowSendStaticPass";
    });
    radioAuthFlowDef.addEventListener("change", function ()
    {
        if (radioAuthFlowDef.checked) { setValue("piSelectedAuthFlow", "piAuthFlowDefault"); }
    });
    radioAuthFlowTriggerChallenge.addEventListener("change", function ()
    {
        if (radioAuthFlowTriggerChallenge.checked) { setValue("piSelectedAuthFlow", "piAuthFlowTriggerChallenge"); }
    });
    radioAuthFlowSendPassword.addEventListener("change", function ()
    {
        if (radioAuthFlowSendPassword.checked) { setValue("piSelectedAuthFlow", "piAuthFlowSendPassword"); }
    });
    radioAuthFlowSendStaticPass.addEventListener("change", function ()
    {
        if (radioAuthFlowSendStaticPass.checked) { setValue("piSelectedAuthFlow", "piAuthFlowSendStaticPass"); }
    });

    getValue("piInputLayout", function (piInputLayout)
    {
        if (layoutMigrated) { return; }
        radioLayoutSeparate.checked = piInputLayout === "separate";
        radioLayoutOtpOnly.checked = piInputLayout !== "separate";
    });
    radioLayoutOtpOnly.addEventListener("change", function ()
    {
        if (radioLayoutOtpOnly.checked) { setValue("piInputLayout", "otp"); }
    });
    radioLayoutSeparate.addEventListener("change", function ()
    {
        if (radioLayoutSeparate.checked) { setValue("piInputLayout", "separate"); }
    });

    /* Service account name */
    getValue("piServiceName", function (piServiceName)
    {
        document.getElementById("piServiceName").value = piServiceName;
    });
    document.getElementById("piServiceName").addEventListener("change", function ()
    {
        let value = document.getElementById("piServiceName").value;
        setValue("piServiceName", value);
    });

    /* Service account pass */
    getValue("piServicePass", function (piServicePass)
    {
        document.getElementById("piServicePass").value = piServicePass;
    });
    document.getElementById("piServicePass").addEventListener("change", function ()
    {
        let value = document.getElementById("piServicePass").value;
        setValue("piServicePass", value);
    });

    /* Service account realm */
    getValue("piServiceRealm", function (piServiceRealm)
    {
        document.getElementById("piServiceRealm").value = piServiceRealm;
    });
    document.getElementById("piServiceRealm").addEventListener("change", function ()
    {
        let value = document.getElementById("piServiceRealm").value;
        setValue("piServiceRealm", value);
    });

    /* Static pass */
    getValue("piStaticPass", function (piStaticPass)
    {
        document.getElementById("piStaticPass").value = piStaticPass;
    });
    document.getElementById("piStaticPass").addEventListener("change", function ()
    {
        let value = document.getElementById("piStaticPass").value;
        setValue("piStaticPass", value);
    });

    /* Poll in browser */
    getValue("piPollInBrowser", function (piPollInBrowser)
    {
        document.getElementById("piPollInBrowser").checked = piPollInBrowser === "1";
    });
    document.getElementById("piPollInBrowser").addEventListener("change", function ()
    {
        let checked = this.checked;
        setValue("piPollInBrowser", checked ? "1" : "0");
    });
    getValue("piPollInBrowserURL", function (piPollInBrowserURL)
    {
        document.getElementById("piPollInBrowserURL").value = piPollInBrowserURL;
    });
    document.getElementById("piPollInBrowserURL").addEventListener("change", function ()
    {
        let value = document.getElementById("piPollInBrowserURL").value;
        setValue("piPollInBrowserURL", value);
    });

    /* Form-auto-submit after X digits entered */
    getValue("piActivateAutoSubmitOtpLength", function (piActivateAutoSubmitOtpLength)
    {
        document.getElementById("piActivateAutoSubmitOtpLength").checked = piActivateAutoSubmitOtpLength === "1";
    });
    document.getElementById("piActivateAutoSubmitOtpLength").addEventListener("change", function ()
    {
        let checked = this.checked;
        setValue("piActivateAutoSubmitOtpLength", checked ? "1" : "0");
    });
    getValue("piAutoSubmitOtpLength", function (piAutoSubmitOtpLength)
    {
        document.getElementById("piAutoSubmitOtpLength").value = piAutoSubmitOtpLength;
    });
    document.getElementById("piAutoSubmitOtpLength").addEventListener("change", function ()
    {
        let value = document.getElementById("piAutoSubmitOtpLength").value;
        setValue("piAutoSubmitOtpLength", value);
    });

    /* Forward headers */
    getValue("piForwardHeaders", function (piForwardHeaders)
    {
        document.getElementById("piForwardHeaders").value = piForwardHeaders;
    });
    document.getElementById("piForwardHeaders").addEventListener("change", function ()
    {
        let value = document.getElementById("piForwardHeaders").value;
        setValue("piForwardHeaders", value);
    });

    /* OTP field hint (placeholder) */
    getValue("piOTPFieldHint", function (piOTPFieldHint)
    {
        document.getElementById("piOTPFieldHint").value = piOTPFieldHint;
    });
    document.getElementById("piOTPFieldHint").addEventListener("change", function ()
    {
        let value = document.getElementById("piOTPFieldHint").value;
        setValue("piOTPFieldHint", value);
    });

    /* Password/PIN field hint (placeholder) */
    getValue("piPassFieldHint", function (piPassFieldHint)
    {
        document.getElementById("piPassFieldHint").value = piPassFieldHint;
    });
    document.getElementById("piPassFieldHint").addEventListener("change", function ()
    {
        let value = document.getElementById("piPassFieldHint").value;
        setValue("piPassFieldHint", value);
    });

    // todo add default message
    // todo add passOnNoUser
    /* Let the user log in if the user is not found in privacyIDEA */
    /*getValue("piPassOnNoUser", function (piPassOnNoUser)
    {
        let value = (piPassOnNoUser === "1");
        document.getElementById("piPassOnNoUser").checked = value;
    });
    document.getElementById("piPassOnNoUser").addEventListener("change", function ()
    {
        let checked = this.checked;
        setValue("piPassOnNoUser", checked ? "1" : "0");
    });*/
});