function piFormTemplate()
{
    if (piGetValue("webAuthnSignRequest") === "")
    {
        piDisableElement("webAuthnButton");
    }
    if (piGetValue("pushAvailable") !== "1")
    {
        piDisableElement("pushButton");
    }
    if (piGetValue("otpAvailable") !== "1")
    {
        piDisableElement("otpButton");
    }
    if (piGetValue("mode") === "otp" || piGetValue("mode").length < 1)
    {
        piDisableElement("otpButton");
    }
    if (piGetValue("mode") === "push")
    {
        piDisableElement("otp");
        piDisableElement("submitButton");
        if (piGetValue("mode") === "push")
        {
            piDisableElement("pushButton");
        }
        piEnableElement("otpButton");
    }
    if (piGetValue("mode") === "webauthn")
    {
        piDisableElement("otp");
        piDisableElement("submitButton");
        doWebAuthn();
    }
    if (piGetValue("pushAvailable") !== "1" && piGetValue("webAuthnSignRequest").length < 1)
    {
        console.log("Disabling alternate login options");
        piDisableElement("alternateLoginOptions");
    }
}

/**
 * @param mode
 */
function ensureSecureContextAndMode(mode)
{
    // If mode is push, we have to change it, otherwise the site will refresh while doing webauthn
    if (piGetValue("mode") === "push")
    {
        piChangeMode(mode);
    }

    if (!window.isSecureContext)
    {
        window.alert("Unable to proceed with WebAuthn because the context is insecure!");
        console.log("Insecure context detected: Aborting WebAuthn authentication!");
        piChangeMode("otp");
    }

    if (mode === "webauthn")
    {
        if (!window.piWebAuthn)
        {
            window.alert("Could not load WebAuthn library. Please try again or use other token!");
            piChangeMode("otp");
        }
    }
}

function doWebAuthn()
{
    ensureSecureContextAndMode("webauthn");

    const requestStr = piGetValue("webAuthnSignRequest");
    if (requestStr === null)
    {
        window.alert("Could not to process WebAuthn request. Please try again or use other token.");
        piChangeMode("otp");
    }

    // Set origin
    if (!window.location.origin)
    {
        window.location.origin = window.location.protocol + "//"
            + window.location.hostname
            + (window.location.port ? ':' + window.location.port : '');
    }
    piSetValue("origin", window.origin);

    try
    {
        const requestjson = JSON.parse(requestStr);

        const webAuthnSignResponse = piWebAuthn.sign(requestjson);
        webAuthnSignResponse.then(function (webauthnresponse)
        {
            const response = JSON.stringify(webauthnresponse);
            piSetValue("webAuthnSignResponse", response);
            piSetValue("mode", "webauthn");
            document.forms["piLoginForm"].submit();
        });
    }
    catch (err)
    {
        console.log("Error while signing WebAuthnSignRequest: " + err);
        window.alert("Error while signing WebAuthnSignRequest: " + err);
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    piFormTemplate();
});