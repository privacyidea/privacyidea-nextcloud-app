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
        piDisableElement("pushButton");
        piEnableElement("otpButton");
    }
    if (piGetValue("pushAvailable") !== "1" && piGetValue("webAuthnSignRequest").length < 1)
    {
        console.log("Disabling alternate login options");
        piDisableElement("alternateLoginOptions");
    }
    if (piGetValue("mode") === "webauthn")
    {
        piDisableElement("otp");
        piDisableElement("submitButton");
        piEnableElement("otpButton");
        processWebauthn();
    }
}

function ensureSecureContextAndMode()
{
    // If mode is push, we have to change it, otherwise the site will refresh while processing webauthn
    if (piGetValue("mode") === "push")
    {
        piChangeMode("webauthn");
    }

    if (!window.isSecureContext)
    {
        window.alert("Unable to proceed with WebAuthn because the context is insecure!");
        console.log("Insecure context detected: Aborting WebAuthn authentication!");
        piChangeMode("otp");
    }

    if (piGetValue("mode") === "webauthn")
    {
        if (typeof piWebauthn === undefined)
        {
            window.alert("Could not load WebAuthn library. Please try again or use other token!");
            piChangeMode("otp");
        }
    }
}

function processWebauthn()
{
    ensureSecureContextAndMode();

    const requestStr = piGetValue("webAuthnSignRequest");
    if (!requestStr)
    {
        window.alert("Could not to process WebAuthn request. Please try again or use other token.");
        piChangeMode("otp");
        return;
    }

    // Set origin
    if (!window.location.origin)
    {
        window.location.origin = window.location.protocol + "//"
            + window.location.hostname
            + (window.location.port ? ':' + window.location.port : '');
    }
    piSetValue("origin", window.origin); // todo check if this is correct (window.location.origin)

    try
    {
        const requestJson = JSON.parse(requestStr);
        console.log("WebAuthn sign request in json: " + requestJson);
        const webAuthnSignResponse = piWebauthn.sign(requestJson);
        console.log("WebAuthn sign response: " + webAuthnSignResponse);
        webAuthnSignResponse.then(function (credentials)
        {
            const response = JSON.stringify(credentials);
            piSetValue("webAuthnSignResponse", response);
            piSetValue("mode", "webauthn");
            document.forms["piLoginForm"].submit();
        }).catch(function (error) {
            console.log("Error while signing WebAuthnSignRequest: ", error);
            window.alert("Error while signing WebAuthnSignRequest: " + error);
        });
    }
    catch (error)
    {
        console.log("Error while signing WebAuthnSignRequest: " + error);
        window.alert("Error while signing WebAuthnSignRequest: " + error);
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    piFormTemplate();
});