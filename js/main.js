function piFormTemplate()
{
    if (piGetValue("webAuthnSignRequest") === "")
    {
        piDisableElement("webAuthnButton");
    }
    if (piGetValue("isPushAvailable") !== "1")
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
        piDisableElement("otpSection");
        piDisableElement("pushButton");
        piEnableElement("otpButton");
    }
    if (piGetValue("passkeyRegistration").length > 0)
    {
        piDisableElement("alternateLoginOptions");
        piDisableElement("otpSection");
    }
    if (piGetValue("isPushAvailable") !== "1"
        && piGetValue("webAuthnSignRequest").length < 1
        && piGetValue("passkeyChallenge").length < 1
        || piGetValue("isEnrollViaMultichallenge") === "1")
    {
        piDisableElement("alternateLoginOptions");
    }
    if (piGetValue("mode") === "webauthn")
    {
        piDisableElement("otpSection");
        piEnableElement("otpButton");
        processWebauthn();
    }
    if (piGetValue("isEnrollViaMultichallengeOptional") !== "1")
    {
        piDisableElement("cancelEnrollmentButton");
    }
    // Passkey authentication
    if (piGetValue("mode") === "passkey")
    {
        piPasskeyAuthentication();
    }
    // Passkey registration
    if (piGetValue("passkeyRegistration").length > 0)
    {
        piRegisterPasskey().catch(function (error)
        {
            piSetValue("errorMessage", "Error during passkey registration: " + error.message);
        });
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
        if (!window.piWebauthn)
        {
            window.alert("Could not load WebAuthn library. Please try again or use other token!");
            piChangeMode("otp");
        }
    }
}

function processWebauthn()
{
    ensureSecureContextAndMode();

    if (!piGetValue("webAuthnSignRequest"))
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
    piSetValue("origin", window.origin);

    try
    {
        const requestJson = JSON.parse(piGetValue("webAuthnSignRequest"));
        const webAuthnSignResponse = piWebauthn.sign(requestJson);
        webAuthnSignResponse.then(function (credentials)
        {
            const response = JSON.stringify(credentials);
            piSetValue("webAuthnSignResponse", response);
            piSetValue("mode", "webauthn");
            document.forms["piLoginForm"].submit();
        }).catch(function (error)
        {
            console.log("Error while signing WebAuthnSignRequest: ", error);
            piChangeMode("otp");
        });
    }
    catch (error)
    {
        console.log("Error while signing WebAuthnSignRequest: " + error);
        piChangeMode("otp");
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    piFormTemplate();
});