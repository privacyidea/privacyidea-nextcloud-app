function piFormTemplate()
{
    // Cache values to avoid repeated DOM lookups
    const webAuthnSignRequest = piGetValue("webAuthnSignRequest");
    const isPushAvailable = piGetValue("isPushAvailable");
    const otpAvailable = piGetValue("otpAvailable");
    const mode = piGetValue("mode");
    const passkeyRegistration = piGetValue("passkeyRegistration");
    const passkeyChallenge = piGetValue("passkeyChallenge");
    const isEnrollViaMultichallenge = piGetValue("isEnrollViaMultichallenge");
    const isEnrollViaMultichallengeOptional = piGetValue("isEnrollViaMultichallengeOptional");

    if (webAuthnSignRequest === "") piDisableElement("webAuthnButton");
    if (isPushAvailable !== "1") piDisableElement("pushButton");

    if (mode === "push")
    {
        piDisableElement("otpSection");
        piDisableElement("pushButton");
    }

    if (passkeyRegistration.length > 0)
    {
        piDisableElement("alternateLoginOptions");
        piDisableElement("otpSection");
    }

    if (isPushAvailable !== "1" &&
        webAuthnSignRequest.length < 1 &&
        passkeyChallenge.length < 1 ||
        isEnrollViaMultichallenge === "1")
    {
        piDisableElement("alternateLoginOptions");
    }

    // WebAuthn and passkey only fire navigator.credentials.get in the
    // background, so the OTP/PIN inputs stay visible as the fallback (no
    // separate UI needed, unlike push).
    if (mode === "webauthn")
    {
        piAfterPaint(processWebauthn);
    }

    if (isEnrollViaMultichallengeOptional !== "1") piDisableElement("cancelEnrollmentButton");

    // Passkey authentication
    if (mode === "passkey")
    {
        piAfterPaint(piPasskeyAuthentication);
    }

    // Passkey registration
    if (passkeyRegistration.length > 0)
    {
        piRegisterPasskey().catch(function (error)
        {
            piSetValue("errorMessage", "Error during passkey registration: " + error.message);
        });
    }

    // The OTP button only reveals the OTP/PIN inputs, so it is meaningful only
    // when those inputs are hidden (push) and OTP is actually available.
    // Enforcing this once, after the mode branches have set the input
    // visibility, keeps the button and the inputs mutually exclusive in every
    // mode - including the form re-render after a cancelled passkey prompt.
    const otpSection = document.getElementById("otpSection");
    const otpInputsHidden = !otpSection || otpSection.style.display === "none";
    if (otpAvailable === "1" && otpInputsHidden)
    {
        piEnableElement("otpButton");
    }
    else
    {
        piDisableElement("otpButton");
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
