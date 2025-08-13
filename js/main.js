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
        piDisableElement("otpSection");
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
    // Passkey registration
    if (piGetValue("passkeyRegistration").length > 0)
    {
        registerPasskey().catch(function (error)
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
        console.log("WebAuthn sign request in json: " + requestJson);
        const webAuthnSignResponse = piWebauthn.sign(requestJson);
        console.log("WebAuthn sign response: " + webAuthnSignResponse);
        webAuthnSignResponse.then(function (credentials)
        {
            const response = JSON.stringify(credentials);
            piSetValue("webAuthnSignResponse", response);
            piSetValue("mode", "webauthn");
            document.forms["piLoginForm"].submit();
        }).catch(function (error)
        {
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

// Convert a byte array to a base64 string
// Used for passkey registration
function base64URLToBytes (base64URLString)
{
    const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLength, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++)
    {
        bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
}

function registerPasskey ()
{
    let data = JSON.parse(piGetValue("passkeyRegistration").replace(/(&quot;)/g, "\""));
    let excludedCredentials = [];
    if (data.excludeCredentials) {
        for (const cred of data.excludeCredentials) {
            excludedCredentials.push({
                id: base64URLToBytes(cred.id),
                type: cred.type,
            });
        }
    }
    return navigator.credentials.create({
        publicKey: {
            rp: data.rp,
            user: {
                id: base64URLToBytes(data.user.id),
                name: data.user.name,
                displayName: data.user.displayName
            },
            challenge: Uint8Array.from(data.challenge, c => c.charCodeAt(0)),
            pubKeyCredParams: data.pubKeyCredParams,
            excludeCredentials: excludedCredentials,
            authenticatorSelection: data.authenticatorSelection,
            timeout: data.timeout,
            extensions: {
                credProps: true,
            },
            attestation: data.attestation
        }
    }).then(function (publicKeyCred) {
        let params = {
            credential_id: publicKeyCred.id,
            rawId: bytesToBase64(new Uint8Array(publicKeyCred.rawId)),
            authenticatorAttachment: publicKeyCred.authenticatorAttachment,
            attestationObject: bytesToBase64(
                new Uint8Array(publicKeyCred.response.attestationObject)),
            clientDataJSON: bytesToBase64(new Uint8Array(publicKeyCred.response.clientDataJSON)),
        }
        if (publicKeyCred.response.attestationObject) {
            params.attestationObject = bytesToBase64(
                new Uint8Array(publicKeyCred.response.attestationObject));
        }
        const extResults = publicKeyCred.getClientExtensionResults();
        if (extResults.credProps) {
            params.credProps = extResults.credProps;
        }
        piSetValue("passkeyRegistrationResponse", JSON.stringify(params));
        piSetValue("origin", window.origin);
        document.forms["piLoginForm"].submit();
    }, function (error) {
        console.log("Error while registering passkey:");
        console.log(error);
        return null;
    });
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    piFormTemplate();
});