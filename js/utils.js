window.piGetValue = function getValue(id) {
    const element = document.getElementById(id);
    if (element === null)
    {
        console.log(id + " is null!");
        return "";
    }
    return element.value;
}

window.piSetValue = function setValue(id, value)
{
    const element = document.getElementById(id);
    if (element !== null)
    {
        element.value = value;
    }
    else
    {
        console.log(id + " is null!");
    }
}

window.piDisableElement = function disableElement(id)
{
    const element = document.getElementById(id);
    if (element !== null)
    {
        element.style.display = "none";
    }
    else
    {
        console.log(id + " is null!");
    }
}

window.piEnableElement = function enableElement(id)
{
    const element = document.getElementById(id);
    if (element !== null)
    {
        element.style.display = "initial";
    }
    else
    {
        console.log(id + " is null!");
    }
}

window.piChangeMode = function changeMode(newMode)
{
    document.getElementById("mode").value = newMode;
    document.getElementById("modeChanged").value = "1";
    document.forms["piLoginForm"].submit();
}

// Convert a byte array to a base64 string
// Used for passkey authentication
function bytesToBase64(bytes)
{
    const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte),).join("");
    return btoa(binString);
}

// Convert a base64url string to a byte array
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

window.piRegisterPasskey = function registerPasskey ()
{
    let data = JSON.parse(piGetValue("passkeyRegistration").replace(/(&quot;)/g, "\""));
    let excludedCredentials = [];
    if (data.excludeCredentials)
    {
        for (const cred of data.excludeCredentials)
        {
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
    }).then(function (publicKeyCred)
    {
        let params = {
            credential_id: publicKeyCred.id,
            rawId: bytesToBase64(new Uint8Array(publicKeyCred.rawId)),
            authenticatorAttachment: publicKeyCred.authenticatorAttachment,
            attestationObject: bytesToBase64(
                new Uint8Array(publicKeyCred.response.attestationObject)),
            clientDataJSON: bytesToBase64(new Uint8Array(publicKeyCred.response.clientDataJSON)),
        }
        if (publicKeyCred.response.attestationObject)
        {
            params.attestationObject = bytesToBase64(
                new Uint8Array(publicKeyCred.response.attestationObject));
        }
        const extResults = publicKeyCred.getClientExtensionResults();
        if (extResults.credProps)
        {
            params.credProps = extResults.credProps;
        }
        piSetValue("passkeyRegistrationResponse", JSON.stringify(params));
        piSetValue("origin", window.origin);
        document.forms["piLoginForm"].submit();
    }, function (error)
    {
        console.log("Error while registering passkey:");
        console.log(error);
        return null;
    });
}

window.piPasskeyAuthentication = function passkeyAuthentication()
{
    if (piGetValue("mode") === "push")
    {
        piChangeMode("passkey");
    }
    let passkeyChallenge = piGetValue("passkeyChallenge");
    if (!passkeyChallenge)
    {
        console.log("Passkey Authentication: Challenge data is empty!");
    }
    else
    {
        piSetValue("passkeyLoginCancelled", "0");
        let challengeObject = JSON.parse(passkeyChallenge.replace(/(&quot;)/g, "\""));
        let userVerification = "preferred";
        if (["required", "preferred", "discouraged"].includes(challengeObject.user_verification))
        {
            userVerification = challengeObject.user_verification;
        }
        navigator.credentials.get({
            publicKey: {
                challenge: Uint8Array.from(challengeObject.challenge, c => c.charCodeAt(0)),
                rpId: challengeObject.rpId, userVerification: userVerification,
            },
        }).then(credential => {
            let params = {
                transaction_id: challengeObject.transaction_id, credential_id: credential.id,
                authenticatorData: bytesToBase64(new Uint8Array(credential.response.authenticatorData)),
                clientDataJSON: bytesToBase64(new Uint8Array(credential.response.clientDataJSON)),
                signature: bytesToBase64(new Uint8Array(credential.response.signature)),
                userHandle: bytesToBase64(new Uint8Array(credential.response.userHandle)),
            };
            piSetValue("passkeySignResponse", JSON.stringify(params));
            piSetValue("origin", window.origin);
            document.forms["piLoginForm"].submit();
        }, function (error)
        {
            console.log("Error during passkey authentication: " + error);
            piSetValue("passkeyLoginCancelled", "1");
            document.forms["piLoginForm"].submit();
        });
    }
}