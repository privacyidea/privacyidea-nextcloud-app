window.piGetValue = function getValue(id)
{
    const element = document.getElementById(id);
    if (element === null)
    {
        console.log(id + " is null!");
        return "";
    }
    else
    {
        return element.value;
    }
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
        }).then(credential =>
        {
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