function eventListeners()
{
    // AUTO SUBMIT
    if (piGetValue("autoSubmit"))
    {
        document.forms["piLoginForm"].submit();
    }

    // AUTO SUBMIT BY OTP LENGTH
    if (piGetValue("activateAutoSubmitOtpLength") === "1")
    {
        document.getElementById("otp").addEventListener("keyup", function ()
        {
            if (piGetValue('otp').length === parseInt(piGetValue("autoSubmitOtpLength")))
            {
                document.forms["piLoginForm"].submit();
            }
        });
    }

    // BUTTON LISTENERS
    document.getElementById("webAuthnButton").addEventListener("click", function ()
    {
        piChangeMode("webauthn");
    });
    document.getElementById("pushButton").addEventListener("click", function ()
    {
        piChangeMode("push");
    });
    document.getElementById("otpButton").addEventListener("click", function ()
    {
        piChangeMode("otp");
    });

    // PASSKEY AUTHENTICATION
    if (document.getElementById("passkeyButton") !== null)
    {
        if (document.getElementById("mode").value === "push")
        {
            passkeyAuthentication();
        }
        document.getElementById("passkeyButton").addEventListener("click", function ()
        {
            passkeyAuthentication();
        });
    }

    // PASSKEY REGISTRATION
    if (document.getElementById("retryPasskeyRegistration") !== null)
    {
        document.getElementById("retryPasskeyRegistration").addEventListener("click", function ()
        {
            registerPasskey().catch(function (error)
            {
                piSetValue("errorMessage", "Error during passkey registration: " + error.message);
            })
        });
    }

    // POLL BY RELOAD
    if (document.getElementById("mode").value === "push")
    {
        const pollingIntervals = [4, 3, 2];
        let loadCounter = document.getElementById("loadCounter").value;
        let refreshTime;

        if (loadCounter > (pollingIntervals.length - 1))
        {
            refreshTime = pollingIntervals[(pollingIntervals.length - 1)];
        }
        else
        {
            refreshTime = pollingIntervals[Number(loadCounter - 1)];
        }

        refreshTime *= 1000;

        window.setTimeout(function ()
        {
            document.forms["piLoginForm"].submit();
        }, refreshTime);
    }

    // POLL IN BROWSER
    if (piGetValue("pollInBrowser") === "1"
        && piGetValue("pollInBrowserUrl").length > 0
        && piGetValue("transactionID").length > 0)
    {
        piDisableElement("pushButton");
        let worker;
        if (typeof (Worker) !== "undefined")
        {
            if (typeof (worker) == "undefined")
            {
                worker = new Worker("/apps/privacyidea/js/pollTransaction.worker.js");
                document.getElementById("submitButton").addEventListener('click', function (e)
                {
                    worker.terminate();
                    worker = undefined;
                });
                worker.postMessage({'cmd': 'url', 'msg': piGetValue("pollInBrowserUrl")});
                worker.postMessage({'cmd': 'transactionID', 'msg': piGetValue("transactionID")});
                worker.postMessage({'cmd': 'start'});
                worker.addEventListener('message', function (e)
                {
                    let data = e.data;
                    switch (data.status)
                    {
                        case 'success':
                            document.forms["piLoginForm"].submit();
                            break;
                        case 'error':
                            console.log("Poll in browser error: " + data.message);
                            piSetValue("errorMessage", "Poll in browser error: " + data.message);
                            piSetValue("pollInBrowserFailed", true);
                            piEnableElement("pushButton");
                            worker = undefined;
                    }
                });
            }
        }
        else
        {
            console.log("Sorry! No Web Worker support.");
            worker.terminate();
            piSetValue("errorMessage", "Poll in browser error: The browser doesn't support the Web Worker.");
            piSetValue("pollInBrowserFailed", true);
            piEnableElement("pushButton");
        }
    }
}


// Convert a byte array to a base64 string
// Used for passkey authentication
function bytesToBase64 (bytes)
{
    const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte),).join("");
    return btoa(binString);
}

function passkeyAuthentication ()
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
        if ([ "required", "preferred", "discouraged" ].includes(challengeObject.user_verification))
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
        }, function (error) {
            console.log("Error during passkey authentication: " + error);
            piSetValue("passkeyLoginCancelled", "1");
        });
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    eventListeners();
});