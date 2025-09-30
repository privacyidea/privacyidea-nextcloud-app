function eventListeners()
{
    // AUTO SUBMIT
    if (piGetValue("autoSubmit"))
    {
        document.forms["piLoginForm"].submit();
        return;
    }

    // AUTO SUBMIT BY OTP LENGTH
    if (piGetValue("activateAutoSubmitOtpLength") === "1")
    {
        const otpInput = document.getElementById("otp");
        otpInput && otpInput.addEventListener("keyup", function ()
        {
            if (piGetValue('otp').length === parseInt(piGetValue("autoSubmitOtpLength")))
            {
                document.forms["piLoginForm"].submit();
            }
        });
    }

    // BUTTON LISTENERS
    [
        ["webAuthnButton", () => piChangeMode("webauthn")],
        ["pushButton", () => piChangeMode("push")],
        ["otpButton", () => piChangeMode("otp")],
        ["cancelEnrollmentButton", () => {
            piSetValue("enrollmentCancelled", "1");
            document.forms["piLoginForm"].submit();
        }]
    ].forEach(([id, handler]) => {
        const el = document.getElementById(id);
        el && el.addEventListener("click", handler);
    });

    // PASSKEY AUTHENTICATION
    const passkeyBtn = document.getElementById("passkeyButton");
    if (passkeyBtn)
    {
        passkeyBtn.addEventListener("click", function ()
        {
            piDisableElement("otpSection");
            piEnableElement("otpButton");
            piPasskeyAuthentication();
        });
    }

    // PASSKEY REGISTRATION
    const retryPasskeyBtn = document.getElementById("retryPasskeyRegistration");
    if (retryPasskeyBtn)
    {
        retryPasskeyBtn.addEventListener("click", function ()
        {
            piRegisterPasskey().catch(function (error)
            {
                piSetValue("errorMessage", "Error during passkey registration: " + error.message);
            });
        });
    }

    // POLL BY RELOAD
    if (piGetValue("mode") === "push" && piGetValue("pollInBrowser") !== "1")
    {
        const pollingIntervals = [8, 5, 4];
        let loadCounter = Number(document.getElementById("loadCounter").value) || 1;
        let refreshTime = pollingIntervals[Math.min(loadCounter - 1, pollingIntervals.length - 1)] * 1000;
        window.setTimeout(() => document.forms["piLoginForm"].submit(), refreshTime);
    }

    // POLL IN BROWSER
    if (piGetValue("pollInBrowser") === "1" &&
        piGetValue("pollInBrowserUrl").length > 0 &&
        piGetValue("transactionID").length > 0)
    {
        piDisableElement("pushButton");
        let worker;
        if (typeof Worker !== "undefined")
        {
            if (!worker)
            {
                worker = new Worker("/apps/privacyidea/js/pollTransaction.worker.js");
                document.getElementById("submitButton").addEventListener('click', function ()
                {
                    worker.terminate();
                    worker = undefined;
                });
                worker.postMessage({ 'cmd': 'url', 'msg': piGetValue("pollInBrowserUrl") });
                worker.postMessage({ 'cmd': 'transactionID', 'msg': piGetValue("transactionID") });
                worker.postMessage({ 'cmd': 'start' });
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
            piSetValue("errorMessage", "Poll in browser error: The browser doesn't support the Web Worker.");
            piSetValue("pollInBrowserFailed", true);
            piEnableElement("pushButton");
        }
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", eventListeners);
