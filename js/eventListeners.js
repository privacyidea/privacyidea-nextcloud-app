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
            // Passkey just starts navigator.credentials.get; keep the OTP/PIN
            // inputs as the fallback and hide the redundant OTP switch button.
            piDisableElement("otpButton");
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
    const startPollByReload = function ()
    {
        const pollingIntervals = [8, 5, 4];
        let loadCounter = Number(document.getElementById("loadCounter").value) || 1;
        // Poll immediately on the first push render (e.g. right after switching
        // to the push option): the user may already have confirmed on their
        // phone, so waiting the full interval before the first check is a
        // needless delay. Later reloads back off on the interval schedule.
        let refreshTime = loadCounter <= 1
            ? 0
            : pollingIntervals[Math.min(loadCounter - 2, pollingIntervals.length - 1)] * 1000;
        window.setTimeout(() => document.forms["piLoginForm"].submit(), refreshTime);
    };
    if (piGetValue("mode") === "push" && piGetValue("pollInBrowser") !== "1")
    {
        startPollByReload();
    }

    // POLL IN BROWSER
    if (piGetValue("pollInBrowser") === "1" &&
        piGetValue("pollInBrowserUrl").length > 0 &&
        piGetValue("transactionID").length > 0)
    {
        piDisableElement("pushButton");
        // If the browser cannot poll, show the error and give the push button
        // back. On the push page, also poll by reload, so that the login still
        // completes when the user confirms the push. Other pages keep their
        // input field and do not reload.
        const pollInBrowserFailed = function (message)
        {
            console.log("Poll in browser error: " + message);
            piSetValue("errorMessage", "Poll in browser error: " + message);
            piSetValue("pollInBrowserFailed", true);
            piEnableElement("pushButton");
            if (piGetValue("mode") === "push")
            {
                startPollByReload();
            }
        };
        let worker;
        if (typeof Worker !== "undefined")
        {
            if (!worker)
            {
                worker = new Worker(piGetValue("pollInBrowserWorkerUrl"));
                document.getElementById("submitButton").addEventListener('click', function ()
                {
                    if (worker)
                    {
                        worker.terminate();
                        worker = undefined;
                    }
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
                            worker = undefined;
                            pollInBrowserFailed(data.message);
                    }
                });
                // A worker script that does not load (for example from a wrong
                // URL) fires an error event and never sends a message.
                worker.addEventListener('error', function ()
                {
                    worker = undefined;
                    pollInBrowserFailed("The poll worker could not start.");
                });
            }
        }
        else
        {
            pollInBrowserFailed("The browser doesn't support the Web Worker.");
        }
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", eventListeners);
