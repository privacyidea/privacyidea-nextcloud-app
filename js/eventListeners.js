function autoSubmitByLength()
{
    if (piGetValue('otp').length === parseInt(piGetValue("autoSubmitOtpLength")))
    {
        document.forms["piLoginForm"].submit();
    }
}

function eventListeners()
{
    if (piGetValue("activateAutoSubmitOtpLength") === "1")
    {
        document.getElementById("otp").addEventListener("keyup", autoSubmitByLength);
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
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    eventListeners();
});