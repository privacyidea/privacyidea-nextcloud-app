window.onload = function ()
{
    if (piGetValue("autoSubmit"))
    {
        document.forms["piLoginForm"].submit();
    }
};