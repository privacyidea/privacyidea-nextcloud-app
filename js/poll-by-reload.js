function pollByReload()
{
    let mode = document.getElementById("mode").value;
    if (mode === "push")
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
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    pollByReload();
});