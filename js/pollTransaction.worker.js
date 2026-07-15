let url;
let params;

self.addEventListener('message', function (e)
{
    let data = e.data;

    switch (data.cmd)
    {
        case 'url':
            url = data.msg + "/validate/polltransaction";
            break;
        case 'transactionID':
            params = "transaction_id=" + data.msg;
            break;
        case 'start':
            if (url.length > 0 && params.length > 0)
            {
                setInterval(function ()
                {
                    fetch(url + "?" + params, {method: 'GET'})
                        .then(r =>
                        {
                            if (r.ok)
                            {
                                // Return the promise so any rejection reaches the
                                // outer .catch, and guard parsing/access so a
                                // non-JSON or unexpected body surfaces an error
                                // instead of hanging the poll silently.
                                return r.text().then(result =>
                                {
                                    let resultJson;
                                    try
                                    {
                                        resultJson = JSON.parse(result);
                                    }
                                    catch (parseError)
                                    {
                                        self.postMessage({'message': 'Poll in browser error: invalid server response', 'status': 'error'});
                                        self.close();
                                        return;
                                    }
                                    if (resultJson && resultJson.result && resultJson.result.authentication === "ACCEPT")
                                    {
                                        self.postMessage({
                                            'message': 'Polling in browser: Push message confirmed!',
                                            'status': 'success'
                                        });
                                        self.close();
                                    }
                                });
                            }
                            else
                            {
                                self.postMessage({'message': r.statusText, 'status': 'error'});
                                self.close();
                            }
                        })
                        .catch(e =>
                            {
                                self.postMessage({'message': e, 'status': 'error'});
                                self.close();
                            }
                        );
                }, 300);
            }
            break;
    }
});