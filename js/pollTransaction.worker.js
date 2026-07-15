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
                // Wait before the first poll: the user needs a moment to confirm
                // on their phone, so immediate polls are wasted. After that, poll
                // on a self-scheduling timer (never below 500ms and never
                // overlapping, since the next poll is only queued once the
                // previous response is handled) so the page reacts quickly on
                // confirmation without flooding the server.
                const initialDelayMs = 3000;
                const pollIntervalMs = 500;

                const poll = function ()
                {
                    fetch(url + "?" + params, {method: 'GET'})
                        .then(r =>
                        {
                            if (!r.ok)
                            {
                                self.postMessage({'message': r.statusText, 'status': 'error'});
                                self.close();
                                return;
                            }
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
                                const authentication = resultJson && resultJson.result
                                    ? resultJson.result.authentication : undefined;
                                if (authentication === undefined)
                                {
                                    // Valid JSON but not the expected shape: stop
                                    // rather than poll forever against a broken endpoint.
                                    self.postMessage({'message': 'Poll in browser error: unexpected server response', 'status': 'error'});
                                    self.close();
                                    return;
                                }
                                if (authentication === "ACCEPT")
                                {
                                    self.postMessage({
                                        'message': 'Polling in browser: Push message confirmed!',
                                        'status': 'success'
                                    });
                                    self.close();
                                    return;
                                }
                                // Still pending: queue the next poll.
                                setTimeout(poll, pollIntervalMs);
                            });
                        })
                        .catch(e =>
                            {
                                self.postMessage({'message': e, 'status': 'error'});
                                self.close();
                            }
                        );
                };
                setTimeout(poll, initialDelayMs);
            }
            break;
    }
});