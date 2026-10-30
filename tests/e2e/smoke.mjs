// Browser smoke test for the privacyIDEA Nextcloud app, used by run.sh.
// It drives headless Chrome over the DevTools protocol, so it needs no npm
// packages. Node 22 or newer is required for the built-in WebSocket.
//
//   node smoke.mjs <nextcloud-url> <expected-piURL>
//
// The Nextcloud must have the user admin/admin, and the app must be enabled and
// point to mock_privacyidea.py, which accepts only the OTP 123456.
import {execFileSync, spawn} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const [baseUrl, expectedPiUrl] = process.argv.slice(2);
if (!baseUrl || !expectedPiUrl)
{
    console.error('usage: node smoke.mjs <nextcloud-url> <expected-piURL>');
    process.exit(2);
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const failures = [];

function check(ok, message)
{
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${message}`);
    if (!ok)
    {
        failures.push(message);
        if (process.env.GITHUB_ACTIONS === 'true')
        {
            console.log(`::error title=Browser smoke test::${message}`);
        }
    }
    return ok;
}

function findChrome()
{
    if (process.env.CHROME_BIN)
    {
        return process.env.CHROME_BIN;
    }
    for (const name of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser'])
    {
        try
        {
            return execFileSync('which', [name]).toString().trim();
        }
        catch
        {
            // Not installed under this name, try the next one.
        }
    }
    throw new Error('Chrome or Chromium not found, set CHROME_BIN');
}

const profileDir = mkdtempSync(join(tmpdir(), 'pi-e2e-chrome-'));
const chromeArgs = ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profileDir}`,
    '--no-first-run', '--no-default-browser-check', '--disable-gpu', 'about:blank'];
// The Ubuntu runners of GitHub Actions block the user namespaces that the
// Chrome sandbox needs. The test only opens the local throwaway Nextcloud.
if (process.env.CI)
{
    chromeArgs.unshift('--no-sandbox');
}
// google-chrome is a wrapper script. A separate process group lets shutdown()
// stop the real browser processes too.
const chrome = spawn(findChrome(), chromeArgs, {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
let chromeStderr = '';
let chromeExitCode = null;
chrome.stderr.on('data', chunk =>
{
    chromeStderr = (chromeStderr + chunk).slice(-4000);
});
chrome.on('exit', code =>
{
    chromeExitCode = code;
});

async function shutdown(code)
{
    try
    {
        process.kill(-chrome.pid, 'SIGTERM');
    }
    catch
    {
        // The browser already exited.
    }
    // Chrome writes to its profile until all of its processes exit.
    for (let i = 0; i < 50; i++)
    {
        try
        {
            rmSync(profileDir, {recursive: true, force: true});
            break;
        }
        catch
        {
            await sleep(100);
        }
    }
    process.exit(code);
}

// With port 0, Chrome picks a free port and writes it to DevToolsActivePort.
// The first start on a fresh CI runner can take longer than 10 seconds.
const portFile = join(profileDir, 'DevToolsActivePort');
const readPort = () => (existsSync(portFile) ? readFileSync(portFile, 'utf8').split('\n')[0] : '');
let port = '';
for (let i = 0; i < 600 && !/^\d+$/.test(port) && chromeExitCode === null; i++)
{
    await sleep(100);
    port = readPort();
}
if (!/^\d+$/.test(port))
{
    const reason = chromeExitCode === null ? 'in 60 seconds' : `(exit code ${chromeExitCode})`;
    check(false, `Chrome did not start ${reason}`);
    console.error(chromeStderr);
    await shutdown(1);
}
const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const ws = new WebSocket(targets.find(target => target.type === 'page').webSocketDebuggerUrl);
await new Promise(resolve => ws.addEventListener('open', resolve));

let nextId = 0;
const pending = new Map();
const exceptions = [];
const consoleErrors = [];
ws.addEventListener('message', event =>
{
    const message = JSON.parse(event.data);
    if (message.id !== undefined)
    {
        const resolve = pending.get(message.id);
        pending.delete(message.id);
        if (typeof resolve === 'function')
        {
            resolve(message);
        }
    }
    else if (message.method === 'Runtime.exceptionThrown')
    {
        const details = message.params.exceptionDetails;
        const description = details.exception?.description || details.text;
        exceptions.push({text: description.split('\n')[0], source: `${details.url || ''}\n${description}`});
    }
    else if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error')
    {
        consoleErrors.push(`${message.params.entry.text} ${message.params.entry.url || ''}`);
    }
});

function send(method, params = {})
{
    return new Promise(resolve =>
    {
        const id = ++nextId;
        pending.set(id, resolve);
        ws.send(JSON.stringify({id, method, params}));
        // A call during a page load can stay unanswered. Treat that as no result.
        setTimeout(() =>
        {
            if (pending.delete(id))
            {
                resolve({});
            }
        }, 10000);
    });
}

async function evaluate(expression)
{
    const reply = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    if (!reply.result || reply.result.exceptionDetails)
    {
        return undefined;
    }
    return reply.result.result.value;
}

async function waitFor(expression, timeoutMs = 20000)
{
    const end = Date.now() + timeoutMs;
    while (Date.now() < end)
    {
        if (await evaluate(expression))
        {
            return true;
        }
        await sleep(250);
    }
    return false;
}

// Marks the current document, so that a wait can tell when a submit loaded a new one.
const markPage = () => evaluate('window.piE2EOldPage = true');
const newPageLoaded = 'window.piE2EOldPage !== true && document.readyState === "complete"';
const onChallengePage = `${newPageLoaded} && location.pathname.endsWith("/login/challenge/privacyidea")`
    + ' && !!document.getElementById("piLoginForm")';

async function submitOtp(otp)
{
    await markPage();
    await evaluate(`document.getElementById("otp").value = ${JSON.stringify(otp)};
        document.getElementById("piLoginForm").submit();`);
}

await send('Runtime.enable');
await send('Page.enable');
await send('Log.enable');

try
{
    await send('Page.navigate', {url: `${baseUrl}/login`});
    check(await waitFor('!!document.querySelector("input[name=user]") && !!document.querySelector("input[name=password]")', 30000),
        'login page shows the user and password fields');

    await markPage();
    // The login form is a Vue component: set the values through the native
    // setter and fire input events, so that Vue sees them.
    await evaluate(`(() => {
        const setValue = (field, value) => {
            Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(field, value);
            field.dispatchEvent(new Event('input', {bubbles: true}));
        };
        setValue(document.querySelector('input[name=user]'), 'admin');
        setValue(document.querySelector('input[name=password]'), 'admin');
        document.querySelector('form button[type=submit], form input[type=submit]').click();
    })()`);
    if (!check(await waitFor(onChallengePage), 'password login opens the privacyIDEA challenge page'))
    {
        throw new Error(`stopped at ${await evaluate('location.href')}`);
    }
    check(await evaluate('document.getElementById("otp")?.offsetParent !== null'), 'challenge page shows the OTP field');

    await submitOtp('000000');
    check(await waitFor(onChallengePage), 'wrong OTP returns to the challenge page');

    await submitOtp('123456');
    if (!check(await waitFor(`${newPageLoaded} && !location.pathname.includes("/login")`), 'correct OTP logs the user in'))
    {
        throw new Error(`stopped at ${await evaluate('location.href')}`);
    }

    await send('Page.navigate', {url: `${baseUrl}/settings/admin/privacyidea`});
    check(await waitFor(`document.getElementById("piURL")?.value === ${JSON.stringify(expectedPiUrl)}`),
        'admin settings page shows the stored server URL');
    check(await evaluate('document.getElementById("piActivatePI")?.checked === true'),
        'admin settings page shows privacyIDEA as active');

    await evaluate(`(() => {
        const realm = document.getElementById("piRealm");
        realm.value = "e2e-realm";
        realm.dispatchEvent(new Event("change"));
    })()`);
    check(await waitFor('document.getElementById("piSettingsMsg")?.textContent.includes("Saved")'),
        'admin settings page saves a changed value');
}
catch (error)
{
    check(false, `browser test aborted: ${error.message}`);
}

const appExceptions = exceptions.filter(exception => exception.source.includes('/privacyidea/'));
check(appExceptions.length === 0, 'no JavaScript exceptions from the app');
for (const exception of appExceptions)
{
    console.log(`     ${exception.text}`);
}
for (const exception of exceptions.filter(exception => !appExceptions.includes(exception)))
{
    console.log(`note: JavaScript exception outside the app: ${exception.text}`);
}
for (const error of consoleErrors)
{
    console.log(`note: browser console error: ${error}`);
}

ws.close();
await shutdown(failures.length ? 1 : 0);
