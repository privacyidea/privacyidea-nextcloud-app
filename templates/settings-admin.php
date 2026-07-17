<?php

use OCP\Util;

Util::addScript('privacyidea', 'settings-admin');
Util::addStyle('privacyidea', 'settings-admin');

?>

<div class="section" id="privacyIDEA">
    <div id="piTitle">
        <h2>privacyIDEA Authenticator <a target="_blank" rel="noreferrer" class="icon-info svg" title="Documentation"
                                         href="https://privacyidea.readthedocs.io"></a></h2>
    </div>

    <div id="piSettings">
        <h2>Configuration</h2>
        <span id="piSettingsMsg" class="msg"></span>
        <br>

        <h2>Activate multi-factor authentication with privacyIDEA</h2>
        <table>
            <tr>
                <td>
                    <input id="piActivatePI" type="checkbox" class="checkbox"/>
                    <label for="piActivatePI">Activate privacyIDEA</label>
                </td>
                <td>
                    <em>Before activating the MFA with privacyIDEA, please assure, that the connection to your
                        privacyIDEA server is configured correctly.</em>
                </td>
            </tr>
        </table>
        <br>
        <hr>

        <h2>Server config</h2>
        <table>
            <tr>
                <td>
                    <input id="piURL" type="text" width="300px"/>
                    <label for="piURL">URL of the privacyIDEA server</label>
                </td>
                <td>
                    <em>Provide the base URL of your privacyIDEA instance.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piSSLVerify" type="checkbox" class="checkbox" checked/>
                    <label for="piSSLVerify">SSL certificate verification</label>
                </td>
                <td>
                    <em>
                        Enable or disable SSL verification.
                        Note: Do not uncheck this in productive environments!
                    </em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piRealm" type="text" width="300px"/>
                    <label for="piRealm">Realm</label>
                </td>
                <td>
                    <em>Provide the realm of your privacyIDEA instance if its differ from default one.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piExcludeIPs" type="text" width="300px"/>
                    <label for="piExcludeIPs">Exclude IP addresses</label>
                </td>
                <td>
                    <em>You can either add single IPs like 10.0.1.12,10.0.1.13, a range like 10.0.1.12-10.0.1.113<br>
                        or combinations like 10.0.1.12-10.0.1.113,192.168.0.15</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piNoProxy" type="checkbox" class="checkbox">
                    <label for="piNoProxy">No proxy</label>
                </td>
                <td>
                    <em> Ignore the system-wide proxy settings and send the authentication requests directly to
                        privacyIDEA.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piForwardClientIP" type="checkbox" class="checkbox">
                    <label for="piForwardClientIP">Forward client IP</label>
                </td>
                <td>
                    <em> Send the "client" parameter to allow using the original IP address in the privacyIDEA
                        policies.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piTimeout" type="number" min="1" placeholder="Default is 5">
                    <label for="piTimeout">Timeout</label>
                </td>
                <td>
                    <em>Set a server connection timeout in seconds.</em>
                </td>
            </tr>
        </table>
        <hr>

        <h2>Include or exclude specific groups</h2>
        <em>Include or exclude given groups from the MFA.</em>
        <table>
            <tr>
                <td>
                    <input id="piIncludeGroups" type="radio" name="piInExGroups">
                    <label for="piIncludeGroups">Include groups</label>
                    <br>
                    <input id="piExcludeGroups" type="radio" name="piInExGroups">
                    <label for="piExcludeGroups">Exclude groups</label>
                    <input id="piInOrExSelected" type="hidden" name="piInOrExSelected" value=""/>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piInExGroupsField" type="text" width="300px"/>
                    <label for="piInExGroupsField">Group names</label>
                </td>
                <td>
                    <em>Select the group names.</em>
                </td>
            </tr>
        </table>
        <hr>

        <h2>Authentication flow</h2>
        <em>What is sent to privacyIDEA before the login screen is shown. Mutually exclusive;
            used to trigger the user's token challenges (or complete authentication) up front.</em>
        <table>
            <tr>
                <td>
                    <input id="piAuthFlowDefault" type="radio" name="piAuthenticationFlow" checked>
                    <label for="piAuthFlowDefault">None (prompt only)</label>
                    <input id="piSelectedAuthFlow" type="hidden" name="piSelectedAuthFlow" value=""/>
                </td>
                <td>
                    <em>(Default) Nothing is sent up front; the login screen is shown and whatever
                        the user submits is sent to privacyIDEA.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piAuthFlowTriggerChallenge" type="radio" name="piAuthenticationFlow">
                    <label for="piAuthFlowTriggerChallenge">Trigger Challenge</label>
                </td>
                <td>
                    <em>Triggers all of the user's challenges beforehand using the service account.
                        Requires the service name and password below.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piAuthFlowSendPassword" type="radio" name="piAuthenticationFlow">
                    <label for="piAuthFlowSendPassword">Send Password</label>
                </td>
                <td>
                    <em>Sends the user's Nextcloud login password to privacyIDEA beforehand (password
                        logins only; ignored for SSO/passkey logins).</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piAuthFlowSendStaticPass" type="radio" name="piAuthenticationFlow">
                    <label for="piAuthFlowSendStaticPass">Send Static Pass</label>
                </td>
                <td>
                    <em>Sends the configured static password to privacyIDEA beforehand. Requires the
                        static password below.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piServiceName" type="text" width="300px" autocomplete="off"/>
                    <label for="piServiceName">Service name</label>
                </td>
                <td>
                    <em>Provide the service account name for the trigger challenge flow.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piServicePass" type="text" width="300px" autocomplete="off" class="pi-secret"/>
                    <label for="piServicePass">Service password</label>
                </td>
                <td>
                    <em>Provide the service account password for the trigger challenge flow.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piServiceRealm" type="text" width="300px"/>
                    <label for="piServiceRealm">Service realm</label>
                </td>
                <td>
                    <em>Provide the service account realm (optional).</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piStaticPass" type="text" width="300px" autocomplete="off" class="pi-secret"/>
                    <label for="piStaticPass">Static password</label>
                </td>
                <td>
                    <em>Provide the static password for the send static pass flow.</em>
                </td>
            </tr>
        </table>
        <hr>

        <h2>Poll in browser</h2>
        <table>
            <tr>
                <td>
                    <input id="piPollInBrowser" type="checkbox" class="checkbox"/>
                    <label for="piPollInBrowser">Activate poll in browser</label>
                </td>
                <td>
                    <em>Process polling for a push token request's confirmation directly in your browser.<br>
                        The user's browser must be able to reach the privacyIDEA server directly for this feature to work.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piPollInBrowserURL" type="text" width="300px"/>
                    <label for="piPollInBrowserURL">URL for poll in browser</label>
                </td>
                <td>
                    <em>The privacyIDEA URL the browser polls (must be reachable from the browser).</em>
                </td>
            </tr>
        </table>
        <hr>

        <h2>Auto-submit by OTP length</h2>
        <table>
            <tr>
                <td>
                    <input id="piActivateAutoSubmitOtpLength" type="checkbox" class="checkbox">
                    <label for="piActivateAutoSubmitOtpLength">Activate auto-submit function</label>
                </td>
                <td>
                    <em>Submit the form automatically after x number of characters
                        are entered into the OTP input field.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piAutoSubmitOtpLength" type="number" min="1" size="20" placeholder="Default is 6"/>
                    <label for="piAutoSubmitOtpLength">OTP length</label>
                </td>
                <td>
                    <em>Set the expected OTP length.</em>
                </td>
            </tr>
        </table>
        <hr>

        <h2>Login screen</h2>
        <table>
            <tr>
                <td>
                    <input id="piOTPFieldHint" type="text" width="300px" placeholder="One-Time-Password"/>
                    <label for="piOTPFieldHint">OTP field hint</label>
                </td>
                <td>
                    <em>Placeholder shown in the one-time-password input field (default "One-Time-Password").</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piPassFieldHint" type="text" width="300px" placeholder="Password/PIN"/>
                    <label for="piPassFieldHint">Password/PIN field hint</label>
                </td>
                <td>
                    <em>Placeholder shown in the password/PIN input field of the "Password/PIN and OTP" layout (default "Password/PIN").</em>
                </td>
            </tr>
            <tr>
                <td>
                    <input id="piLayoutOtpOnly" type="radio" name="piInputLayoutRadio" checked>
                    <label for="piLayoutOtpOnly">OTP only</label>
                    <br>
                    <input id="piLayoutSeparate" type="radio" name="piInputLayoutRadio">
                    <label for="piLayoutSeparate">Password/PIN and OTP</label>
                    <input id="piInputLayout" type="hidden" name="piInputLayout" value=""/>
                </td>
                <td>
                    <em>Login-screen input layout: a single OTP field, or a separate password/PIN field
                        plus an OTP field (combined and sent to privacyIDEA).</em>
                </td>
            </tr>
        </table>
        <hr>

        <h2>Forward headers to privacyIDEA</h2>
        <table>
            <tr>
                <td>
                    <input id="piForwardHeaders" type="text" width="300px"/>
                    <label for="piForwardHeaders">Headers to forward</label>
                </td>
                <td>
                    <em>Comma-separated list of headers to forward, e.g.
                    <code>X-Forwarded-For</code>. Only headers present on the
                    request are sent.</em>
                </td>
            </tr>
        </table>
    </div>
</div>