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

    <span id="piSettingsMsg" class="msg"></span>

    <div id="piSettings">
        <h2>Configuration</h2>
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
                        privacyIDEA server is configured correctly</em>
                </td>
            </tr>
        </table>
        <br>
        <hr>

        <h2>Server config</h2>
        <table>
            <tr>
                <td>
                    <label for="piURL">URL of the privacyIDEA server: </label>
                    <input id="piURL" type="text" width="300px"/>
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
                    <label for="piRealm">Realm: </label>
                    <input id="piRealm" type="text" width="300px"/>
                </td>
                <td>
                    <em>Provide the realm of your privacyIDEA instance if its differ from default one.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <label for="piExcludeIPs">Exclude IP addresses: </label>
                    <input id="piExcludeIPs" type="text" width="300px"/>
                </td>
                <td>
                    <em>You can either add single IPs like 10.0.1.12,10.0.1.13, a range like 10.0.1.12-10.0.1.113
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
                    <em> Send the "client" parameter to allow using the original IP address in the privacyIDEA policies.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <label for="piTimeout">Timeout: </label>
                    <input id="piTimeout" type="number" min="1" placeholder="Default is 5">
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
                    <label for="piInExGroupsField">Group names: </label>
                    <input id="piInExGroupsField" type="text" width="300px"/>
                </td>
                <td>
                    <em>Select the group names.</em>
                </td>
            </tr>
        </table>
        <hr>

        <h2>Authentication flow</h2>
        <em>Choose one of the following authentication flows:
            "Send Password" - (default) Login interface contains an username input and an single password/OTP input.
            "Trigger Challenge" - triggers all challenges beforehand using the provided service account.
            This flow require additional parameters: 'service name','service pass' (see below).
            "Separate OTP" - Login interface will contain separate Pass an OTP inputs.
            "Send static pass" - performs the privacyIDEA server request automatically beforehand using
            the provided static password. This flow require additional parameter: 'static pass' (see below).</em>
        <br>
        <table>
            <tr>
                <td>
                    <input id="piAuthFlowDefault" type="radio" name="piAuthenticationFlow" checked>
                    <label for="piAuthFlowDefault">Send Password</label>
                    <br>
                    <input id="piAuthFlowTriggerChallenge" type="radio" name="piAuthenticationFlow">
                    <label for="piAuthFlowTriggerChallenge">Trigger Challenge</label>
                    <br>
                    <input id="piAuthFlowSeparateOTP" type="radio" name="piAuthenticationFlow">
                    <label for="piAuthFlowSeparateOTP">Separate OTP</label>
                    <br>
                    <input id="piAuthFlowSendStaticPass" type="radio" name="piAuthenticationFlow">
                    <label for="piAuthFlowSendStaticPass">Send Static Pass</label>
                    <br>
                    <br>
                    <input id="piSelectedAuthFlow" type="hidden" name="piSelectedAuthFlow" value=""/>
                </td>
            </tr>
            <tr>
                <td>
                    <label for="piServiceName">Service name: </label>
                    <input id="piServiceName" type="text" width="300px"/>
                </td>
                <td>
                    <em>Provide the service account name for the trigger challenge flow.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <label for="piServicePass">Service password: </label>
                    <input id="piServicePass" type="password" width="300px"/>
                </td>
                <td>
                    <em>Provide the service account password for the trigger challenge flow.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <label for="piServiceRealm">Service realm: </label>
                    <input id="piServiceRealm" type="text" width="300px"/>
                </td>
                <td>
                    <em>Provide the service account realm (optional).</em>
                </td>
            </tr>
            <tr>
                <td>
                    <label for="piStaticPass">Static password: </label>
                    <input id="piStaticPass" type="password" width="300px"/>
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
                    <em>Process polling for a push token request's confirmation directly in your browser.</em>
                </td>
            </tr>
            <tr>
                <td>
                    <label for="piPollInBrowserURL">URL for poll in browser: </label>
                    <input id="piPollInBrowserURL" type="text" width="300px"/>
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
                    <label for="piAutoSubmitOtpLength">OTP length: </label>
                    <input id="piAutoSubmitOtpLength" type="number" min="1" size="20" placeholder="Default is 6"/>
                </td>
                <td>
                    <em>Set the expected OTP length.</em>
                </td>
            </tr>
        </table>

        <h2>Forward headers to privacyIDEA</h2>
        <table>
            <tr>
                <td>
                    <label for="piForwardHeaders">Headers to forward: </label>
                    <input id="piForwardHeaders" type="text" width="300px"/>
                </td>
                <td>
                    <em>Set headers which should be forwarded to privacyIDEA.</em>
                </td>
            </tr>
        </table>
    </div>
</div>