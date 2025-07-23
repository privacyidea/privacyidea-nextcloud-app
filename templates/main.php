<?php
declare(strict_types=1);
use OCP\Util;

Util::addScript('privacyidea', 'utils');
Util::addScript('privacyidea', 'piWebAuthn');
Util::addScript('privacyidea', 'main');
Util::addScript('privacyidea', 'eventListeners');
Util::addScript('privacyidea', 'pollTransaction.worker');
Util::addStyle('privacyidea', 'main');
?>

<!-- MESSAGES -->
<?php if (!empty($_['message'])) : ?>
    <fieldset class="warning">
        <?php p($_['message']); ?>
    </fieldset>
    <br>
<?php endif; ?>

<!-- IMAGES & ENROLLMENT LINK -->
<?php if (!empty($_['imgWebauthn']) && $_['mode'] === 'webauthn') : ?>
    <img class="tokenImages" src="<?php p($_['imgWebauthn']); ?>" alt="WebAuthn image"><br><br>
<?php endif;
if (!empty($_['imgPush']) && $_['mode'] === 'push') : ?>
    <img class="tokenImages" src="<?php p($_['imgPush']); ?>" alt="Push image"><br><br>
<?php endif;
if (!empty($_['imgOTP']) && $_['mode'] === 'otp') : ?>
    <img class="tokenImages" id="imgOtp" src="<?php p($_['imgOTP']); ?>" alt="OTP image"><br><br>
<?php endif;?>
<?php if (!empty($_['enrollmentLink'])) : ?>
    <a id="enrollmentLink" href="<?php p($_['enrollmentLink']); ?>" target="_blank" rel="noopener noreferrer">Enrollment Link</a>
<?php endif;?>

<!-- FORM -->
<form method="POST" id="piLoginForm" name="piLoginForm">
    <?php if (!isset($_['hideOTPField']) || !$_['hideOTPField']) : ?>
    <?php if (isset($_['separateOTP']) && $_['separateOTP']) : ?>
        <label>
            <input id="passField" type="password" name="passField" placeholder="Password" autocomplete="off" required autofocus>
        </label>
        <?php endif; ?>
        <label>
            <input id="otp" type="password" name="challenge" placeholder="OTP" autocomplete="off" required autofocus>
        </label>
        <br>
        <input id="submitButton" type="submit" class="button" value="<?php if (isset($_['verify'])) : p($_['verify']); endif; ?>">
    <?php endif; ?>

    <!-- Hidden input that saves the changes -->
    <input id="modeChanged" type="hidden" name="modeChanged" value="0"/>
    <input id="activateAutoSubmitOtpLength" type="hidden" name="activateAutoSubmitOtpLength"
           value="<?php if (!empty($_['activateAutoSubmitOtpLength'])) : p($_['activateAutoSubmitOtpLength']); endif; ?>"/>
    <input id="autoSubmitOtpLength" type="hidden" name="autoSubmitOtpLength"
           value="<?php if (!empty($_['autoSubmitOtpLength'])) : p($_['autoSubmitOtpLength']); endif; ?>"/>
    <input id="webAuthnSignRequest" type="hidden" name="webAuthnSignRequest"
           value="<?php if (isset($_['webAuthnSignRequest'])) : p($_['webAuthnSignRequest']); endif; ?>"/>
    <input id="webAuthnSignResponse" type="hidden" name="webAuthnSignResponse" value=""/>
    <input id="origin" type="hidden" name="origin" value=""/>
    <input id="passkeyChallenge" type="hidden" name="passkeyChallenge"
           value="<?php if (isset($_['passkeyChallenge'])) : p($_['passkeyChallenge']); endif; ?>"/>
    <input id="passkeyRegistration" type="hidden" name="passkeyRegistration"
           value="<?php if (isset($_['passkeyRegistration'])) : p($_['passkeyRegistration']); endif; ?>"/>
    <input id="passkeyRegistrationResponse" type="hidden" name="passkeyRegistrationResponse" value=""/>
    <input id="passkeySignResponse" type="hidden" name="passkeySignResponse" value=""/>
    <input id="passkeyLoginRequested" type="hidden" name="passkeyLoginRequested" value="0"/>
    <input id="passkeyLoginCancelled" type="hidden" name="passkeyLoginCancelled" value="0"/>
    <input id="isEnrollViaMultichallenge" type="hidden" name="isEnrollViaMultichallenge"
           value="<?php if (isset($_['isEnrollViaMultichallenge'])) : p($_['isEnrollViaMultichallenge']); endif; ?>"/>
    <input id="pushAvailable" type="hidden" name="pushAvailable"
           value="<?php if (isset($_['pushAvailable'])) : p($_['pushAvailable']); endif; ?>"/>
    <input id="otpAvailable" type="hidden" name="otpAvailable"
           value="<?php if (isset($_['otpAvailable'])) : p($_['otpAvailable']); endif; ?>"/>
    <input id="loadCounter" type="hidden" name="loadCounter"
           value="<?php if (isset($_['loadCounter'])) : p($_['loadCounter']); endif; ?>"/>
    <input id="pollInBrowser" type="hidden" name="pollInBrowser"
           value="<?php if (isset($_['pollInBrowser'])) : p($_['pollInBrowser']); endif; ?>"/>
    <input id="pollInBrowserUrl" type="hidden" name="pollInBrowserUrl"
           value="<?php if (isset($_['pollInBrowserUrl'])) : p($_['pollInBrowserUrl']); endif; ?>"/>
    <input id="pollInBrowserFailed" type="hidden" name="pollInBrowserFailed"
           value="<?php if (isset($_['pollInBrowserFailed'])) : p($_['pollInBrowserFailed']); endif; ?>"/>
    <input id="transactionID" type="hidden" name="transactionID"
           value="<?php if (isset($_['transactionID'])) : p($_['transactionID']); endif; ?>"/>
    <input id="errorMessage" type="hidden" name="errorMessage" value="">
    <input id="autoSubmit" type="hidden" name="autoSubmit"
           value="<?php if (isset($_['autoSubmit'])) : p($_['autoSubmit']); endif; ?>"/>
    <input id="mode" type="hidden" name="mode"
           value="<?php if (isset($_['mode'])) { p($_['mode']); } else { p('otp'); } ?>"/>

    <!-- PASSKEY INIT & AUTHENTICATION -->
    <?php if (!empty($_['passkeyChallenge'])) : ?>
        <input id="passkeyButton" type="button" name="passkeyButton"
               value="<?php if (isset($_['passkeyButton'])) : p($_['passkeyButton']); endif; ?>"/>
    <?php elseif (empty($_['passkeyRegistration']) && !empty($_['isEnrollViaMultichallenge'])
                    && $_['isEnrollViaMultichallenge'] === true && !$_['isDisablePasskey']) : ?>
        <button id="initPasskeyLogin" type="button" name="initPasskeyLogin">
            <?php if (isset($_['initPasskeyLogin'])) : p($_['initPasskeyLogin']); endif; ?>
        </button>
    <?php endif;?>

    <!-- PASSKEY REGISTRATION (enroll_via_multichallenge) with retry button -->
    <?php if (!empty($_['passkeyRegistration'])) : ?>
        <input id="retryPasskeyRegistration" type="button" name="retryPasskeyRegistration"
               value="<?php if (isset($_['retryPasskeyRegistration'])) : p($_['retryPasskeyRegistration']);endif; ?>"/>
    <?php endif; ?>

    <!-- ALTERNATE LOGIN OPTIONS -->
    <div id="alternateLoginOptions">
        <label>
            <strong>
                <?php if (isset($_['alternateLoginOptions'])) : p($_['alternateLoginOptions']); endif; ?>
            </strong>
        </label>
        <br>
        <input class="alternateTokenButtons" id="webAuthnButton" name="webAuthnButton"
               type="button" value="WebAuthn"/>
        <input class="alternateTokenButtons" id="pushButton" name="pushButton" type="button" value="Push"/>
        <input id="otpButton" name="otpButton" type="button" value="OTP"/>
    </div>
</form>