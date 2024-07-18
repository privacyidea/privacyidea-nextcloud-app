<?php
declare(strict_types=1);
use OCP\Util;
Util::addScript('privacyidea', 'utils');
Util::addScript('privacyidea', 'main');
Util::addScript('privacyidea', 'eventListeners');
Util::addScript('privacyidea', 'webauthn');
Util::addScript('privacyidea', 'pollByReload');
Util::addScript('privacyidea', 'pollTransaction.worker');
Util::addScript('privacyidea', 'pollInBrowser');
Util::addStyle('privacyidea', 'main');
?>

<!-- MESSAGES -->
<?php if (!empty($_['message'])) : ?>
    <fieldset class="warning">
        <?php p($_['message']); ?>
    </fieldset>
<?php endif; ?>

<!-- IMAGES -->
<?php if (!empty($_['imgWebauthn']) && $_['mode'] === "webauthn") : ?>
    <img class="tokenImages" src="<?php p($_['imgWebauthn']); ?>" alt="WebAuthn image"><br><br>
<?php endif;
if (!empty($_['imgPush']) && $_['mode'] === "push") : ?>
    <img class="tokenImages" src="<?php p($_['imgPush']); ?>" alt="Push image"><br><br>
<?php endif;
if (!empty($_['imgOTP']) && $_['mode'] === "otp") : ?>
    <img class="tokenImages" id="imgOtp" src="<?php p($_['imgOTP']); ?>" alt="OTP image"><br><br>
<?php endif;?>

<!-- FORM -->
<form method="POST" id="piLoginForm" name="piLoginForm">
    <?php if (!empty($_['redirect_url'])) : ?>
        <input type="hidden" name="redirect_url" value="<?php p($_['redirect_url']); ?>">
    <?php endif; ?>

    <?php if (!isset($_['hideOTPField']) || !$_['hideOTPField']) : ?>
        <label>
            <input id="otp" type="password" name="challenge" placeholder="OTP" autocomplete="off" required
                   autofocus>
        </label>
        <br>
        <input id="submitButton" type="submit" class="button"
               value="<?php if (isset($_['verify'])) : p($_['verify']); endif; ?>">
    <?php endif; ?>

    <!-- Hidden input that saves the changes -->
    <input id="mode" type="hidden" name="mode"
           value="<?php if (isset($_['mode']))
           {
               p($_['mode']);
           }
           else
           {
               p("otp");
           } ?>"/>
    <input id="modeChanged" type="hidden" name="modeChanged" value="0"/>
    <input id="autoSubmitOtpLength" type="hidden" name="autoSubmitOtpLength"
           value="<?php if (!empty($_['autoSubmitOtpLength'])) : p($_['autoSubmitOtpLength']); endif; ?>"/>
    <input id="webAuthnSignRequest" type="hidden" name="webAuthnSignRequest"
           value='<?php if (isset($_['webAuthnSignRequest'])) : p($_['webAuthnSignRequest']); endif; ?>'/>
    <input id="webAuthnSignResponse" type="hidden" name="webAuthnSignResponse" value=""/>
    <input id="origin" type="hidden" name="origin" value=""/>
    <input id="pushAvailable" type="hidden" name="pushAvailable"
           value="<?php if (isset($_['pushAvailable'])) : p($_['pushAvailable']); endif; ?>"/>
    <input id="otpAvailable" type="hidden" name="otpAvailable"
           value="<?php if (isset($_['otpAvailable'])) : p($_['otpAvailable']); endif; ?>"/>
    <input id="loadCounter" type="hidden" name="loadCounter"
           value="<?php if (isset($_['loadCounter'])) : p($_['loadCounter']); endif; ?>"/>
    <input id="pollInBrowserUrl" type="hidden" name="pollInBrowserUrl"
           value="<?php if (isset($_['pollInBrowserUrl'])) : p($_['pollInBrowserUrl']); endif; ?>"/>
    <input id="pollInBrowser" type="hidden" name="pollInBrowser"
           value="<?php if (isset($_['pollInBrowser'])) : p($_['pollInBrowser']); endif; ?>"/>
    <input id="transactionId" type="hidden" name="transactionId"
           value="<?php if (isset($_['transactionId'])) : p($_['transactionId']); endif; ?>"/>
    <input id="errorMessage" type="hidden" name="errorMessage" value="">
    <input id="pollInBrowserFailed" type="hidden" name="pollInBrowserFailed"
           value="<?php if (isset($_['pollInBrowserFailed'])) : p($_['pollInBrowserFailed']); endif; ?>"/>
    <input id="autoSubmit" type="hidden" name="autoSubmit"
           value="<?php if (isset($_['autoSubmit'])) : p($_['autoSubmit']); endif; ?>"/>

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

    <?php if (isset($_['autoSubmit']) && $_['autoSubmit']): ?>
        <input type="submit" class="button" value="Login">
        <br>
    <?php endif; ?>
</form>
