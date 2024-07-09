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

<div id="privacyidea">

    <p> privacyIDEA Authenticator</p>

</div>