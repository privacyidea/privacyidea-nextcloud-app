<?php

/*
 * Copyright 2024 NetKnights GmbH - lukas.matusiewicz@netknights.it
 * <p>
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3;
 * you may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace OCA\PrivacyIDEA\Provider;

use OCA\PrivacyIDEA\AppInfo\Application;
use OCA\PrivacyIDEA\PIClient\PrivacyIDEA;
use OCP\App\IAppManager;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IRequest;
use Psr\Log\LoggerInterface;

/**
 * Builds a configured {@see PrivacyIDEA} client from the app configuration.
 *
 * Extracted from PrivacyIDEAProvider so that the provider no longer news up
 * the client itself. This is the seam that lets tests inject a fake client:
 * a test can pass a stub factory whose create() returns a mock PrivacyIDEA.
 */
class PrivacyIDEAFactory
{
	/** @var IAppConfig */
	private IAppConfig $appConfig;
	/** @var IRequest */
	private IRequest $request;
	/** @var LoggerInterface */
	private LoggerInterface $logger;
	/** @var IAppManager */
	private IAppManager $appManager;
	/** @var IConfig */
	private IConfig $config;

	public function __construct(IAppConfig $appConfig, IRequest $request, LoggerInterface $logger, IAppManager $appManager, IConfig $config)
	{
		$this->appConfig = $appConfig;
		$this->request = $request;
		$this->logger = $logger;
		$this->appManager = $appManager;
		$this->config = $config;
	}

	/**
	 * Create a new privacyIDEA client with the configured settings.
	 *
	 * @return PrivacyIDEA|null Configured client or null when no server URL is set.
	 */
	public function create(): ?PrivacyIDEA
	{
		$piUrl = $this->getAppValue('piURL', '');
		if (empty($piUrl)) {
			$this->logger->error('Cannot create privacyIDEA instance: Server URL missing in configuration!', ['app' => 'privacyidea']);
			return null;
		}
		// Single source of truth for the version: the app manifest (info.xml),
		// read at runtime so the user agent never drifts from the release.
		$userAgent = 'privacyidea-nextcloud/' . $this->appManager->getAppVersion(Application::APP_ID);
		$pi = new PrivacyIDEA($userAgent, $piUrl);
		$pi->setSSLVerifyHost($this->getAppValue('piSSLVerify', true));
		$pi->setSSLVerifyPeer($this->getAppValue('piSSLVerify', true));
		$pi->setServiceAccountName($this->getAppValue('piServiceName', ''));
		$pi->setServiceAccountPass($this->getAppValue('piServicePass', ''));
		$pi->setServiceAccountRealm($this->getAppValue('piServiceRealm', ''));
		$pi->setRealm($this->getAppValue('piRealm', ''));
		$pi->setTimeout($this->getAppValue('piTimeout', '5'));
		$pi->setNoProxy($this->getAppValue('piNoProxy', false));
		// Only build the verbose request/response debug logs when the system is
		// actually recording debug (loglevel 0); otherwise they would be encoded
		// and immediately discarded on every login request.
		$pi->setDebugLog($this->config->getSystemValueInt('loglevel', 2) <= 0);
		if ($this->getAppValue('piForwardClientIP', false) && !empty($this->getClientIP())) {
			$pi->setForwardClientIP($this->getClientIP());
		}
		return $pi;
	}

	/**
	 * Retrieve a value from the privacyIDEA app configuration store.
	 *
	 * @param string $key application config key
	 * @param string|bool $default default value
	 * @return string
	 */
	private function getAppValue(string $key, $default): string
	{
		return $this->appConfig->getValueString('privacyidea', $key, (string)$default);
	}

	/**
	 * Get the client IP address.
	 *
	 * @return string Client IP address or an empty string.
	 */
	private function getClientIP(): string
	{
		$clientIP = $this->request->getRemoteAddress();
		if (!empty($clientIP)) {
			return $clientIP;
		}
		$this->logger->error('Cannot get client IP address.', ['app' => 'privacyidea']);
		return '';
	}
}
