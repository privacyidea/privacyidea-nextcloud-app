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

use OCP\IRequest;
use Psr\Log\LoggerInterface;

/**
 * Resolves the client IP address of the current request.
 *
 * Shared by {@see PrivacyIDEAProvider} (exclude-IP check) and
 * {@see PrivacyIDEAFactory} (forward-client-IP setting) so both derive the
 * address the same way and cannot drift apart.
 */
final class ClientIp
{
	/**
	 * @param IRequest $request Current request.
	 * @param LoggerInterface $logger Logger for the failure case.
	 * @return string Client IP address, or an empty string when unavailable.
	 */
	public static function resolve(IRequest $request, LoggerInterface $logger): string
	{
		$clientIP = $request->getRemoteAddress();
		if (!empty($clientIP)) {
			return $clientIP;
		}
		$logger->error('Cannot get client IP address.', ['app' => 'privacyidea']);
		return '';
	}
}
