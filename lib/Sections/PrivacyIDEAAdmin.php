<?php

namespace OCA\PrivacyIDEA\Sections;

use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\Settings\IIconSection;

class PrivacyIDEAAdmin implements IIconSection
{
    private IL10N $l;
    private IURLGenerator $urlGenerator;

    public function __construct(IL10N $l, IURLGenerator $urlGenerator)
    {
        $this->l = $l;
        $this->urlGenerator = $urlGenerator;
    }

    public function getIcon(): string
    {
        return $this->urlGenerator->imagePath('privacyidea', 'settings-dark.svg');
    }

    public function getID(): string
    {
        return 'privacyidea';
    }

    public function getName(): string
    {
        return $this->l->t('privacyIDEA');
    }

    public function getPriority(): int
    {
        return 91;
    }
}