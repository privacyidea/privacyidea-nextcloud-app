<?php

return array(
    'routes' => [
        [
            'name' => 'Settings#setValue',
            'url' => '/setValue',
            'verb' => 'POST'
        ],
        [
            'name' => 'Settings#getValue',
            'url' => '/getValue',
            'verb' => 'GET'
        ],
    ]);