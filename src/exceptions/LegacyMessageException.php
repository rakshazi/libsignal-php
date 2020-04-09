<?php

declare(strict_types=1);

namespace Libsignal\exceptions;

class LegacyMessageException extends \Exception
{
    public function __construct($detailMesssage) // [String s]
    {
        $this->message = $detailMesssage;
    }
}
