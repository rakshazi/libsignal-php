<?php

declare(strict_types=1);

namespace Libsignal\exceptions;

class InvalidMacException extends \Exception
{
    public function __construct($detailMessage) // [String detailMessage]
    {
        $this->message = $detailMessage;
    }
}
