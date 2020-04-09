<?php

declare(strict_types=1);

namespace Libsignal\exceptions;

class NoSessionException extends \Exception
{
    public function __construct($s) // [String s]
    {
        $this->message = $s;
    }
}
