<?php

declare(strict_types=1);

namespace Libsignal\ecc;

interface ECPrivateKey
{
    public function serialize();

    public function getType();
}
