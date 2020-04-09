<?php

declare(strict_types=1);

namespace Libsignal\kdf;

class HKDFv3 extends HKDF
{
    protected function getIterationStartOffset()
    {
        return 1;
    }
}
