<?php

declare(strict_types=1);

namespace Libsignal\state;

abstract class SignedPreKeyStore
{
    abstract public function loadSignedPreKey($signedPreKeyId);

    // [int signedPreKeyId]

    abstract public function loadSignedPreKeys();

    abstract public function storeSignedPreKey($signedPreKeyId, $record);

    // [int signedPreKeyId, SignedPreKeyRecord record]

    abstract public function containsSignedPreKey($signedPreKeyId);

    // [int signedPreKeyId]

    abstract public function removeSignedPreKey($signedPreKeyId);

    // [int signedPreKeyId]
}
