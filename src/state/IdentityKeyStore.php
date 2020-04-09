<?php

declare(strict_types=1);

namespace Libsignal\state;

use Libsignal\IdentityKey;

abstract class IdentityKeyStore
{
    abstract public function getIdentityKeyPair();

    abstract public function getLocalRegistrationId();

    abstract public function saveIdentity($recipientId, $identityKey);

    // [long recipientId, IdentityKey identityKey]

    abstract public function isTrustedIdentity($recipientId, $identityKey);

    // [long recipientId, IdentityKey identityKey]
}
