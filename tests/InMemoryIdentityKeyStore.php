<?php

declare(strict_types=1);

namespace Libsignal\Tests;

//from axolotl.state.identitykeystore import IdentityKeyStore
//from axolotl.ecc.curve import Curve
//from axolotl.identitykey import IdentityKey
//from axolotl.util.keyhelper import KeyHelper
//from axolotl.identitykeypair import IdentityKeyPair
use Libsignal\ecc\Curve;
use Libsignal\IdentityKey;
use Libsignal\IdentityKeyPair;
use Libsignal\state\IdentityKeyStore;
use Libsignal\util\KeyHelper;

class InMemoryIdentityKeyStore extends IdentityKeyStore
{
    protected $trustedKeys;
    protected $identityKeyPair;
    protected $localRegistrationId;

    public function __construct()
    {
        $this->trustedKeys = [];
        $identityKeyPairKeys = Curve::generateKeyPair();
        $this->identityKeyPair = new IdentityKeyPair(new IdentityKey($identityKeyPairKeys->getPublicKey()), $identityKeyPairKeys->getPrivateKey());
        $this->localRegistrationId = KeyHelper::generateRegistrationId();
    }

    public function getIdentityKeyPair()
    {
        return $this->identityKeyPair;
    }

    public function getLocalRegistrationId()
    {
        return $this->localRegistrationId;
    }

    public function saveIdentity($recepientId, $identityKey): void
    {
        $this->trustedKeys[$recepientId] = $identityKey;
    }

    public function isTrustedIdentity($recepientId, $identityKey)
    {
        if (!isset($this->trustedKeys[$recepientId])) {
            return true;
        }

//        dd(["trusted" => $this->trustedKeys[$recepientId], "vadim's" => $identityKey]);

        return $this->trustedKeys[$recepientId] === $identityKey;
    }
}
