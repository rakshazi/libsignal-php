<?php

declare(strict_types=1);

namespace Libsignal;

use Libsignal\ecc\Curve;
use Libsignal\ecc\DjbECPublicKey;
use Libsignal\ecc\ECPublicKey;

class IdentityKey extends DjbECPublicKey
{
    protected $publicKey;    // ECPublicKey

    public function __construct($publicKeyOrBytes, $offset = null) // [ECPublicKey publicKey]
    {
        if (null === $offset) {
            $this->publicKey = $publicKeyOrBytes;
        } else {
            $this->publicKey = Curve::decodePoint($publicKeyOrBytes, $offset);
        }
    }

    public function getPublicKey()
    {
        return $this->publicKey;
    }

    public function serialize()
    {
        return $this->publicKey->serialize();
    }

    public function getFingerprint()
    {
        $hex = \unpack('H*', $this->publicKey->serialize());
        $hex = \implode(' ', \str_split($hex, 2));

        return $hex;
    }

    public function equals($other) // [Object other]
    {
        if ((null === $other)) {
            return  false;
        }
        if (!($other instanceof self)) {
            return  false;
        }

        return $this->publicKey->equals($other->getPublicKey());
    }

    public function hashCode()
    {
        return $this->publicKey->hashCode();
    }
}
