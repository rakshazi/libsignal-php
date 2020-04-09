<?php

declare(strict_types=1);

namespace Libsignal\ratchet;

use Libsignal\ecc\ECKeyPair;
use Libsignal\ecc\ECPublicKey;
use Libsignal\IdentityKey;
use Libsignal\IdentityKeyPair;

class SymmetricAxolotlParameters
{
    protected $ourBaseKey;    // ECKeyPair
    protected $ourRatchetKey;    // ECKeyPair
    protected $ourIdentityKey;    // IdentityKeyPair
    protected $theirBaseKey;    // ECPublicKey
    protected $theirRatchetKey;    // ECPublicKey
    protected $theirIdentityKey;    // IdentityKey

    public function __construct($ourBaseKey, $ourRatchetKey, $ourIdentityKey, $theirBaseKey, $theirRatchetKey, $theirIdentityKey) // [ECKeyPair ourBaseKey, ECKeyPair ourRatchetKey, IdentityKeyPair ourIdentityKey, ECPublicKey theirBaseKey, ECPublicKey theirRatchetKey, IdentityKey theirIdentityKey]
    {
        $this->ourBaseKey = $ourBaseKey;
        $this->ourRatchetKey = $ourRatchetKey;
        $this->ourIdentityKey = $ourIdentityKey;
        $this->theirBaseKey = $theirBaseKey;
        $this->theirRatchetKey = $theirRatchetKey;
        $this->theirIdentityKey = $theirIdentityKey;

        if ((null === $ourBaseKey) || (null === $ourRatchetKey)
            || (null === $ourIdentityKey) || (null === $theirBaseKey)
            || (null === $theirRatchetKey) || (null === $theirIdentityKey)) {
            throw new \Exception('Null values!');
        }
    }

    public function getOurBaseKey()
    {
        return $this->ourBaseKey;
    }

    public function getOurRatchetKey()
    {
        return $this->ourRatchetKey;
    }

    public function getOurIdentityKey()
    {
        return $this->ourIdentityKey;
    }

    public function getTheirBaseKey()
    {
        return $this->theirBaseKey;
    }

    public function getTheirRatchetKey()
    {
        return $this->theirRatchetKey;
    }

    public function getTheirIdentityKey()
    {
        return $this->theirIdentityKey;
    }

    public static function newBuilder()
    {
        return new SymmetricBuilder();
    }
}
