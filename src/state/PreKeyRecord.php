<?php

declare(strict_types=1);

namespace Libsignal\state;

use Libsignal\ecc\Curve;
use Libsignal\ecc\ECKeyPair;

require_once __DIR__.'/pb_proto_LocalStorageProtocol.php';

class PreKeyRecord
{
    protected $structure;    // PreKeyRecordStructure

    public function __construct($id = null, $keyPair = null, $serialized = null) // [int id, ECKeyPair keyPair]
    {
        $this->structure = new Textsecure_PreKeyRecordStructure();

        if (null === $serialized) {
            $this->structure->setId($id)->setPublicKey((string) $keyPair->getPublicKey()->serialize())->setPrivateKey((string) $keyPair->getPrivateKey()->serialize());
        } else {
            try {
                $this->structure->parseFromString($serialized);
            } catch (\Exception $ex) {
                throw new \Exception('Cannot unserialize PreKEyRecordStructure');
            }
        }
    }

    public function getId()
    {
        return $this->structure->getId();
    }

    public function getKeyPair()
    {
        $publicKey = Curve::decodePoint($this->structure->getPublicKey(), 0);
        $privateKey = Curve::decodePrivatePoint($this->structure->getPrivateKey());

        return new ECKeyPair($publicKey, $privateKey);
    }

    public function serialize()
    {
        return $this->structure->serializeToString();
    }
}

class Textsecure_PreKeyRecordStructure extends \ProtobufMessage
{
    // Field index constants
    const ID = 1;
    const PUBLICKEY = 2;
    const PRIVATEKEY = 3;

    // @var array Field descriptors
    protected static $fields = [
        self::ID => [
            'name' => 'id',
            'required' => false,
            'type' => 5,
        ],
        self::PUBLICKEY => [
            'name' => 'publicKey',
            'required' => false,
            'type' => 7,
        ],
        self::PRIVATEKEY => [
            'name' => 'privateKey',
            'required' => false,
            'type' => 7,
        ],
    ];

    /**
     * Constructs new message container and clears its internal state.
     *
     * @return null
     */
    public function __construct()
    {
        $this->reset();
    }

    /**
     * Clears message values and sets default ones.
     *
     * @return null
     */
    public function reset()
    {
        $this->values[self::ID] = null;
        $this->values[self::PUBLICKEY] = null;
        $this->values[self::PRIVATEKEY] = null;
    }

    /**
     * Returns field descriptors.
     *
     * @return array
     */
    public function fields()
    {
        return self::$fields;
    }

    /**
     * Sets value of 'id' property.
     *
     * @param int $value Property value
     *
     * @return null
     */
    public function setId($value)
    {
        return $this->set(self::ID, $value);
    }

    /**
     * Returns value of 'id' property.
     *
     * @return int
     */
    public function getId()
    {
        return $this->get(self::ID);
    }

    /**
     * Sets value of 'publicKey' property.
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setPublicKey($value)
    {
        return $this->set(self::PUBLICKEY, $value);
    }

    /**
     * Returns value of 'publicKey' property.
     *
     * @return string
     */
    public function getPublicKey()
    {
        return $this->get(self::PUBLICKEY);
    }

    /**
     * Sets value of 'privateKey' property.
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setPrivateKey($value)
    {
        return $this->set(self::PRIVATEKEY, $value);
    }

    /**
     * Returns value of 'privateKey' property.
     *
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->get(self::PRIVATEKEY);
    }
}
