<?php

namespace Libsignal\protocol;

/**
 * WhisperMessage message
 */
class Textsecure_WhisperMessage extends \ProtobufMessage
{
    /* Field index constants */
    const RATCHETKEY = 1;
    const COUNTER = 2;
    const PREVIOUSCOUNTER = 3;
    const CIPHERTEXT = 4;

    /* @var array Field descriptors */
    protected static $fields = array(
        self::RATCHETKEY => array(
            'name' => 'ratchetKey',
            'required' => false,
            'type' => 7,
        ),
        self::COUNTER => array(
            'name' => 'counter',
            'required' => false,
            'type' => 5,
        ),
        self::PREVIOUSCOUNTER => array(
            'name' => 'previousCounter',
            'required' => false,
            'type' => 5,
        ),
        self::CIPHERTEXT => array(
            'name' => 'ciphertext',
            'required' => false,
            'type' => 7,
        ),
    );

    /**
     * Constructs new message container and clears its internal state
     *
     * @return null
     */
    public function __construct()
    {
        $this->reset();
    }

    /**
     * Clears message values and sets default ones
     *
     * @return null
     */
    public function reset()
    {
        $this->values[self::RATCHETKEY] = null;
        $this->values[self::COUNTER] = null;
        $this->values[self::PREVIOUSCOUNTER] = null;
        $this->values[self::CIPHERTEXT] = null;
    }

    /**
     * Returns field descriptors
     *
     * @return array
     */
    public function fields()
    {
        return self::$fields;
    }

    /**
     * Sets value of 'ratchetKey' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setRatchetKey($value)
    {
        return $this->set(self::RATCHETKEY, $value);
    }

    /**
     * Returns value of 'ratchetKey' property
     *
     * @return string
     */
    public function getRatchetKey()
    {
        return $this->get(self::RATCHETKEY);
    }

    /**
     * Sets value of 'counter' property
     *
     * @param int $value Property value
     *
     * @return null
     */
    public function setCounter($value)
    {
        return $this->set(self::COUNTER, $value);
    }

    /**
     * Returns value of 'counter' property
     *
     * @return int
     */
    public function getCounter()
    {
        return $this->get(self::COUNTER);
    }

    /**
     * Sets value of 'previousCounter' property
     *
     * @param int $value Property value
     *
     * @return null
     */
    public function setPreviousCounter($value)
    {
        return $this->set(self::PREVIOUSCOUNTER, $value);
    }

    /**
     * Returns value of 'previousCounter' property
     *
     * @return int
     */
    public function getPreviousCounter()
    {
        return $this->get(self::PREVIOUSCOUNTER);
    }

    /**
     * Sets value of 'ciphertext' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setCiphertext($value)
    {
        return $this->set(self::CIPHERTEXT, $value);
    }

    /**
     * Returns value of 'ciphertext' property
     *
     * @return string
     */
    public function getCiphertext()
    {
        return $this->get(self::CIPHERTEXT);
    }
}

/**
 * PreKeyWhisperMessage message
 */
class Textsecure_PreKeyWhisperMessage extends \ProtobufMessage
{
    /* Field index constants */
    const REGISTRATIONID = 5;
    const PREKEYID = 1;
    const SIGNEDPREKEYID = 6;
    const BASEKEY = 2;
    const IDENTITYKEY = 3;
    const MESSAGE = 4;

    /* @var array Field descriptors */
    protected static $fields = array(
        self::REGISTRATIONID => array(
            'name' => 'registrationId',
            'required' => false,
            'type' => 5,
        ),
        self::PREKEYID => array(
            'name' => 'preKeyId',
            'required' => false,
            'type' => 5,
        ),
        self::SIGNEDPREKEYID => array(
            'name' => 'signedPreKeyId',
            'required' => false,
            'type' => 5,
        ),
        self::BASEKEY => array(
            'name' => 'baseKey',
            'required' => false,
            'type' => 7,
        ),
        self::IDENTITYKEY => array(
            'name' => 'identityKey',
            'required' => false,
            'type' => 7,
        ),
        self::MESSAGE => array(
            'name' => 'message',
            'required' => false,
            'type' => 7,
        ),
    );

    /**
     * Constructs new message container and clears its internal state
     *
     * @return null
     */
    public function __construct()
    {
        $this->reset();
    }

    /**
     * Clears message values and sets default ones
     *
     * @return null
     */
    public function reset()
    {
        $this->values[self::REGISTRATIONID] = null;
        $this->values[self::PREKEYID] = null;
        $this->values[self::SIGNEDPREKEYID] = null;
        $this->values[self::BASEKEY] = null;
        $this->values[self::IDENTITYKEY] = null;
        $this->values[self::MESSAGE] = null;
    }

    /**
     * Returns field descriptors
     *
     * @return array
     */
    public function fields()
    {
        return self::$fields;
    }

    /**
     * Sets value of 'registrationId' property
     *
     * @param int $value Property value
     *
     * @return null
     */
    public function setRegistrationId($value)
    {
        return $this->set(self::REGISTRATIONID, $value);
    }

    /**
     * Returns value of 'registrationId' property
     *
     * @return int
     */
    public function getRegistrationId()
    {
        return $this->get(self::REGISTRATIONID);
    }

    /**
     * Sets value of 'preKeyId' property
     *
     * @param int $value Property value
     *
     * @return null
     */
    public function setPreKeyId($value)
    {
        return $this->set(self::PREKEYID, $value);
    }

    /**
     * Returns value of 'preKeyId' property
     *
     * @return int
     */
    public function getPreKeyId()
    {
        return $this->get(self::PREKEYID);
    }

    /**
     * Sets value of 'signedPreKeyId' property
     *
     * @param int $value Property value
     *
     * @return null
     */
    public function setSignedPreKeyId($value)
    {
        return $this->set(self::SIGNEDPREKEYID, $value);
    }

    /**
     * Returns value of 'signedPreKeyId' property
     *
     * @return int
     */
    public function getSignedPreKeyId()
    {
        return $this->get(self::SIGNEDPREKEYID);
    }

    /**
     * Sets value of 'baseKey' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setBaseKey($value)
    {
        return $this->set(self::BASEKEY, $value);
    }

    /**
     * Returns value of 'baseKey' property
     *
     * @return string
     */
    public function getBaseKey()
    {
        return $this->get(self::BASEKEY);
    }

    /**
     * Sets value of 'identityKey' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setIdentityKey($value)
    {
        return $this->set(self::IDENTITYKEY, $value);
    }

    /**
     * Returns value of 'identityKey' property
     *
     * @return string
     */
    public function getIdentityKey()
    {
        return $this->get(self::IDENTITYKEY);
    }

    /**
     * Sets value of 'message' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setMessage($value)
    {
        return $this->set(self::MESSAGE, $value);
    }

    /**
     * Returns value of 'message' property
     *
     * @return string
     */
    public function getMessage()
    {
        return $this->get(self::MESSAGE);
    }
}

/**
 * KeyExchangeMessage message
 */
class Textsecure_KeyExchangeMessage extends \ProtobufMessage
{
    /* Field index constants */
    const ID = 1;
    const BASEKEY = 2;
    const RATCHETKEY = 3;
    const IDENTITYKEY = 4;
    const BASEKEYSIGNATURE = 5;

    /* @var array Field descriptors */
    protected static $fields = array(
        self::ID => array(
            'name' => 'id',
            'required' => false,
            'type' => 5,
        ),
        self::BASEKEY => array(
            'name' => 'baseKey',
            'required' => false,
            'type' => 7,
        ),
        self::RATCHETKEY => array(
            'name' => 'ratchetKey',
            'required' => false,
            'type' => 7,
        ),
        self::IDENTITYKEY => array(
            'name' => 'identityKey',
            'required' => false,
            'type' => 7,
        ),
        self::BASEKEYSIGNATURE => array(
            'name' => 'baseKeySignature',
            'required' => false,
            'type' => 7,
        ),
    );

    /**
     * Constructs new message container and clears its internal state
     *
     * @return null
     */
    public function __construct()
    {
        $this->reset();
    }

    /**
     * Clears message values and sets default ones
     *
     * @return null
     */
    public function reset()
    {
        $this->values[self::ID] = null;
        $this->values[self::BASEKEY] = null;
        $this->values[self::RATCHETKEY] = null;
        $this->values[self::IDENTITYKEY] = null;
        $this->values[self::BASEKEYSIGNATURE] = null;
    }

    /**
     * Returns field descriptors
     *
     * @return array
     */
    public function fields()
    {
        return self::$fields;
    }

    /**
     * Sets value of 'id' property
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
     * Returns value of 'id' property
     *
     * @return int
     */
    public function getId()
    {
        return $this->get(self::ID);
    }

    /**
     * Sets value of 'baseKey' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setBaseKey($value)
    {
        return $this->set(self::BASEKEY, $value);
    }

    /**
     * Returns value of 'baseKey' property
     *
     * @return string
     */
    public function getBaseKey()
    {
        return $this->get(self::BASEKEY);
    }

    /**
     * Sets value of 'ratchetKey' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setRatchetKey($value)
    {
        return $this->set(self::RATCHETKEY, $value);
    }

    /**
     * Returns value of 'ratchetKey' property
     *
     * @return string
     */
    public function getRatchetKey()
    {
        return $this->get(self::RATCHETKEY);
    }

    /**
     * Sets value of 'identityKey' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setIdentityKey($value)
    {
        return $this->set(self::IDENTITYKEY, $value);
    }

    /**
     * Returns value of 'identityKey' property
     *
     * @return string
     */
    public function getIdentityKey()
    {
        return $this->get(self::IDENTITYKEY);
    }

    /**
     * Sets value of 'baseKeySignature' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setBaseKeySignature($value)
    {
        return $this->set(self::BASEKEYSIGNATURE, $value);
    }

    /**
     * Returns value of 'baseKeySignature' property
     *
     * @return string
     */
    public function getBaseKeySignature()
    {
        return $this->get(self::BASEKEYSIGNATURE);
    }
}

/**
 * SenderKeyMessage message
 */
class Textsecure_SenderKeyMessage extends \ProtobufMessage
{
    /* Field index constants */
    const ID = 1;
    const ITERATION = 2;
    const CIPHERTEXT = 3;

    /* @var array Field descriptors */
    protected static $fields = array(
        self::ID => array(
            'name' => 'id',
            'required' => false,
            'type' => 5,
        ),
        self::ITERATION => array(
            'name' => 'iteration',
            'required' => false,
            'type' => 5,
        ),
        self::CIPHERTEXT => array(
            'name' => 'ciphertext',
            'required' => false,
            'type' => 7,
        ),
    );

    /**
     * Constructs new message container and clears its internal state
     *
     * @return null
     */
    public function __construct()
    {
        $this->reset();
    }

    /**
     * Clears message values and sets default ones
     *
     * @return null
     */
    public function reset()
    {
        $this->values[self::ID] = null;
        $this->values[self::ITERATION] = null;
        $this->values[self::CIPHERTEXT] = null;
    }

    /**
     * Returns field descriptors
     *
     * @return array
     */
    public function fields()
    {
        return self::$fields;
    }

    /**
     * Sets value of 'id' property
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
     * Returns value of 'id' property
     *
     * @return int
     */
    public function getId()
    {
        return $this->get(self::ID);
    }

    /**
     * Sets value of 'iteration' property
     *
     * @param int $value Property value
     *
     * @return null
     */
    public function setIteration($value)
    {
        return $this->set(self::ITERATION, $value);
    }

    /**
     * Returns value of 'iteration' property
     *
     * @return int
     */
    public function getIteration()
    {
        return $this->get(self::ITERATION);
    }

    /**
     * Sets value of 'ciphertext' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setCiphertext($value)
    {
        return $this->set(self::CIPHERTEXT, $value);
    }

    /**
     * Returns value of 'ciphertext' property
     *
     * @return string
     */
    public function getCiphertext()
    {
        return $this->get(self::CIPHERTEXT);
    }
}

/**
 * SenderKeyDistributionMessage message
 */
class Textsecure_SenderKeyDistributionMessage extends \ProtobufMessage
{
    /* Field index constants */
    const ID = 1;
    const ITERATION = 2;
    const CHAINKEY = 3;
    const SIGNINGKEY = 4;

    /* @var array Field descriptors */
    protected static $fields = array(
        self::ID => array(
            'name' => 'id',
            'required' => false,
            'type' => 5,
        ),
        self::ITERATION => array(
            'name' => 'iteration',
            'required' => false,
            'type' => 5,
        ),
        self::CHAINKEY => array(
            'name' => 'chainKey',
            'required' => false,
            'type' => 7,
        ),
        self::SIGNINGKEY => array(
            'name' => 'signingKey',
            'required' => false,
            'type' => 7,
        ),
    );

    /**
     * Constructs new message container and clears its internal state
     *
     * @return null
     */
    public function __construct()
    {
        $this->reset();
    }

    /**
     * Clears message values and sets default ones
     *
     * @return null
     */
    public function reset()
    {
        $this->values[self::ID] = null;
        $this->values[self::ITERATION] = null;
        $this->values[self::CHAINKEY] = null;
        $this->values[self::SIGNINGKEY] = null;
    }

    /**
     * Returns field descriptors
     *
     * @return array
     */
    public function fields()
    {
        return self::$fields;
    }

    /**
     * Sets value of 'id' property
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
     * Returns value of 'id' property
     *
     * @return int
     */
    public function getId()
    {
        return $this->get(self::ID);
    }

    /**
     * Sets value of 'iteration' property
     *
     * @param int $value Property value
     *
     * @return null
     */
    public function setIteration($value)
    {
        return $this->set(self::ITERATION, $value);
    }

    /**
     * Returns value of 'iteration' property
     *
     * @return int
     */
    public function getIteration()
    {
        return $this->get(self::ITERATION);
    }

    /**
     * Sets value of 'chainKey' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setChainKey($value)
    {
        return $this->set(self::CHAINKEY, $value);
    }

    /**
     * Returns value of 'chainKey' property
     *
     * @return string
     */
    public function getChainKey()
    {
        return $this->get(self::CHAINKEY);
    }

    /**
     * Sets value of 'signingKey' property
     *
     * @param string $value Property value
     *
     * @return null
     */
    public function setSigningKey($value)
    {
        return $this->set(self::SIGNINGKEY, $value);
    }

    /**
     * Returns value of 'signingKey' property
     *
     * @return string
     */
    public function getSigningKey()
    {
        return $this->get(self::SIGNINGKEY);
    }
}
