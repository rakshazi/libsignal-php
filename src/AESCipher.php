<?php

declare(strict_types=1);

namespace Libsignal;

use Illuminate\Support\Facades\Log;

class AESCipher
{
    protected $key;
    protected $iv;
    protected $version;
    protected $counter;

    public function __construct($key, $iv, $version = 3, $counter = null)
    {
        $this->key = $key;
        $this->iv = $iv;
        $this->version = $version;

        if ($this->version < 3 && null === $counter) {
            throw new \Exception('Counter is needed for version < 3');
        }

        $this->counter = $counter;
    }

    public function encrypt($raw)
    {
        // if sys.version_info >= (3,0):
        //     rawPadded = pad(raw.decode()).encode()
        // else:
        if ($this->version >= 3) {
            $rawPadded = $this->pad($raw);

//            $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key, $rawPadded, MCRYPT_MODE_CBC, $this->iv);
            $encrypted = \openssl_encrypt($rawPadded, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $this->iv);

            return $encrypted;
        }

//            $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key, $raw, 'ctr', $this->counter->Next());

        //$data, $method, $key, $options = 0, $iv = "", &$tag = NULL, $aad = "", $tag_length = 16
        $encrypted = \openssl_encrypt($raw, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $this->counter->Next());

        return $encrypted;
    }

    public function decrypt($enc)
    {
        if ($this->version >= 3) {
//            Log::info(json_encode(["action" => "decode", "enc" => bin2hex($enc), "key" => bin2hex($this->key), "iv" => bin2hex($this->iv)]));

            // $result = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->key, $enc, MCRYPT_MODE_CBC, $this->iv);
            $result = \openssl_decrypt($enc, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $this->iv);

            return $result;
            /*$unpaded = $this->unpad($result);
            $last_unpadded = $unpaded[strlen($unpaded) - 1];
            $double_padding = substr($unpaded, -1 * (ord($last_unpadded) - 1));

            if (ord($last_unpadded) - 1 == strlen($double_padding))
            {
                $has_dp = true;

                for ($x = 0; $x < strlen($double_padding); $x++)
                {
                    if ($double_padding[$x] != $last_unpadded)
                    {
                        $has_dp = false;
                        break;
                    }
                }
            }
            else {
                $has_dp = false;
            }
            if ($has_dp)
            {
                $unpaded = $this->unpad($unpaded, 1);
            }

            return $unpaded;*/
        }

        // return mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->key, $enc, 'ctr', $this->counter->Next());
        return \openssl_decrypt($enc, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $this->counter->Next());
    }

    private function pad($s)
    {
        //$BS = 16;

        //  return $s.str_repeat(chr($BS - (strlen($s) % $BS)), ($BS - (strlen($s) % $BS)));
        //return $s.str_repeat(chr(0), ($BS - (strlen($s) % $BS)));
        return $s;
    }

    private function unpad($s, $diff = 0)
    {
        return \substr($s, 0, -1 * (\ord($s[\strlen($s) - 1]) - $diff));
    }

    /*    public function decrypt($enc)
        {
            if ($this->version >= 3)
            {
    
                Log::info(json_encode(["action" => "decode1", "enc" => bin2hex($enc), "key" => bin2hex($this->key), "iv" => bin2hex($this->iv)]));
    
    //            $result = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->key, $enc, MCRYPT_MODE_CBC, $this->iv);
    
    
                $result = openssl_decrypt( $enc, "AES-256-CBC", $this->key, OPENSSL_RAW_DATA, $this->iv);
    //                    openssl_decrypt($data, $method, $password, $options = 1, $iv = "", $tag = "",  $aad = "")
    //                    ($cipher, $key, $data, $mode, $iv = null)
    
                //  openssl_error_string ()
    
    
                $unpaded = $this->unpad($result);
                $last_unpadded = $unpaded[strlen($unpaded) - 1];
                $double_padding = substr($unpaded, -1 * (ord($last_unpadded) - 1));
    
                if (ord($last_unpadded) - 1 == strlen($double_padding))
                {
                    $has_dp = true;
    
                    for ($x = 0; $x < strlen($double_padding); $x++)
                    {
                        if ($double_padding[$x] != $last_unpadded)
                        {
                            $has_dp = false;
                            break;
                        }
                    }
                }
                else
                {
                    $has_dp = false;
                }
    
                if ($has_dp)
                {
                    $unpaded = $this->unpad($unpaded, 1);
                }
    
                return $unpaded;
            }
            else
            {
    //            $decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->key, $enc, 'ctr', $this->counter->Next());
                $decrypted = openssl_decrypt( $enc, "AES-256-CBC", $this->key, OPENSSL_RAW_DATA, $this->counter->Next());
    
                return $decrypted;
            }
        }*/
}
