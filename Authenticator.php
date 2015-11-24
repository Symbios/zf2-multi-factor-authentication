<?php
/**
 * Authenticator 
 * 2-factory verification
 * 
 * PHP version 5
 *
 * @author Nikolay Dyakov < nikolay@codific.eu >
 * @link   https://codific.eu
 * @formatter:off Prevent eclipse to auto format that file. Require by Nikolay Dyakov
 */
namespace Codific;

/**
 * Authenticator
 * 2-factory verification
 *
 * @author Nikolay Dyakov < nikolay@codific.eu >
 * @link https://codific.eu
 */
class Authenticator
{
    const API_URL = 'https://chart.googleapis.com/chart?chs={chs}&chld=M|0&cht=qr&chl={chl}';
    const CODE_LENGTH = 6;
    const SECRET_KEY_LENGTH = 16;
    
    /**
     * Store user secret key
     * @var string $secretKey
     */
    private $secretKey;
    
    /**
     * Base 32 alphabet
     * https://en.wikipedia.org/wiki/Base32#RFC_4648_Base32_alphabet
     * @var array $base32Chars
     */
    private $base32Chars = array(
        'A','B','C','D','E','F','G','H', // 7
        'I','J','K','L','M','N','O','P', // 15
        'Q','R','S','T','U','V','W','X', // 23
        'Y','Z','2','3','4','5','6','7', // 31
        '=' // padding character
    );

    /**
     * Constructor.
     *
     * @param string $secretKey Base32 Secret key
     * @return void
     */
    public function __construct($secretKey = null)
    {
        $this->secretKey = $secretKey;
        if(is_null($this->secretKey))
        {
            $this->secretKey = $this->generateSecretKey();
        }
    }

    /**
     * Get Secret key.
     *
     * @return string
     */
    public function getSecretKey()
    {
        return $this->secretKey;
    }

    /**
     * Get QRCode url from google.
     *
     * @param string  $username Client username
     * @param integer $size     QRCode image size in pixels
     * @param string  $issuer   Name of issuer
     * @return string
     */
    public function getQRCodeUrl($username, $size = 200, $issuer = 'Codific')
    {
        $params = array('secret' => $this->getSecretKey(), 'issuer' => $issuer);
        return str_replace(array('{chs}','{chl}'), 
                array($size . 'x' . $size,urlencode('otpauth://totp/' . $username . '?' . http_build_query($params))), static::API_URL);
    }

    /**
     * Get code based on secret key.
     *
     * @param integer $timeSlice On that sliced time will provide new code ( default = 30sec ).
     * @return string
     */
    private function getCode($timeSlice = null)
    {
        $secretKey = $this->base32Decode($this->secretKey);
        if($timeSlice === null) $timeSlice = $this->getTimeIndex();
        $time = str_pad(pack("N*", $timeSlice), 8, chr(0), STR_PAD_LEFT);
        $hash = hash_hmac('SHA1', $time, $secretKey, true);
        $offset = ord(substr($hash, - 1)) & 0x0F;
        $value = $this->hashToInt($hash, $offset) & 0x7FFFFFFF;
        $modulo = pow(10, static::CODE_LENGTH);
        return str_pad($value % $modulo, static::CODE_LENGTH, '0', STR_PAD_LEFT);
    }

    /**
     * Check if the code is correct.
     * This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now.
     *
     * @param string  $code        Code to verify.
     * @param integer $discrepancy This is the allowed time drift in 30 second units (8 means 4 minutes before or after).
     * @return bool
     */
    public function verifyCode($code, $discrepancy = 1)
    {
        $currentTimeSlice = $this->getTimeIndex();
        for($i = - $discrepancy; $i <= $discrepancy; $i ++)
            if($this->getCode($currentTimeSlice + $i) == $code) return true;
        return false;
    }

    /**
     * Get sliced time (Unix based time).
     * On that time will be generate every new code.
     * So here will be on each 30 seconds.
     *
     * @return integer
     */
    private function getTimeIndex()
    {
        return floor(time() / 30);
    }

    /**
     * Generate random Secret key.
     *
     * @return string
     */
    private function generateSecretKey()
    {
        $base32Chars = $this->base32Chars;
        unset($base32Chars[32]);
        $secretKey = '';
        for($i = 0; $i < static::SECRET_KEY_LENGTH; $i ++)
        {
            $secretKey .= $base32Chars[array_rand($base32Chars)];
        }
        return $secretKey;
    }

    /**
     * Convert HMAC hash to integer.
     *
     * @param string  $hash   Hash
     * @param integer $offset Offset
     * @return integer
     */
    private function hashToInt($hash, $offset)
    {
        $hashPart = substr($hash, $offset, 4);
        $value = unpack("N", $hashPart);
        return $value[1];
    }

    /**
     * Base32 Decoder according to RFC 4648
     *
     * @param string $string Base32 string
     * @return bool|string
     */
    private function base32Decode($string)
    {
        if(empty($string)) return '';
        $base32charsFlipped = array_flip($this->base32Chars);
        $paddingCharCount = substr_count($string, $this->base32Chars[32]);
        $allowedValues = array(6,4,3,1,0);
        if(! in_array($paddingCharCount, $allowedValues)) return false;
        for($i = 0; $i < 4; $i ++)
        {
            if($paddingCharCount == $allowedValues[$i] &&
                     substr($string, - ($allowedValues[$i])) != str_repeat($this->base32Chars[32], $allowedValues[$i])) return false;
        }
        $string = str_replace('=', '', $string);
        $string = str_split($string);
        $binaryString = "";
        for($i = 0; $i < count($string); $i = $i + 8)
        {
            $x = "";
            if(! in_array($string[$i], $this->base32Chars)) return false;
            for($j = 0; $j < 8; $j ++)
            {
                $x .= str_pad(base_convert(@$base32charsFlipped[@$string[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            for($z = 0; $z < count($eightBits); $z ++)
            {
                $binaryString .= (($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48) ? $y : "";
            }
        }
        return $binaryString;
    }
}