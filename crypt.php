<?php
/**
 * cryptography kit (required php >= 5.1.2)
 * original code - ITNewbie, Inc.
 */
class crypt
{
	/**
	 * generate random string
	 * @static
	 * @param int  $length  - length of string
	 * @param bool $caps    - use latin capitals
	 * @param bool $letters - use the letters
	 * @param bool $numbers - use numbers
	 * @param bool $symbols - use common symbols
	 * @return string
	 */
	public static function rand($length = 32, $caps = true, $letters = true, $numbers = true, $symbols = true)
	{
		$random = array();
		$use = array();
		if ($length < 1)
			return '';
		if ($caps)
			$use[] = 0;
		if ($letters)
			$use[] = 1;
		if ($numbers)
			$use[] = 2;
		if ($symbols)
			$use[] = 3;
		$use_count = count($use) - 1;
		$index = 0;
		for ($i = 1; $i <= $length; $i++)
		{
			switch ($use[$index])
			{
				case 0:
					if (!isset($caps[0]))
						$caps = array(
							'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
							'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
						);
					shuffle($caps);
					$random[] = $caps[0];
					unset($caps[0]);
					break;
				case 1:
					if (!isset($letters[0]))
						$letters = array(
							'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
							'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
						);
					shuffle($letters);
					$random[] = $letters[0];
					unset($letters[0]);
					break;
				case 2:
					if (!isset($numbers[0]))
						$numbers = array(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
					shuffle($numbers);
					$random[] = $numbers[0];
					unset($numbers[0]);
					break;
				case 3:
					if (!isset($symbols[0]))
						$symbols = array(
							'-', '_', '^', '~', '@', '&', '|', '=', '+', ';', '!', ',', '$', "'", '"', ':',
							'<', '>', '`', '\\', '/', '(', ')', '{', '}', '[', ']', '.', '?', '%', '*', '#'
						);
					shuffle($symbols);
					$random[] = $symbols[0];
					unset($symbols[0]);
					break;
			}
			if ($index < $use_count)
				$index++;
			else
				$index = 0;
		}
		shuffle($random);
		return implode($random);
	}

	/**
	 * generate pbkdf2 hash
	 * @static
	 * @param string $password   - defined password
	 * @param string $salt       - defined salt
	 * @param bool   $binary     - generate binary data, or base64 encoded string
	 * @param int    $iterations - how many iterations to perform
	 * @param int    $keylength  - key length
	 * @param string $algorithm  - hashing algorithm
	 * @return bool|string
	 */
	public static function pbkdf2($password, $salt, $binary = true, $iterations = 999, $keylength = 32, $algorithm = 'sha256')
	{
		if (!in_array($algorithm, hash_algos()))
			return false;
		$derivedkey = '';
		for ($block = 1; $block <= ceil($keylength / strlen(hash($algorithm, null, true))); $block++):
			$ib = $b = hash_hmac($algorithm, $salt.pack('N', $block), $password, true);
			for ($i = 1; $i < $iterations; $i++)
				$ib ^= ($b = hash_hmac($algorithm, $b, $password, true));
			$derivedkey .= $ib;
		endfor;
		return $binary ? substr($derivedkey, 0, $keylength) : base64_encode(substr($derivedkey, 0, $keylength));
	}

	/**
	 * encryption
	 * @param mixed  $msg    - message/data
	 * @param string $k      - encryption key
	 * @param bool   $binary - base64 encode result
	 * @return bool|string   - iv+ciphertext+mac
	 */
	public static function encrypt($msg, $k, $binary = true)
	{
		if (!$td = mcrypt_module_open('rijndael-256', '', 'ctr', ''))
			return false;
		if (mcrypt_generic_init($td, $k, $iv = mcrypt_create_iv(32, MCRYPT_RAND)) !== 0)
			return false;
		$msg .= self::pbkdf2($msg = $iv.mcrypt_generic($td, serialize($msg)), $k, 1000, 32);
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
		return $binary ? $msg : base64_encode($msg);
	}

	/**
	 * decryption
	 * @param string $msg    - output from encrypt()
	 * @param string $k      - encryption key
	 * @param bool   $binary - base64 decode msg
	 * @return bool|string   - original data
	 */
	public static function decrypt($msg, $k, $binary = true)
	{
		if (!$binary)
			$msg = base64_decode($msg);
		if (!$td = mcrypt_module_open('rijndael-256', '', 'ctr', ''))
			return false;
		$iv = substr($msg, 0, 32);
		$mo = strlen($msg) - 32;
		$em = substr($msg, $mo);
		$msg = substr($msg, 32, strlen($msg) - 64);
		$mac = self::pbkdf2($iv.$msg, $k, 1000, 32);
		if ($em !== $mac)
			return false;
		if (mcrypt_generic_init($td, $k, $iv) !== 0)
			return false;
		$msg = unserialize(mdecrypt_generic($td, $msg));
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
		return $msg;
	}
}