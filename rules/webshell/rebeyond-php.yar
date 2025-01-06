rule Detect_rebeyond_PHP_Code
{
    meta:
        description = "rebeyond_PHP"
        author = "l"

    strings:
        $pattern1 = /\$post\[\$i\]\s*=\s*\$post\[\$i\]\^\$key\[\$i\+1&15\];/
        $pattern2 = /openssl_(en|de)crypt\(\$post,\s*"AES128",\s*\$key\);/
        $pattern3 = /\$data\[\$i\]\s*=\s*\$data\[\$i\]\^\$key\[\$i\+1&15\];/
        $pattern4 = /openssl_(en|de)crypt\(\$data,\s*"AES128",\s*\$key\);/

    condition:
        ($pattern1 and $pattern2 and (@pattern2 - @pattern1 > 0) and (@pattern2 - @pattern1 <= 160))
	 or
	($pattern3 and $pattern4 and (@pattern4 - @pattern3 > 0) and (@pattern4 - @pattern3 <= 160))
}