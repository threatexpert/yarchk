

rule rebeyondJavaClass_jspfile
{
    meta:
        description = "冰蝎jsp webshell"
        author = "l"
        last_modified = "2024-12-25"
        malware_family = "冰蝎"
        
    strings:
        $pattern = { 73 65 73 73 69 6F 6E 2E 70 75 74 56 61 6C 75 65 28 22 75 22 2C 6B 29 3B 43 69 70 68 65 72 20 63 3D 43 69 70 68 65 72 2E 67 65 74 49 6E 73 74 61 6E 63 65 28 22 41 45 53 22 29 3B 63 2E 69 6E 69 74 28 32 2C 6E 65 77 20 53 65 63 72 65 74 4B 65 79 53 70 65 63 28 [1-32] 2E 67 65 74 42 79 74 65 73 28 29 2C 22 41 45 53 22 29 29 3B 6E 65 77 20 55 28 74 68 69 73 2E 67 65 74 43 6C 61 73 73 28 29 2E 67 65 74 43 6C 61 73 73 4C 6F 61 64 65 72 28 29 29 }

    condition:
        all of them
}

rule rebeyondJavaClass_ClassLoaderU
{
    meta:
        description = "冰蝎jsp webshell"
        author = "l"
        last_modified = "2024-12-25"
        malware_family = "冰蝎"
        
    strings:
        $pattern = { CA FE BA BE 00 00 00 34 00 23 07 00 02 01 00 16 6F 72 67 2F 61 70 61 63 68 65 2F 6A 73 70 2F [5-64] 24 55 07 00 04 01 00 15 6A 61 76 61 2F 6C 61 6E 67 2F 43 6C 61 73 73 4C 6F 61 64 65 72 01 00 06 74 68 69 73 24 30 01 00 16 4C 6F 72 67 2F 61 70 61 63 68 65 2F 6A 73 70 2F [5-64] 3B 01 00 06 3C 69 6E 69 74 3E 01 00 30 28 4C 6F 72 67 2F 61 70 61 63 68 65 2F 6A 73 70 2F [5-64] 3B 4C 6A 61 76 61 2F 6C 61 6E 67 2F 43 6C 61 73 73 4C 6F 61 64 65 72 3B 29 56 01 00 04 43 6F 64 65 09 00 01 00 0B 0C 00 05 00 06 0A 00 03 00 0D 0C 00 07 00 0E 01 00 1A 28 4C 6A 61 76 61 2F 6C 61 6E 67 2F 43 6C 61 73 73 4C 6F 61 64 65 72 3B 29 56 01 00 0F 4C 69 6E 65 4E 75 6D 62 65 72 54 61 62 6C 65 01 00 12 4C 6F 63 61 6C 56 61 72 69 61 62 6C 65 54 61 62 6C 65 01 00 04 74 68 69 73 01 00 18 4C 6F 72 67 2F 61 70 61 63 68 65 2F 6A 73 70 2F [5-64] 24 55 3B 01 00 01 63 01 00 17 4C 6A 61 76 61 2F 6C 61 6E 67 2F 43 6C 61 73 73 4C 6F 61 64 65 72 3B 01 00 01 67 01 00 15 28 5B 42 29 4C 6A 61 76 61 2F 6C 61 6E 67 2F 43 6C 61 73 73 3B 0A 00 03 00 18 0C 00 19 00 1A 01 00 0B 64 65 66 69 6E 65 43 6C 61 73 73 01 00 17 28 5B 42 49 49 29 4C 6A 61 76 61 2F 6C 61 6E 67 2F 43 6C 61 73 73 3B 01 00 01 62 01 00 02 5B 42 01 00 0A 53 6F 75 72 63 65 46 69 6C 65 01 00 0A [5-64] 2E 6A 61 76 61 01 00 0C 49 6E 6E 65 72 43 6C 61 73 73 65 73 07 00 21 01 00 14 6F 72 67 2F 61 70 61 63 68 65 2F 6A 73 70 2F [5-64] 01 00 01 55 00 20 00 01 00 03 00 00 00 01 10 10 00 05 00 06 00 00 00 02 00 00 00 07 00 08 00 01 00 09 00 00 00 47 00 02 00 03 00 00 00 0B 2A 2B B5 00 0A 2A 2C B7 00 0C B1 00 00 00 02 00 0F 00 00 00 0E 00 03 00 00 00 1A 00 05 00 1B 00 0A 00 1C 00 10 00 00 00 16 00 02 00 00 00 0B 00 11 00 12 00 00 00 00 00 0B 00 13 00 14 00 02 00 01 00 15 00 16 00 01 00 09 00 00 00 3D 00 04 00 02 00 00 00 09 2A 2B 03 2B BE B7 00 17 B0 00 00 00 02 00 0F 00 00 00 06 00 01 00 00 00 1F 00 10 00 00 00 16 00 02 00 00 00 09 00 11 00 12 00 00 00 00 00 09 00 1B 00 1C 00 01 00 02 00 1D 00 00 00 02 00 1E 00 1F 00 00 00 0A 00 01 00 01 00 20 00 22 00 00 }

    condition:
        all of them
}


rule rebeyondJavaClass_Echo
{
    meta:
        description = "冰蝎jsp webshell"
        author = "l"
        last_modified = "2024-12-25"
        malware_family = "冰蝎"
        
    strings:
        $pattern = { CA FE BA BE [4-100] 00 10 6A 61 76 61 2F 6C 61 6E 67 2F 4F 62 6A 65 63 74 07 00 03 01 00 09 45 63 68 6F 2E 6A 61 76 61 01 00 07 63 6F 6E 74 65 6E 74 01 00 12 4C 6A 61 76 61 2F 6C 61 6E 67 2F 53 74 72 69 6E 67 3B }

    condition:
        all of them
}

rule rebeyondJavaClass_BasicInfo
{
    meta:
        description = "冰蝎jsp webshell"
        author = "l"
        last_modified = "2024-12-25"
        malware_family = "冰蝎"
        
    strings:
        $pattern = { CA FE BA BE [4-100] 00 10 6A 61 76 61 2F 6C 61 6E 67 2F 4F 62 6A 65 63 74 07 00 03 01 00 0E 42 61 73 69 63 49 6E 66 6F 2E 6A 61 76 61 01 00 13 6A 61 76 61 2F 75 74 69 6C 2F 4D 61 70 24 45 6E 74 72 79 07 00 06 01 00 0D 6A 61 76 61 2F 75 74 69 6C 2F 4D 61 70 07 00 08 01 00 05 45 6E 74 72 79 01 00 08 77 68 61 74 65 76 65 72 01 00 12 4C 6A 61 76 61 2F 6C 61 6E 67 2F 53 74 72 69 6E 67 3B }

    condition:
        all of them
}

rule rebeyondJavaClass_RealCMD
{
    meta:
        description = "冰蝎jsp webshell"
        author = "l"
        last_modified = "2024-12-25"
        malware_family = "冰蝎"
        
    strings:
        $pattern = { CA FE BA BE [4-100] 10 6A 61 76 61 2F 6C 61 6E 67 2F 4F 62 6A 65 63 74 07 00 03 01 00 12 6A 61 76 61 2F 6C 61 6E 67 2F 52 75 6E 6E 61 62 6C 65 07 00 05 01 00 0C 52 65 61 6C 43 4D 44 2E 6A 61 76 61 01 00 08 62 61 73 68 50 61 74 68 01 00 12 4C 6A 61 76 61 2F 6C 61 6E 67 2F 53 74 72 69 6E 67 3B 01 00 04 74 79 70 65 01 00 03 63 6D 64 01 00 08 77 68 61 74 65 76 65 72 }

    condition:
        all of them
}

rule rebeyondJavaClass_MemShell
{
    meta:
        description = "冰蝎jsp webshell"
        author = "l"
        last_modified = "2024-12-25"
        malware_family = "冰蝎"
        
    strings:
        $pattern = { CA FE BA BE [4-100] 00 10 6A 61 76 61 2F 6C 61 6E 67 2F 4F 62 6A 65 63 74 07 00 03 01 00 0D 4D 65 6D 53 68 65 6C 6C 2E 6A 61 76 61 01 00 08 77 68 61 74 65 76 65 72 01 00 12 4C 6A 61 76 61 2F 6C 61 6E 67 2F 53 74 72 69 6E 67 3B }

    condition:
        all of them
}


rule rebeyondJavaClass_FileOperation
{
    meta:
        description = "冰蝎jsp webshell"
        author = "l"
        last_modified = "2024-12-25"
        malware_family = "冰蝎"
        
    strings:
        $pattern = { CA FE BA BE [4-100] 00 10 6A 61 76 61 2F 6C 61 6E 67 2F 4F 62 6A 65 63 74 07 00 03 01 00 12 46 69 6C 65 4F 70 65 72 61 74 69 6F 6E 2E 6A 61 76 61 01 00 04 6D 6F 64 65 01 00 12 4C 6A 61 76 61 2F 6C 61 6E 67 2F 53 74 72 69 6E 67 3B [3-32] 00 04 70 61 74 68 [3-64] 00 07 63 6F 6E 74 65 6E 74 }

    condition:
        all of them
}



rule rebeyondJavaClass_Loader
{
    meta:
        description = "冰蝎jsp webshell"
        author = "l"
        last_modified = "2024-12-25"
        malware_family = "冰蝎"
        
    strings:
        $pattern = { CA FE BA BE [4-100] 00 10 6A 61 76 61 2F 6C 61 6E 67 2F 4F 62 6A 65 63 74 07 00 03 01 00 0B 4C 6F 61 64 65 72 2E 6A 61 76 61 01 00 07 6C 69 62 50 61 74 68 01 00 12 4C 6A 61 76 61 2F 6C 61 6E 67 2F 53 74 72 69 6E 67 3B [2-64] 00 07 52 65 71 75 65 73 74 01 00 12 4C 6A 61 76 61 2F 6C 61 6E 67 2F 4F 62 6A 65 63 74 3B 01 00 08 52 65 73 70 6F 6E 73 65 01 00 07 53 65 73 73 69 6F 6E }

    condition:
        all of them
}
