/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike__Resources_Httpsstager64_Bin_v3_2_through_v4_x
{
	meta:
		desc="Cobalt Strike's resources/httpsstager64.bin signature for versions v3.2 to v4.x"
		rs1 = "109b8c55816ddc0defff360c93e8a07019ac812dd1a42209ea7e95ba79b5a573"
    author = "gssincla@google.com"
		
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for httpstager64 and httpsstager64 really only differ by the flags passed to WinInet API
  // and the inclusion of the InternetSetOptionA call. We will trigger off that API
	/*
		BA 1F 00 00 00    mov     edx, 1Fh
		6A 00             push    0
		68 80 33 00 00    push    3380h
		49 89 E0          mov     r8, rsp
		41 B9 04 00 00 00 mov     r9d, 4
		41 BA 75 46 9E 86 mov     r10d, InternetSetOptionA
	*/

	$InternetSetOptionA = {
			BA 1F 00 00 00
			6A 00
			68 80 33 00 00
			49 [2]
			41 ?? 04 00 00 00
			41 ?? 75 46 9E 86
		}	
	
	condition:
		$apiLocator and $InternetSetOptionA
}
