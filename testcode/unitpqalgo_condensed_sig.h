/*
 * testcode/unitpqalgo_condensed_sig.h - MTL PQC Algorithm condensed signature
 * 
 *  
 *  Copyright (c) 2024, VeriSign, Inc.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted (subject to the limitations in the disclaimer
 *  below) provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of the copyright holder nor the names of its
 *      contributors may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 *  NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
 *  THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 *  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 *  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef MTL_CONDENSED_SIG_BUFFER
#define MTL_CONDENSED_SIG_BUFFER
uint8_t condensed_sig_buffer[] = {0x00,0x84,0x24,0x35,0x67,0x8f,0xba,0xd1,0x1a,0xf0,0x53,0x88,0xfd,0x03,0x5a,0xc0,
                                  0x7e,0x00,0x00,0x36,0xbd,0xb6,0xb3,0xb4,0x25,0xed,0x90,0x00,0x00,0x00,0x04,0x00,
                                  0x00,0x00,0x04,0x00,0x00,0x00,0x05,0x00,0x01,0x39,0x37,0x8d,0x03,0x35,0xe9,0xae,
                                  0xdf,0x6a,0xf0,0x99,0x73,0xb8,0x4a,0x1b,0x1c};
size_t  condensed_sig_buffer_len = 57;
#endif  /* MTL_CONDENSED_SIG_BUFFER */