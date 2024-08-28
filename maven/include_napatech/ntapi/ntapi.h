// $Id: ntapi.h 17202 2012-02-01 14:38:55Z ml $
/*
 * Copyright 2012 Napatech A/S. All rights reserved.
 * CONFIDENTIAL INFORMATION.
 * 
 * 1. Copying, modification, and distribution of this file, or executable
 * versions of the file, is governed by the terms of the agreement (such
 * as an SCLA or NDA) under which the file was made available. If no such
 * agreement is currently in force between You and Napatech A/S, you may
 * not copy, modify, or distribute this file.
 * 
 * 2. This source code is confidential information of Napatech A/S, and
 * as such, may not be distributed, except to or within Napatech A/S
 * customers under a current, executed NDA or equivalent confidentiality
 * agreement governing the distribution of confidential information.
 * 
 * 3. Redistributions of source code must retain this copyright notice,
 * list of conditions and the following disclaimer.
 * 
 * THIS SOFTWARE IS PROVIDED BY NAPATECH A/S ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NAPATECH A/S OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *
 * This header file contains NTAPI function prototypes
 */
#ifndef __NTAPI_H__
#define __NTAPI_H__

/**
 * @brief Initializes the NTAPI library
 *
 * This function <em>must</em> be called prior to any other
 * NTAPI function. It will initialize the NTAPI library and perform
 * compatibility checks based on the version applied.
 * The version is used to indicate to NTAPI what version of the API the
 * application supports and will enable NTAPI to act on this and adapt to that
 * version of the API if possible. This means that if the application is compiled
 * to e.g. version 1 of the API and the current API is version 9, NT_Init will
 * check if it is possible to enable backward compatibility to version 1 and
 * thereby allow the application to run on a version 9 library with version 1 API.
 *
 * @note This function <b>must</b> be called before any threads have been created.
 * It is vital that it executed from a single threaded context.
 *
 * @param[in] version  The version that the calling application supports
 *
 * @retval  NT_SUCCESS     Success
 * @retval  !=0            Error
 */
int NT_Init(uint32_t version);

/**
 * @brief Closes down the NTAPI library
 *
 * @retval  NT_SUCCESS     Success
 */
int NT_Done(void);

/**
 * @brief Explains an error code returned by NTAPI functions
 *
 * This function will convert the error code to text
 *
 * @param[in]     error  The error code to explain
 * @param[in,out] buf    Location of the explanation
 * @param[in]     buflen The buffer length to prevent buffer overrun
 *
 * @retval  NT_SUCCESS     Success
 * @retval  !=0            Error
 */
char *NT_ExplainError(int error, char *buf, uint32_t buflen);

#endif // __NTAPI_H__
