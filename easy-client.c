/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 * Copyright (C) 2011      Adam Laurie
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */

/**
 * @file nfc-mfclassic.c
 * @brief MIFARE Classic manipulation example
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <string.h>
#include <ctype.h>

#include <nfc/nfc.h>

#include "mifare.h"
#include "nfc-utils.h"

#include "easytool.h"

#define DO_NOT_ACCESS 	0x01 

static bool is_debug = false; 
static bool is_addv = false; 

static nfc_context *context;
static nfc_device *pnd;
static nfc_target nt;
static mifare_param mp;
static eTag e; 
static uint8_t uiBlocks;
static uint8_t keysA[][6] = {
	{ 0x7d, 0xb3, 0x6b, 0x71, 0x61, 0x6b }, 
	{ 0x20, 0x07, 0x07, 0x31, 0xab, 0xcd }, 
	{ 0xd9, 0x42, 0x49, 0xe4, 0x89, 0x58 }, 
	{ 0x2a, 0xe4, 0xc7, 0xe3, 0x74, 0x44 }, 
	{ 0x29, 0x75, 0x3d, 0xc7, 0xa6, 0xb5 }, 
	{ 0x57, 0x11, 0x52, 0xfa, 0xb0, 0x77 }, 
	{ 0xbb, 0xf4, 0x42, 0xdc, 0xaf, 0x7b }, 
	{ 0x30, 0xd2, 0xb6, 0x5d, 0xc3, 0xe3 }, 
	{ 0x2c, 0xf1, 0xa6, 0xc3, 0xae, 0xac }, 
	{ 0x88, 0xbd, 0xdc, 0x64, 0x43, 0x80 }, 
	{ 0x6c, 0xa0, 0xd8, 0x18, 0xcd, 0x81 }, 
	{ 0xae, 0x4c, 0xf8, 0x77, 0xa0, 0xa7 }, 
	{ 0x32, 0x02, 0xfa, 0x4e, 0x68, 0x1e }, 
	{ 0xd9, 0xad, 0xd5, 0xa5, 0xd0, 0x2f }, 
	/* { 0xfa, 0x8c, 0x93, 0xe8, 0x5d, 0xe5 }, */
	{ 0x06, 0x00, 0x00, 0x00, 0xf9, 0xff }, 
	{ 0xac, 0xe0, 0x4a, 0x3c, 0xd4, 0x2c }, 
	};

static uint8_t keysB[][6] = {
	{ 0x9f, 0x62, 0xe7, 0x05, 0x71, 0xac }, 	
	{ 0xff, 0xbb, 0x20, 0x07, 0x08, 0x01 }, 
	{ 0x84, 0x3d, 0x5d, 0x08, 0x4e, 0x59 }, 
	{ 0x80, 0xea, 0xb9, 0x7c, 0x2c, 0x6a }, 
	{ 0x75, 0x3e, 0x99, 0xbb, 0x53, 0x0f }, 
	{ 0x70, 0xd4, 0xd2, 0x42, 0x70, 0xe0 }, 
	{ 0x4a, 0x9c, 0x44, 0xbc, 0xb1, 0x22 }, 
	{ 0x70, 0x86, 0x9f, 0x14, 0x30, 0xc1 }, 
	{ 0x99, 0x4c, 0x51, 0xc1, 0x8b, 0x19 }, 
	{ 0xf9, 0x91, 0xcf, 0x59, 0x88, 0x91 }, 
	{ 0x0a, 0xbe, 0xd6, 0x39, 0xc2, 0x3c }, 
	{ 0xaf, 0xc6, 0xd6, 0x04, 0x0c, 0x6f }, 
	{ 0x54, 0xcc, 0x41, 0x43, 0x05, 0x98 }, 
	{ 0xc8, 0xb4, 0xd0, 0xbd, 0xee, 0x62 }, 
	/* { 0x9c, 0xc5, 0x94, 0x87, 0x32, 0x96 }, */
	{ 0x00, 0x00, 0x00, 0xff, 0x00, 0xff }, 
	{ 0x98, 0x3c, 0xc9, 0x60, 0x62, 0xc8 }, 
	}; 

static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

#define MAX_FRAME_LEN 264

static  bool
is_trailer_block(uint32_t uiBlock)
{
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock + 1) % 4 == 0);
  else
    return ((uiBlock + 1) % 16 == 0);
}

static  bool
authenticate(uint32_t uiBlock, bool isTypeA)
{
  mifare_cmd mc;

  // Set the authentication information (uid)
  memcpy(mp.mpa.abtAuthUid, nt.nti.nai.abtUid + nt.nti.nai.szUidLen - 4, 4);

  // Should we use key A or B?
  mc = (isTypeA)?MC_AUTH_A:MC_AUTH_B;

  int uiSecs = (uiBlocks + 1) / 4; 

  if(isTypeA) memcpy(mp.mpa.abtKey, keysA[uiSecs - uiBlock / 4 - 1], 6);
  else memcpy(mp.mpa.abtKey, keysB[uiSecs - uiBlock / 4 - 1], 6);
  if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp)) return true;
  nfc_initiator_select_passive_target(pnd, nmMifare, nt.nti.nai.abtUid, nt.nti.nai.szUidLen, NULL);

  return false;
}

static bool
write_block(uint32_t uiBlock, uint8_t* data, bool isTypeA)
{ 
  if(is_trailer_block(uiBlock)) return false; 
  mifare_param mpw; 
  mifare_cmd mc = MC_WRITE; 
  memcpy(mpw.mpd.abtData, data, 16); 

  if(!authenticate(uiBlock, isTypeA)) return false; 
  if(!nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mpw)) return false; 

  return true; 
}

static bool 
easy_add_value(uint8_t val) 
{
  uint8_t data[16] = { 0x00 }; 
  memcpy(data, e.balblk, 16); 

  data[0]+=val; 
  data[8]+=val;  
  data[4]-=val; //TODO: Do it Smart, please. 
  if(!write_block(TB_BAL, data, false) || !write_block(TB_BAL + 1, data, false)) return false; 

  memcpy(data, e.tran[e.current_tran_idx], 16); 
  data[6]-=val; 
  data[8]+=val; //TODO: Do it Smart, please. 

  if(!write_block(e.latest_tran, data, false)) return false; 

  memcpy(data, e.ltran, 16); 
  data[6]-=val; 
  data[8]+=val; //TODO: Do it Smart, please. 

  if(!write_block(TB_LATEST_TRAN, data, false)) return false; 

  return true; 
}

static  bool
parse_card()
{
  e.logcount = 0; e.current_tran = 0; 
  int32_t iBlock;
  bool    bFailure = false;

  //printf("Reading out %d blocks\n", uiBlocks + 1);
  // Read the card from end to begin
  for (iBlock = uiBlocks; iBlock >= 0; iBlock--) {
    // Authenticate everytime we reach a trailer block
    if(is_debug) printf("  0x%02x : ", iBlock);
    if (iBlock / 4 == DO_NOT_ACCESS) { if(is_debug) printf("!\n"); continue; }
    if (is_trailer_block(iBlock)) {
      if (bFailure) {
        // When a failure occured we need to redo the anti-collision
        if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
          printf("!\nError: tag was removed\n");
          return false;
        }
        bFailure = false;
      }

      fflush(stdout);

      // Try to authenticate for the current sector
      if (!authenticate(iBlock, false)) {
        printf("!\nError: authentication failed for block 0x%02x\n", iBlock);
        return false;
      }
      // Try to read out the trailer
      if (nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
    	  if(is_debug) print_hex(mp.mpd.abtData, 16);
	  parserights(&e, uiBlocks / 4, mp.mpd.abtData); 
      } else {
        printf("!\nfailed to read trailer block 0x%02x\n", iBlock);
        bFailure = true;
      }
    } else {
      // Make sure a earlier readout did not fail
      if (!bFailure) {
        // Try to read out the data block
        if (nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
        	if(is_debug) print_hex(mp.mpd.abtData, 16);
		parseTag(&e, iBlock, mp.mpd.abtData); 
        } else {
          printf("!\nError: unable to read block 0x%02x\n", iBlock);
          bFailure = true;
        }
      }
    }
    if ( bFailure )
      return false;
  }
  fflush(stdout);

  return true;
}

void 
usage() 
{
  printf("Usage: easy-client <options>\n"); 
  printf("options: \n"); 
  printf("-r : act as a easycard reader\n"); 
  printf("-a : add-value process\n\n"); 
}

void 
parseopts(const char* arg) 
{
  const char* rflag = "-r"; 
  const char* aflag = "-a"; 

  if(strcmp(arg, rflag) == 0) is_addv = false; 
  else if(strcmp(arg, aflag) == 0) is_addv = true; 
  else { usage(); exit(EXIT_FAILURE); }

}

int
main(int argc, const char *argv[])
{
  if (argc < 2) {
    usage(); 
    exit(EXIT_FAILURE);   
  } 

  parseopts(argv[1]);  

  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

// Try to open the NFC reader
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  };

// Let the reader only try once to find a tag
  if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
// Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
  if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Configure the CRC
  if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

// Try to find a MIFARE Classic tag
  if (select_target(pnd, &nt) <= 0) {
    printf("Error: no tag was found\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
// Test if we are dealing with a MIFARE compatible tag
  if ((nt.nti.nai.btSak & 0x08) == 0) {
    printf("Warning: tag is probably not a MFC!\n");
  }

  printf("Found MIFARE Classic card:\n");
  nt.nm = nmMifare;
  print_nfc_target(&nt, false);


// Guessing size
  if ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x02)
// 4K
    uiBlocks = 0xff;
  else if ((nt.nti.nai.btSak & 0x01) == 0x01)
// 320b
    uiBlocks = 0x13;
  else
// 1K/2K, checked through RATS
    uiBlocks = 0x3f;

    printf("Guessing size: seems to be a %i-byte card\n", (uiBlocks + 1) * 16);

  if (parse_card()) {
	printf("Done, %d blocks read.\n", uiBlocks + 1);
	fflush(stdout);
  }

  if(is_addv) if(!easy_add_value(0xff) || !parse_card()) printf("Failed Add Value!!\n");    

  printTag(&e); 

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
