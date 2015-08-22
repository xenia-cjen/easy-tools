#ifndef _EASYTOOL_H_
#define _EASYTOOL_H_

#include <stdio.h>
#include <stdlib.h> 
#include <stdint.h>
#include <stdbool.h>

#include <string.h>

#include <nfc/nfc.h>
#include <err.h>

#include "nfc-utils.h" 

#define log_buf 		0x08 
#define logp			0x06

typedef enum {
	TB_BAL = 0x08,  
	TB_ADDV = 0x0a, 
	TB_TRANS = 0x0c, 
	TB_LATEST_TRAN = 0x0d,  
	TB_VAL = 0x3c

} tag_blk; 

typedef enum { 
	TS_TRAN3 = 0x03, 
	TS_TRAN4 = 0x04, 
	TS_TRAN5 = 0x05 
} tag_sec; 

typedef enum { 
	TP_MRT = 0x02, 
	TP_BUS = 0x11
} tran_type;  
	

typedef
struct {
	uint8_t logcount;
	uint8_t current_tran; // temporarily used. 

	uint8_t current_tran_idx; 

	int32_t bal; 
	uint32_t trans; 
	uint32_t latest_tran; 

	uint8_t balblk[16]; 
	uint8_t val[4]; 
	uint8_t addv[16]; 
	uint8_t ltran[16]; 
	uint8_t tran[log_buf][16]; 

	uint8_t rights[16][4]; 
} eTag; 

void parseTag(eTag* e, uint8_t uiSec, uint8_t* data); 
void printTag(const eTag* e); 
void parserights(eTag* e, uint8_t uiSec, uint8_t* data); 
uint8_t getright(const eTag* e, uint8_t uiBlock);  

#endif // _EASYTOOL_H_
