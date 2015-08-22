#include "easytool.h" 

void 
parseTag(eTag* e, uint8_t uiBlock, uint8_t* data) {

	switch (uiBlock) {
		case TB_BAL: 
			e->bal = parse_hex(data, 4); 
			memcpy(e->balblk, data, 16); 
			break; 

		case TB_ADDV: 
			memcpy(e->addv, data, 16); 
			break; 

		case TB_TRANS: 
			e->trans = parse_hex(data, 2); 
			break; 

		case TB_LATEST_TRAN: 
			memcpy(e->ltran, data, 16); 
			break; 

		case TB_VAL: 
			memcpy(e->val, data + 1, 4); 
			break; 

	}

	uint8_t uiSec = uiBlock / 4; 
	switch (uiSec) {
		//case TS_TRAN3: 
		case TS_TRAN4: 
		case TS_TRAN5: 
			if(e->logcount < log_buf) {  
				if(data[0] > e->current_tran) {  
					e->current_tran = data[0]; 
					e->current_tran_idx = e->logcount; 
					e->latest_tran = uiBlock; 
				}
				memcpy(e->tran[e->logcount], data, 16); 				
			}
			e->logcount+=1; 
			break; 

	}
}

void parserights(eTag* e, uint8_t uiSec, uint8_t* data) { 

	e->rights[uiSec][0] = ((data[7] & 0x10)>>4) | ((data[8] & 0x1)<<1) | ((data[8] & 0x10)>>2);
	e->rights[uiSec][1] = ((data[7] & 0x20)>>5) | ((data[8] & 0x2)<<0) | ((data[8] & 0x20)>>3);
	e->rights[uiSec][2] = ((data[7] & 0x40)>>6) | ((data[8] & 0x4)>>1) | ((data[8] & 0x40)>>4);
	e->rights[uiSec][3] = ((data[7] & 0x80)>>7) | ((data[8] & 0x8)>>2) | ((data[8] & 0x80)>>5);

}

uint8_t getright(const eTag* e, uint8_t uiBlock) { return e->rights[uiBlock / 4][uiBlock % 4]; } 

void 
printTag(const eTag* e) { 
	char buf[256]; 

	char mrtstat[256][64]; //TODO Checking Gap...

	strncpy(mrtstat[7], "SongShan Airport", 64); 
	strncpy(mrtstat[8], "Zhongshan Junior High School", 64); 
	strncpy(mrtstat[9], "Nanjing E. Rd", 64); 
	strncpy(mrtstat[10], "Zhongxiao Fuxing", 64); 
	strncpy(mrtstat[11], "Daan", 64); 
	strncpy(mrtstat[12], "Technology Building", 64); 
	strncpy(mrtstat[13], "Liuzhangli", 64); 
	strncpy(mrtstat[14], "Linguang", 64); 
	strncpy(mrtstat[15], "Xinhai", 64); 
	strncpy(mrtstat[16], "Wanfang Hospital", 64); 
	strncpy(mrtstat[17], "Wanfang Community", 64); 
	strncpy(mrtstat[18], "Muzha", 64); 
	strncpy(mrtstat[19], "Taipei Zoo", 64); 
	strncpy(mrtstat[21], "Dazhi", 64); 
	strncpy(mrtstat[22], "Jiannan Rd", 64); 
	strncpy(mrtstat[23], "Xihu", 64); 
	strncpy(mrtstat[24], "Gangqian", 64); 
	strncpy(mrtstat[25], "Wende", 64); 
	strncpy(mrtstat[26], "Neihu", 64); 
	strncpy(mrtstat[27], "Dahu Park", 64); 
	strncpy(mrtstat[28], "Huzhou", 64); 
	strncpy(mrtstat[29], "Donghu", 64); 
	strncpy(mrtstat[30], "Nangang Software Park", 64); 
	strncpy(mrtstat[31], "Taipei Nangang Exhibition Center", 64); 
	strncpy(mrtstat[32], "Xiaobitan", 64); 
	strncpy(mrtstat[33], "Xindian", 64); 
	strncpy(mrtstat[34], "Xindian District Office", 64); 
	strncpy(mrtstat[35], "Qizhang", 64); 
	strncpy(mrtstat[36], "Dapinglin", 64); 
	strncpy(mrtstat[37], "Jingmei", 64); 
	strncpy(mrtstat[38], "Wanlong", 64); 
	strncpy(mrtstat[39], "Gongguan", 64); 
	strncpy(mrtstat[40], "Taipower Building", 64); 
	strncpy(mrtstat[41], "Guting", 64); 
	strncpy(mrtstat[42], "Chiang Kai-Shek Memorial Hall", 64); 
	strncpy(mrtstat[43], "Xiaonanmen", 64); 
	strncpy(mrtstat[45], "Dingxi", 64); 
	strncpy(mrtstat[46], "Yongan Market", 64); 
	strncpy(mrtstat[47], "Jingan", 64); 
	strncpy(mrtstat[48], "Nanshijiao", 64); 
	strncpy(mrtstat[50], "NTU Hospital", 64); 
	strncpy(mrtstat[51], "Taipei Main Station", 64); 
	strncpy(mrtstat[52], "Taipei Main Station", 64); 
	strncpy(mrtstat[53], "Zhongshan", 64); 
	strncpy(mrtstat[54], "Shuanglian", 64); 
	strncpy(mrtstat[55], "Minquan W. Rd", 64); 
	strncpy(mrtstat[56], "Yuanshan", 64); 
	strncpy(mrtstat[57], "Jiantan", 64); 
	strncpy(mrtstat[58], "Shilin", 64); 
	strncpy(mrtstat[59], "Zhishan", 64); 
	strncpy(mrtstat[60], "Mingde", 64); 
	strncpy(mrtstat[61], "Shipai", 64); 
	strncpy(mrtstat[62], "Qilian", 64); 
	strncpy(mrtstat[63], "Qiyan", 64); 
	strncpy(mrtstat[64], "Beitou", 64); 
	strncpy(mrtstat[65], "Xinbeitou", 64); 
	strncpy(mrtstat[66], "Fuxinggang", 64); 
	strncpy(mrtstat[67], "Zhongyi", 64); 
	strncpy(mrtstat[68], "Guandu", 64); 
	strncpy(mrtstat[69], "Zhuwei", 64); 
	strncpy(mrtstat[70], "Hongshulin", 64); 
	strncpy(mrtstat[71], "Tamsui", 64); 
	strncpy(mrtstat[77], "Yongning", 64); 
	strncpy(mrtstat[78], "Tucheng", 64); 
	strncpy(mrtstat[79], "Haishan", 64); 
	strncpy(mrtstat[80], "Far Eastern Hospital", 64); 
	strncpy(mrtstat[81], "Fuzhong", 64); 
	strncpy(mrtstat[82], "Banqiao", 64); 
	strncpy(mrtstat[83], "Xinpu", 64); 
	strncpy(mrtstat[84], "Jiangzicui", 64); 
	strncpy(mrtstat[85], "Longshan Temple", 64); 
	strncpy(mrtstat[86], "Ximen", 64); 
	strncpy(mrtstat[88], "Shandao Temple", 64); 
	strncpy(mrtstat[89], "Zhongxiao Xinsheng", 64); 
	strncpy(mrtstat[91], "Zhongxiao Dunhua", 64); 
	strncpy(mrtstat[92], "Sun Yat-Sen Memorial Hall", 64); 
	strncpy(mrtstat[93], "Taipei City Hall", 64); 
	strncpy(mrtstat[94], "Yongchun", 64); 
	strncpy(mrtstat[95], "Houshanpi", 64); 
	strncpy(mrtstat[96], "Kunyang", 64); 
	strncpy(mrtstat[97], "Nangang", 64); 
	strncpy(mrtstat[99], "Xiangshan", 64); 
	strncpy(mrtstat[100], "Taipei 101/World Trade Center", 64); 
	strncpy(mrtstat[101], "Xinyi Anhe", 64); 
	strncpy(mrtstat[103], "Daan Park", 64); 
	strncpy(mrtstat[121], "Fu Jen University", 64); 
	strncpy(mrtstat[122], "Xinzhuang", 64); 
	strncpy(mrtstat[123], "Touqianzhuang", 64); 
	strncpy(mrtstat[124], "Xianse Temple", 64); 
	strncpy(mrtstat[125], "Sanchong", 64); 
	strncpy(mrtstat[126], "Cailiao", 64); 
	strncpy(mrtstat[127], "Taipei Bridge", 64); 
	strncpy(mrtstat[128], "Daqiaotou", 64); 
	strncpy(mrtstat[130], "Zhongshan Elementary School", 64); 
	strncpy(mrtstat[131], "Xingtian Temple", 64); 
	strncpy(mrtstat[132], "Songjiang Nanjing", 64); 
	strncpy(mrtstat[134], "Dongmen", 64); 
	strncpy(mrtstat[174], "Luzhou", 64); 
	strncpy(mrtstat[175], "Sanmin Senior High School", 64); 
	strncpy(mrtstat[176], "St. Ignatius High School", 64); 
	strncpy(mrtstat[177], "Sanhe Junior High School", 64); 
	strncpy(mrtstat[178], "Sanchong Elementary School", 64); 
	strncpy(mrtstat[179], "Huilong", 64); 
	strncpy(mrtstat[180], "Danfeng", 64); 
	
	printf("\n------------------------------ \n"); 
	printf("Information \n"); 
	printf("------------------------------ \n"); 
	printf("Balance: %d\n", e->bal); 
	printf("Used: %d time(s)\n", e->trans); 
	printf("\n"); 
	print_time(e->val, buf); 
	printf("Valid before: %s\n", buf); 

	printf("\n------------------------------ \n"); 
	printf("Recent Value-adding Log \n"); 
	printf("------------------------------ \n"); 
	print_time(e->addv + 1, buf); 
	printf("Date: %s\n", buf); 
	printf("Amount: %d \n", parse_hex(e->addv + 6, 1)); 

	printf("\n------------------------------ \n"); 
        printf("Transaction Log \n"); 
        printf("------------------------------ \n"); 
	uint8_t i = 0; 

	printf("#  Date\t\t\t%32s\t\tCost\tBal\n", "Stat"); 
	for(; i < logp; i++) { 
		printf("%d. ", i + 1); 
		print_time(e->tran[i] + 1, buf); 
		printf("%s ", buf); 
		switch(e->tran[i][10]) {
			case TP_MRT: 
				printf("%32s - ", mrtstat[e->tran[i][11]]); 
				if(e->tran[i][5] == 0x11) printf("leaving\t"); //TODO Checking Types 
				else printf("entering\t"); 
				break; 
			case TP_BUS: 
			default: 
				printf("\t\t\t\tTaipei Bus\t"); 
				break; 

		}
		int16_t bal = parse_hex(e->tran[i] + 8, 2); 
		printf("%d\t%d", e->tran[i][6], bal); 
		if(e->tran[i][0] == e->current_tran) printf("*"); 
		printf("\n"); 
	}

}
