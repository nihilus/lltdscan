void hexdump(const uint8_t*p, int len){
	int i;
	for(i=0; i<len; i++){
		printf("%02x ",p[i]);
	}
//	puts("");
}

void lltd_dump_tlv(const uint8_t*p, int len){
	char*desc=NULL;
	char buf[0x40];
	char comment[0x100];
	*buf=0;
	*comment=0;
	switch(*p){
		case 0x01: desc="Host ID"; break;
		case 0x02: desc="Charact."; 
			if(p[2]&0x80) strcat(comment, "NAT-public, ");
			if(p[2]&0x40) strcat(comment, "NAT-private, ");
			if(p[2]&0x20) strcat(comment, "full-duplex, ");
			if(p[2]&0x10) strcat(comment, "has_HTTP, ");
			if(p[2]&0x08) strcat(comment, "loopback, ");
			if(*comment){
				comment[strlen(comment)-2] = 0;
			}
			break;
		case 0x03: desc="Media"; 
			if(p[5] ==  6) strcpy(comment,"Ethernet");
			if(p[5] == 71) strcpy(comment,"802.11");
			break;
		case 0x07: desc="IPv4"; break;
		case 0x08: desc="IPv6"; break;
		case 0x0A: desc="Perf.cntr"; break;
		case 0x0C: desc="Link speed"; 
			u_int32_t spd = (p[2]<<24) + (p[3]<<16) + (p[4]<<8) + p[5];
			if( spd >= 10000){
				snprintf(buf, sizeof(buf)/sizeof(buf[0]), "%d Mbit/s", spd/10000);
			} else {
				snprintf(buf, sizeof(buf)/sizeof(buf[0]), "%d kbit/s", spd/10);
			}
			break;
		case 0x0F: desc="Name"; break;
		case 0x14: desc="QoS"; 
			if(p[2]&0x80) strcat(comment, "qWave-enabled, ");
			if(p[2]&0x40) strcat(comment, "802.1q-support, ");
			if(p[2]&0x20) strcat(comment, "802.1p-support, ");
			if(*comment){
				comment[strlen(comment)-2] = 0;
			}
			break;
	}
	if(!desc) snprintf(desc=buf, sizeof(buf)/sizeof(buf[0]), "0x%02x", *p);
	printf("  %10s: ", desc);
	if( *buf && desc!=buf)
		printf("%s",buf);
	else
		hexdump(p+2,len);
	if( *comment ){
		printf("\t(%s)", comment);
	}
	puts("");
}

uint8_t* lltd_extract_name(const uint8_t*p){
	uint8_t l;
	static uint8_t namebuf[0x40];

	while(*p){
		l = p[1];
		if( *p == 0x0F ){
			int namelen = l/2;
			if( namelen >= sizeof(namebuf) ){
				namelen = sizeof(namebuf) - 1;
			}
			p += 2;
			// name is in UTF8
			char *pbuf;
			for(pbuf=namebuf; namelen>0; p++, namelen--){
				*pbuf++ = *p++;
			}
			*pbuf = 0;
			return namebuf;
		}
		p += l + 2;
	}
	return NULL;
}

uint8_t* lltd_extract_unicode_name(const uint8_t*p){
	uint8_t l;
	static uint8_t namebuf[0x40];

	while(*p){
		l = p[1];
		if( *p == 0x0F ){
			int namelen = l/2;
			p += 2;
			uint8_t *pbuf;
			/* convert ucs-2le to utf-8 */
			/* FIXME: maybe, this is utf-16le, not ucs-2le? */
			for(pbuf=namebuf; namelen>0; namelen--){
				unsigned short ch = *p++;
				ch |= ((unsigned short)*p++) << 8;
				if(ch >= 0xd800 && ch <= 0xdfff){
					static int once;
					if(!once++)
						fprintf(stderr, "Warning: utf-16 unsupported, please report\n");
				}
				if(ch >= 0x800){
					if(pbuf - namebuf + 3 >= sizeof(namebuf))
						break;
					*pbuf++ = 0xe0 | ((ch >> 12) & 0x0f);
					*pbuf++ = 0x80 | ((ch >>  6) & 0x3f);
					*pbuf++ = 0x80 | ( ch        & 0x3f);
					continue;
				}
				if(ch >= 0x80){
					if(pbuf - namebuf + 2 >= sizeof(namebuf))
						break;
					*pbuf++ = 0xc0 | ((ch >>  6) & 0x1f);
					*pbuf++ = 0x80 | ( ch        & 0x3f);
					continue;
				}
				if (pbuf - namebuf + 1 >= sizeof(namebuf))
					break;
				*pbuf++ = ch;
			}
			*pbuf = 0;
			return namebuf;
		}
		p += l + 2;
	}
	return NULL;
}

uint8_t* lltd_extract_ip(const uint8_t*p){
	uint8_t l;
	static uint8_t buf[20];

	while(*p){
		l = p[1];
		if( *p == 0x07 ){
			snprintf(buf, sizeof(buf)/sizeof(buf[0]), "%d.%d.%d.%d", p[2], p[3], p[4], p[5]);
			return buf;
		}
		p += l + 2;
	}
	return NULL;
}

void lltd_dump(const uint8_t*p){
	uint8_t l;

	while(*p){
		l = p[1];
		lltd_dump_tlv(p,l);
		p += l + 2;
	}
}
