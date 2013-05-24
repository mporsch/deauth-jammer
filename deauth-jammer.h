#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef u32 __le32;
typedef u16 __le16;

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define	le16_to_cpu(x) (x)
#define	le32_to_cpu(x) (x)
#define	cpu_to_le16(x) (x)
//#define	cpu_to_le32(x) (x)
#else
#define	le16_to_cpu(x) ((((x)&0xff)<<8)|(((x)&0xff00)>>8))
#define	le32_to_cpu(x) \
((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)&0xff0000)>>8)|(((x)&0xff000000)>>24))
#define	cpu_to_le16(x) ((((x)&0xff00)>>8)|(((x)&0xff)<<8))
//#define	cpu_to_le32(x) (x)
#endif

#define unlikely(x) (x)

/*
 * Definitions for sparse validation
 * (http://kernel.org/pub/linux/kernel/people/josh/sparse/)
 */
#ifdef __CHECKER__
#define __force __attribute__((force))
#define __bitwise __attribute__((bitwise))
#else
#define __force
#define __bitwise
#endif

#define ETH_ALEN	6


typedef u16 __bitwise be16;
typedef u16 __bitwise le16;
typedef u32 __bitwise be32;
typedef u32 __bitwise le32;
//typedef u64 __bitwise be64;
//typedef u64 __bitwise le64;

#ifdef __GNUC__
#define PRINTF_FORMAT(a,b) __attribute__ ((format (printf, (a), (b))))
#define STRUCT_PACKED __attribute__ ((packed))
#else
#define PRINTF_FORMAT(a,b)
#define STRUCT_PACKED
#endif

struct ieee80211_mgmt {
	le16 frame_control;
	le16 duration;
	u8 da[ETH_ALEN];
	u8 sa[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	le16 seq_ctrl;
	union {
//		struct {
//			le16 auth_alg;
//			le16 auth_transaction;
//			le16 status_code;
//			/* possibly followed by Challenge text */
//			u8 variable[0];
//		} STRUCT_PACKED auth;
		struct {
			le16 reason_code;
			u8 variable[0];
		} STRUCT_PACKED deauth;
//		struct {
//			le16 capab_info;
//			le16 listen_interval;
//			/* followed by SSID and Supported rates */
//			u8 variable[0];
//		} STRUCT_PACKED assoc_req;
//		struct {
//			le16 capab_info;
//			le16 status_code;
//			le16 aid;
//			/* followed by Supported rates */
//			u8 variable[0];
//		} STRUCT_PACKED assoc_resp, reassoc_resp;
//		struct {
//			le16 capab_info;
//			le16 listen_interval;
//			u8 current_ap[6];
//			/* followed by SSID and Supported rates */
//			u8 variable[0];
//		} STRUCT_PACKED reassoc_req;
//		struct {
//			le16 reason_code;
//			u8 variable[0];
//		} STRUCT_PACKED disassoc;
		struct {
			u8 timestamp[8];
			le16 beacon_int;
			le16 capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params, TIM */
			u8 variable[0];
		} STRUCT_PACKED beacon;
//		struct {
//			/* only variable items: SSID, Supported rates */
//			u8 variable[0];
//		} STRUCT_PACKED probe_req;
//		struct {
//			u8 timestamp[8];
//			le16 beacon_int;
//			le16 capab_info;
//			/* followed by some of SSID, Supported rates,
//			 * FH Params, DS Params, CF Params, IBSS Params */
//			u8 variable[0];
//		} STRUCT_PACKED probe_resp;
//		struct {
//			u8 category;
//			union {
//				struct {
//					u8 action_code;
//					u8 dialog_token;
//					u8 status_code;
//					u8 variable[0];
//				} STRUCT_PACKED wmm_action;
//				struct{
//					u8 action_code;
//					u8 element_id;
//					u8 length;
//					u8 switch_mode;
//					u8 new_chan;
//					u8 switch_count;
//				} STRUCT_PACKED chan_switch;
//				struct {
//					u8 action;
//					u8 sta_addr[ETH_ALEN];
//					u8 target_ap_addr[ETH_ALEN];
//					u8 variable[0]; /* FT Request */
//				} STRUCT_PACKED ft_action_req;
//				struct {
//					u8 action;
//					u8 sta_addr[ETH_ALEN];
//					u8 target_ap_addr[ETH_ALEN];
//					le16 status_code;
//					u8 variable[0]; /* FT Request */
//				} STRUCT_PACKED ft_action_resp;
//				struct {
//					u8 action;
//					u8 trans_id[WLAN_SA_QUERY_TR_ID_LEN];
//				} STRUCT_PACKED sa_query_req;
//				struct {
//					u8 action; /* */
//					u8 trans_id[WLAN_SA_QUERY_TR_ID_LEN];
//				} STRUCT_PACKED sa_query_resp;
//				struct {
//					u8 action;
//					u8 dialogtoken;
//					u8 variable[0];
//				} STRUCT_PACKED wnm_sleep_req;
//				struct {
//					u8 action;
//					u8 dialogtoken;
//					le16 keydata_len;
//					u8 variable[0];
//				} STRUCT_PACKED wnm_sleep_resp;
//				struct {
//					u8 action;
//					u8 variable[0];
//				} STRUCT_PACKED public_action;
//				struct {
//					u8 action; /* 9 */
//					u8 oui[3];
//					/* Vendor-specific content */
//					u8 variable[0];
//				} STRUCT_PACKED vs_public_action;
//				struct {
//					u8 action; /* 7 */
//					u8 dialog_token;
//					u8 req_mode;
//					le16 disassoc_timer;
//					u8 validity_interval;
//					/* BSS Termination Duration (optional),
//					 * Session Information URL (optional),
//					 * BSS Transition Candidate List
//					 * Entries */
//					u8 variable[0];
//				} STRUCT_PACKED bss_tm_req;
//				struct {
//					u8 action; /* 8 */
//					u8 dialog_token;
//					u8 status_code;
//					u8 bss_termination_delay;
//					/* Target BSSID (optional),
//					 * BSS Transition Candidate List
//					 * Entries (optional) */
//					u8 variable[0];
//				} STRUCT_PACKED bss_tm_resp;
//				struct {
//					u8 action; /* 6 */
//					u8 dialog_token;
//					u8 query_reason;
//					/* BSS Transition Candidate List
//					 * Entries (optional) */
//					u8 variable[0];
//				} STRUCT_PACKED bss_tm_query;
//			} u;
//		} STRUCT_PACKED action;
	} u;
} STRUCT_PACKED;



#define IEEE80211_FCTL_FTYPE		0x000c
#define IEEE80211_FCTL_STYPE		0x00f0
#define IEEE80211_FTYPE_MGMT		0x0000
#define IEEE80211_STYPE_BEACON		0x0080
#define IEEE80211_STYPE_DEAUTH		0x00C0

#define WLAN_REASON_DEAUTH_LEAVING	0x0003

/**
 * ieee80211_is_beacon - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_BEACON
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee80211_is_beacon(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
	       cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_BEACON);
}
