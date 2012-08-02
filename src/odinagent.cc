/*
 * OdinAgent.{cc,hh} -- An agent for the Odin system
 * Lalith Suresh <suresh.lalith@gmail.com>
 *
 * Copyright (c) 2012 Lalith Suresh
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is 
 * legally binding.
 */

#include <click/config.h>
#include <clicknet/wifi.h>
#include <click/router.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/packet_anno.hh>
#include <click/handlercall.hh>
#include <clicknet/ether.h>
#include <clicknet/llc.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <net/if.h>
#include "odinagent.hh"


extern "C" {
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "nl80211_copy.h"
}

CLICK_DECLS

#define WPA_NONCE_LEN 32
#define SHA1_SIZE 20
#define ETH_ALEN 6
#define HMAC_OUT_LEN  20 /* SHA1 specific */
#define WLAN_CIPHER_SUITE_CCMP 0x000FAC04

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#define WPA_KEY_INFO_TYPE_MASK ((uint16_t) (BIT(0) | BIT(1) | BIT(2)))

#define WIFI_WEP_HEADERSIZE (WIFI_WEP_IVLEN + WIFI_WEP_KIDLEN)

#define WIFI_CCMP_PNLEN      7 /* 7 octets */
#define WIFI_CCMP_KIDLEN     1 /* 1 octet */
#define WIFI_CCMP_MICLEN     8
#define WIFI_CCMP_HEADERSIZE (WIFI_CCMP_PNLEN + WIFI_CCMP_KIDLEN)


struct click_802_1x_header {
  uint8_t version;
  uint8_t type;
  uint16_t len;
  // followed by descriptor
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct click_wpa_eapol_key_descriptor {
  uint8_t type;
  uint16_t key_info;
  uint16_t key_len;
  uint8_t replay_counter[8];
  uint8_t key_nonce[WPA_NONCE_LEN];
  uint8_t eapol_key_iv[16];
  uint8_t rsc[8];
  uint8_t key_identifier[8];
  uint8_t key_mic[16];
  uint16_t key_data_length;
  // followed by key_data
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct wpa_ptk {
  uint8_t kck[16]; /* EAPOL-Key Key Confirmation Key (KCK) */
  uint8_t kek[16]; /* EAPOL-Key Key Encryption Key (KEK) */
  uint8_t tk1[16]; /* Temporal Key 1 (TK1) */
  union {
    uint8_t tk2[16]; /* Temporal Key 2 (TK2) */
    struct {
      uint8_t tx_mic_key[8];
      uint8_t rx_mic_key[8];
    } auth;
  } u;
} CLICK_SIZE_PACKED_ATTRIBUTE;

#define nl_handle nl_sock

struct nl80211_handles {
  struct nl_handle *handle;
  struct nl_cache *cache;
};

struct nl80211_global {
  int if_add_ifindex;
  struct netlink_data *netlink;
  struct nl_cb *nl_cb;
  struct nl80211_handles nl;
  struct genl_family *nl80211;
  int ioctl_sock; /* socket for ioctl() use */
};

#define FOUR_WAY_STATE_NULL 0x00
#define FOUR_WAY_STATE_1 0x01
#define FOUR_WAY_STATE_3 0x02
#define FOUR_WAY_STATE_GROUP 0x03


void cleanup_lvap (Timer *timer, void *);

OdinAgent::OdinAgent()
: _rtable(0),
  _associd(0),
  _debug(false),
  _beacon_timer(this)
{
  _cleanup_timer.assign (&cleanup_lvap, (void *) this);
}

OdinAgent::~OdinAgent()
{
}

int
OdinAgent::initialize(ErrorHandler*)
{
  _beacon_timer.initialize(this);
  _cleanup_timer.initialize(this);
  _cleanup_timer.schedule_now();
  compute_bssid_mask ();
  return 0;
}

/*
 * This timer drives the beacon generation
 */
void
OdinAgent::run_timer (Timer*)
{
  for (HashTable<EtherAddress, OdinStationState>::iterator it 
      = _sta_mapping_table.begin(); it.live(); it++)
   {
      // Note that the beacon is directed at the unicast address of the
      // client corresponding to the VAP. This should
      // prevent clients from seeing each others VAPs
      send_beacon (it.key(), it.value()._vap_bssid, it.value()._vap_ssid, false);
   }
   
   _beacon_timer.reschedule_after_msec(_interval_ms);
}


/*
 * Click Element method
 */
int
OdinAgent::configure(Vector<String> &conf, ErrorHandler *errh)
{ 
  _interval_ms = 5000;
  _channel = 6;
  if (Args(conf, this, errh)
  .read_mp("HWADDR", _hw_mac_addr)
  .read_m("RT", ElementCastArg("AvailableRates"), _rtable)
  .read_m("CHANNEL", _channel)
  .read_m("DEFAULT_GW", _default_gw_addr)
  .complete() < 0)
  return -1;
  
  return 0;
}


/*
 * This re-computes the BSSID mask for this node
 * using all the BSSIDs of the VAPs, and sets the
 * hardware register accordingly.
 */
void
OdinAgent::compute_bssid_mask()
{
  uint8_t bssid_mask[6];
  int i;

  // Start with a mask of ff:ff:ff:ff:ff:ff
  for (i = 0; i < 6; i++) 
    {
      bssid_mask[i] = 0xff;
    }

  // For each VAP, update the bssid mask to include
  // the common bits of all VAPs.
  for (HashTable<EtherAddress, OdinStationState>::iterator it 
      = _sta_mapping_table.begin(); it.live(); it++)
   {
     for (i = 0; i < 6; i++)
        {
          const uint8_t *hw= (const uint8_t *)_hw_mac_addr.data();
          const uint8_t *bssid= (const uint8_t *)it.value()._vap_bssid.data();
          bssid_mask[i] &= ~(hw[i] ^ bssid[i]);
        }
  
   }
  
  // Update bssid mask register through debugfs 
  FILE *debugfs_file = fopen ("/sys/kernel/debug/ieee80211/phy0/ath9k/bssid_extra","w");
    
  if (debugfs_file!=NULL)
    {
      fprintf(stderr, "%s\n", EtherAddress (bssid_mask).unparse_colon().c_str());
      fprintf(debugfs_file, "%s\n", EtherAddress (bssid_mask).unparse_colon().c_str());//, sa.take_string().c_str());
      fclose (debugfs_file);
    }
}

/** 
 * Invoking this implies adding a client
 * to the VAP.
 *
 * return -1 if the STA is already assigned
 */
int
OdinAgent::add_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, String vap_ssid)
{
  // First make sure that this VAP isn't here already, in which
  // case we'll just ignore the request
  if (_sta_mapping_table.find(sta_mac) != _sta_mapping_table.end())
  {
    fprintf(stderr, "Ignoring VAP add request because it has already been assigned a slot\n");
    return -1;
  }

  OdinStationState state;
  state._vap_bssid = sta_bssid;
  state._sta_ip_addr_v4 = sta_ip;
  state._vap_ssid = vap_ssid;
  state.state_4way = FOUR_WAY_STATE_NULL;
  _sta_mapping_table.set(sta_mac, state);

  // We need to prime the ARP responders
  // FIXME: Don't rely on labelled name
  Router *r = router();
  HandlerCall::call_write (r->find("fh_arpr"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());

  compute_bssid_mask();

  // Start beacon generation
  if (_sta_mapping_table.size() == 1) {
      _beacon_timer.schedule_now();
  }

  // In case this invocation is in response to a page-faulted-probe-request,
  // then process the faulty packet
  HashTable<EtherAddress, void *>::const_iterator it = _packet_buffer.find(sta_mac);
  if (it != _packet_buffer.end()) {
    _packet_buffer.erase(it.key());
    OdinStationState oss = _sta_mapping_table.get (sta_mac);
    send_beacon (sta_mac, oss._vap_bssid, oss._vap_ssid, true);
  }

  return 0;
}


/** 
 * Invoking this implies updating a client's
 * details. To be used primarily to update
 * a client's IP address
 *
 * return -1 if the STA is already assigned
 */
int
OdinAgent::set_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, String vap_ssid)
{
  if (_debug) {
    fprintf(stderr, "set_vap (%s, %s, %s, %s)\n", sta_mac.unparse_colon().c_str()
                                                , sta_ip.unparse().c_str()
                                                , sta_bssid.unparse().c_str()
                                                , vap_ssid.c_str());
  }

  // First make sure that this VAP isn't here already, in which
  // case we'll just ignore the request
  if (_sta_mapping_table.find(sta_mac) == _sta_mapping_table.end())
  {
    fprintf(stderr, "Ignoring LVAP set request because the agent isn't hosting the LVAP\n");
    return -1;
  }

  OdinStationState state;
  state._vap_bssid = sta_bssid;
  state._sta_ip_addr_v4 = sta_ip;
  state._vap_ssid = vap_ssid;
  _sta_mapping_table.set(sta_mac, state);

  // We need to update the ARP responder
  // FIXME: Don't rely on labelled name
  Router *r = router();
  HandlerCall::call_write (r->find("fh_arpr"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());

  compute_bssid_mask();

  return 0;
}


/** 
 * Invoking this implies knocking
 * a client off the access point
 */
int
OdinAgent::remove_vap (EtherAddress sta_mac)
{
  if (_debug) {
    fprintf(stderr, "remove_vap (%s)\n", sta_mac.unparse_colon().c_str());
  }

  HashTable<EtherAddress, OdinStationState>::iterator it = _sta_mapping_table.find (sta_mac);
      
  // VAP doesn't exist on this node. Ignore.
  if (it == _sta_mapping_table.end())
    return -1;

  // We need to un-prime the ARP responders
  // FIXME: Don't rely on labelled name
  Router *r = router();
  HandlerCall::call_write (r->find("fh_arpr"), "remove", it.value()._sta_ip_addr_v4.unparse() + "/32");

  _sta_mapping_table.erase (it);
  
  // Remove this VAP's BSSID from the mask
  compute_bssid_mask();

  // Stop beacon generator if this was the last
  // LVAP
  if (_sta_mapping_table.size() == 0) {
    _beacon_timer.unschedule();
  }

  return 0;
} 


/** 
 * Handle a probe request. This code is
 * borrowed from the ProbeResponder element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::recv_probe_request (Packet *p)
{

  struct click_wifi *w = (struct click_wifi *) p->data();
  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  uint8_t *end  = (uint8_t *) p->data() + p->length();

  uint8_t *ssid_l = NULL;
  uint8_t *rates_l = NULL;

  while (ptr < end) {
  switch (*ptr) {
  case WIFI_ELEMID_SSID:
    ssid_l = ptr;
    break;
  case WIFI_ELEMID_RATES:
    rates_l = ptr;
    break;
  default:
    break;
  }
  ptr += ptr[1] + 2;

  }

  String ssid = "";
  if (ssid_l && ssid_l[1]) {
    ssid = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
  }

  EtherAddress src = EtherAddress(w->i_addr2);

  //If we're not aware of this VAP, then send to the controller.
  // TODO: Need to garbage collect the buffer
  if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
    StringAccum sa;
    sa << "probe " << src.unparse_colon().c_str() << "\n";
    String payload = sa.take_string();
    WritablePacket *odin_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
    output(3).push(odin_probe_packet);
    _packet_buffer.set (src, NULL);
    p->kill();
    return;
  }

  OdinStationState oss = _sta_mapping_table.get (src);
  send_beacon(src, oss._vap_bssid, oss._vap_ssid, true);

  p->kill();
  return;
}


/** 
 * Send a beacon/probe-response. This code is
 * borrowed from the BeaconSource element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::send_beacon (EtherAddress dst, EtherAddress bssid, String my_ssid, bool probe) {

  
  Vector<int> rates = _rtable->lookup(bssid);

  /* order elements by standard
   * needed by sloppy 802.11b driver implementations
   * to be able to connect to 802.11g APs */
  int max_len = sizeof (struct click_wifi) +
    8 +                  /* timestamp */
    2 +                  /* beacon interval */
    2 +                  /* cap_info */
    2 + my_ssid.length() + /* ssid */
    2 + WIFI_RATES_MAXSIZE +  /* rates */
    2 + 1 +              /* ds parms */
    1 + 1 + 2 + 4 + 2 + 4 + 2 + 4 + 2 + /* RSN (NOTE: assumes single auth/cipher suite) */
    2 + 4 +              /* tim */
    /* 802.11g Information fields */
    2 + WIFI_RATES_MAXSIZE +  /* xrates */
    0;


  WritablePacket *p = Packet::make(max_len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT;
  if (probe) {
    w->i_fc[0] |= WIFI_FC0_SUBTYPE_PROBE_RESP;
  } else {
    w->i_fc[0] |=  WIFI_FC0_SUBTYPE_BEACON;
  }

  w->i_fc[1] = WIFI_FC1_DIR_NODS;

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, bssid.data(), 6);

  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
  int actual_length = sizeof (struct click_wifi);


  /* timestamp is set in the hal. ??? */
  memset(ptr, 0, 8);
  ptr += 8;
  actual_length += 8;

  uint16_t beacon_int = (uint16_t) _interval_ms;
  *(uint16_t *)ptr = cpu_to_le16(beacon_int);
  ptr += 2;
  actual_length += 2;

  uint16_t cap_info = 0;
  cap_info |= WIFI_CAPINFO_ESS;
  cap_info |= WIFI_CAPINFO_PRIVACY;
  *(uint16_t *)ptr = cpu_to_le16(cap_info);
  ptr += 2;
  actual_length += 2;

  /* ssid */
  ptr[0] = WIFI_ELEMID_SSID;
  ptr[1] = my_ssid.length();
  memcpy(ptr + 2, my_ssid.data(), my_ssid.length());
  ptr += 2 + my_ssid.length();
  actual_length += 2 + my_ssid.length();

  /* rates */
  ptr[0] = WIFI_ELEMID_RATES;
  ptr[1] = WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  for (int x = 0; x < WIFI_MIN(WIFI_RATE_SIZE, rates.size()); x++) {
    ptr[2 + x] = (uint8_t) rates[x];

    if (rates[x] == 2) {
      ptr [2 + x] |= WIFI_RATE_BASIC;
    }

  }
  ptr += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  actual_length += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());


  /* channel */
  ptr[0] = WIFI_ELEMID_DSPARMS;
  ptr[1] = 1;
  ptr[2] = (uint8_t) _channel;
  ptr += 2 + 1;
  actual_length += 2 + 1;

  /* RSN */

  ptr[0] =  48; // tag id
  ptr[1] =  20; // len
  ptr += 2;
  actual_length += 2;
  *(uint16_t *)ptr = cpu_to_le16((uint16_t) 1); // version
  ptr += 2;
  actual_length += 2;
  *(uint32_t *)ptr = cpu_to_le32((uint32_t)0x04ac0f00); // group key suite
  ptr += 4;
  actual_length += 4;
  *(uint16_t *)ptr = cpu_to_le16((uint16_t) 1); // pairwise suite count
  ptr += 2;
  actual_length += 2;

  // NOTE: Only supports one for now
   *(uint32_t *)ptr = cpu_to_le32((uint32_t)0x04ac0f00); // pairwise suite list
  ptr += 4;
  actual_length += 4;

  *(uint16_t *)ptr = cpu_to_le16((uint16_t) 1); // authentication suite count
  ptr += 2;
  actual_length += 2;

  // NOTE: Only supports one for now
  *(uint32_t *)ptr = cpu_to_le32((uint32_t)0x02ac0f00); // authentication suite list
  ptr += 4;
  actual_length += 4;

  *(uint16_t *)ptr = cpu_to_le16((uint16_t)0x000c); // capabilities
  ptr += 2;
  actual_length += 2;


  /* tim */

  ptr[0] = WIFI_ELEMID_TIM;
  ptr[1] = 4;

  ptr[2] = 0; //count
  ptr[3] = 1; //period
  ptr[4] = 0; //bitmap control
  ptr[5] = 0; //paritial virtual bitmap
  ptr += 2 + 4;
  actual_length += 2 + 4;

  /* 802.11g fields */
  /* extended supported rates */
  int num_xrates = rates.size() - WIFI_RATE_SIZE;
  if (num_xrates > 0) {
    /* rates */
    ptr[0] = WIFI_ELEMID_XRATES;
    ptr[1] = num_xrates;
    for (int x = 0; x < num_xrates; x++) {
      ptr[2 + x] = (uint8_t) rates[x + WIFI_RATE_SIZE];

      if (rates[x + WIFI_RATE_SIZE] == 2) {
        ptr [2 + x] |= WIFI_RATE_BASIC;
      }

    }
    ptr += 2 + num_xrates;
    actual_length += 2 + num_xrates;
  }

  p->take(max_len - actual_length);

  output(0).push(p);
}

/** 
 * Receive an association request. This code is
 * borrowed from the AssociationResponder element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::recv_assoc_request (Packet *p) {
  struct click_wifi *w = (struct click_wifi *) p->data();

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  /*capabilty */
  uint16_t capability = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;

  /* listen interval */
  uint16_t lint = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;

  uint8_t *end  = (uint8_t *) p->data() + p->length();

  uint8_t *ssid_l = NULL;
  uint8_t *rates_l = NULL;

  while (ptr < end) {
    switch (*ptr) {
      case WIFI_ELEMID_SSID:
          ssid_l = ptr;
          break;
      case WIFI_ELEMID_RATES:
          rates_l = ptr;
          break;
      default:
          {
            break;
          }
    }
    ptr += ptr[1] + 2;
  }

  Vector<int> basic_rates;
  Vector<int> rates;
  Vector<int> all_rates;
  if (rates_l) {
    for (int x = 0; x < WIFI_MIN((int)rates_l[1], WIFI_RATES_MAXSIZE); x++) {
        uint8_t rate = rates_l[x + 2];

        if (rate & WIFI_RATE_BASIC) {
      basic_rates.push_back((int)(rate & WIFI_RATE_VAL));
        } else {
      rates.push_back((int)(rate & WIFI_RATE_VAL));
        }
          all_rates.push_back((int)(rate & WIFI_RATE_VAL));
    }
  }

  EtherAddress dst = EtherAddress(w->i_addr1);
  EtherAddress src = EtherAddress(w->i_addr2);
  EtherAddress bssid = EtherAddress(w->i_addr3);

  OdinStationState oss = _sta_mapping_table.get (src);

  String ssid;
  String my_ssid = oss._vap_ssid;
  if (ssid_l && ssid_l[1]) {
    ssid = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
  } else {
    /* there was no element or it has zero length */
    ssid = "";
  }

  if (_debug) {
    StringAccum sa;

    sa << "src " << src;
    sa << " dst " << dst;
    sa << " bssid " << bssid;
    sa << "[ ";
    if (capability & WIFI_CAPINFO_ESS) {
      sa << "ESS ";
    }
    if (capability & WIFI_CAPINFO_IBSS) {
      sa << "IBSS ";
    }
    if (capability & WIFI_CAPINFO_CF_POLLABLE) {
      sa << "CF_POLLABLE ";
    }
    if (capability & WIFI_CAPINFO_CF_POLLREQ) {
      sa << "CF_POLLREQ ";
    }
    if (capability & WIFI_CAPINFO_PRIVACY) {
      sa << "PRIVACY ";
    }
    sa << "] ";

    sa << " listen_int " << lint << " ";

    sa << "( { ";
    for (int x = 0; x < basic_rates.size(); x++) {
      sa << basic_rates[x] << " ";
    }
    sa << "} ";
    for (int x = 0; x < rates.size(); x++) {
      sa << rates[x] << " ";
    }

    sa << ")\n";

    fprintf(stderr, "recv_assoc_request: %s\n", sa.take_string().c_str());
  }

  uint16_t associd = 0xc000 | _associd++;

  send_assoc_response(src, WIFI_STATUS_SUCCESS, associd);
  p->kill();
  return;
}


/** 
 * Send an association request. This code is
 * borrowed from the AssociationResponder element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::send_assoc_response (EtherAddress dst, uint16_t status, uint16_t associd) {
  EtherAddress bssid = _sta_mapping_table.get (dst)._vap_bssid;

  Vector<int> rates = _rtable->lookup(bssid);
  int max_len = sizeof (struct click_wifi) +
    2 +                  /* cap_info */
    2 +                  /* status  */
    2 +                  /* assoc_id */
    2 + WIFI_RATES_MAXSIZE +  /* rates */
    2 + WIFI_RATES_MAXSIZE +  /* xrates */
    0;

  WritablePacket *p = Packet::make(max_len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT | WIFI_FC0_SUBTYPE_ASSOC_RESP;
  w->i_fc[1] = WIFI_FC1_DIR_NODS;

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, bssid.data(), 6);


  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
  int actual_length = sizeof(struct click_wifi);

  uint16_t cap_info = 0;
  cap_info |= WIFI_CAPINFO_ESS;
  *(uint16_t *)ptr = cpu_to_le16(cap_info);
  ptr += 2;
  actual_length += 2;

  *(uint16_t *)ptr = cpu_to_le16(status);
  ptr += 2;
  actual_length += 2;

  *(uint16_t *)ptr = cpu_to_le16(associd);
  ptr += 2;
  actual_length += 2;


  /* rates */
  ptr[0] = WIFI_ELEMID_RATES;
  ptr[1] = WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  for (int x = 0; x < WIFI_MIN(WIFI_RATE_SIZE, rates.size()); x++) {
    ptr[2 + x] = (uint8_t) rates[x];

    if (rates[x] == 2) {
      ptr [2 + x] |= WIFI_RATE_BASIC;
    }

  }
  ptr += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  actual_length += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());


  int num_xrates = rates.size() - WIFI_RATE_SIZE;
  if (num_xrates > 0) {
    /* rates */
    ptr[0] = WIFI_ELEMID_XRATES;
    ptr[1] = num_xrates;
    for (int x = 0; x < num_xrates; x++) {
      ptr[2 + x] = (uint8_t) rates[x + WIFI_RATE_SIZE];

      if (rates[x + WIFI_RATE_SIZE] == 2) {
  ptr [2 + x] |= WIFI_RATE_BASIC;
      }

    }
    ptr += 2 + num_xrates;
    actual_length += 2 + num_xrates;
  }

  p->take(max_len - actual_length);

  output(0).push(p);

  _sta_mapping_table.get_pointer(dst)->state_4way = FOUR_WAY_STATE_NULL;  

  /* We need both the Element and the destination
     ether address for invoking send_wpa_eapol_start(),
     so pack them into a HookPair struct and pass the
     struct through the void pointer */   
  HookPair *hp = new HookPair(this, dst);

  /* Authenticator initiates EAPOL handshake */
  Timer *t = new Timer(send_eapol_hook, (void *) hp);
  t->initialize(this);
  t->schedule_after_msec(2);

  if (_debug) {
    fprintf(stderr, "%s completed assocation. Initiating EAPOL\n", dst.unparse_colon().c_str());
  }
}

void
OdinAgent::send_wpa_eapol_key_1 (EtherAddress dst)
{
  if (_sta_mapping_table.get(dst).state_4way != FOUR_WAY_STATE_NULL)
  {
    return;
  }

  EtherAddress bssid = _sta_mapping_table.get (dst)._vap_bssid;

  Vector<int> rates = _rtable->lookup(bssid);
  int max_len = sizeof (struct click_wifi) +
    WIFI_LLC_HEADER_LEN + 2 +
    sizeof (struct click_802_1x_header) +
    sizeof (struct click_wpa_eapol_key_descriptor) +
    0;

  WritablePacket *p = Packet::make(max_len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA);
  w->i_fc[1] = 0;
  w->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & WIFI_FC1_DIR_FROMDS);

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, bssid.data(), 6);


  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
  int actual_length = sizeof(struct click_wifi);

  /* LLC header */
  memcpy(ptr, WIFI_LLC_HEADER, WIFI_LLC_HEADER_LEN);
  ptr += WIFI_LLC_HEADER_LEN;
  actual_length += WIFI_LLC_HEADER_LEN;

  *(uint16_t *)ptr = cpu_to_le16(0x8e88); // type == 802.1X encap
  ptr += 2;
  actual_length += 2;

  /* 802.1X Header */
  struct click_802_1x_header *ah = (struct click_802_1x_header *) ptr;
  ah->version = 2;
  ah->type = 3; // Key
  ah->len = htons (sizeof (struct click_wpa_eapol_key_descriptor));

  ptr += sizeof(struct click_802_1x_header);
  actual_length += sizeof(struct click_802_1x_header);

  /* Key descriptor */
  struct click_wpa_eapol_key_descriptor *kd = (struct click_wpa_eapol_key_descriptor *) ptr;
  kd->type = 2;
  kd->key_info = htons(0x008a);
  kd->key_len = htons(16);

  memset(kd->replay_counter, 0, sizeof(uint8_t) * 8);
  kd->replay_counter[7] = 1;
  memset(kd->key_nonce, 1, sizeof(uint8_t) * 32);
  memset(kd->eapol_key_iv, 0, sizeof(uint8_t) * 16);
  memset(kd->rsc, 0, sizeof(uint8_t) * 8);
  memset(kd->key_identifier, 0, sizeof(uint8_t) * 8);
  memset(kd->key_mic, 0, sizeof(uint8_t) * 16);
  kd->key_data_length = 0;

  actual_length += sizeof(struct click_wpa_eapol_key_descriptor);

  _sta_mapping_table.get_pointer(dst)->state_4way = FOUR_WAY_STATE_1;
  memcpy(_sta_mapping_table.get_pointer(dst)->replay_counter,
          kd->replay_counter,
          sizeof(uint8_t)*8);

  output(0).push(p);

  if (_debug) {
    fprintf(stderr, "EAPOL msg one sent to %s\n", dst.unparse_colon().c_str());  
  }
}

void
OdinAgent::send_wpa_eapol_key_3 (EtherAddress dst, struct wpa_ptk *ptk, uint8_t *gtk)
{
  EtherAddress bssid = _sta_mapping_table.get (dst)._vap_bssid;

  /* Now send msg 3/4. FIXME: MOVE TO ANOTHER FUNCTION */

  Vector<int> rates = _rtable->lookup(bssid);
  int max_len = sizeof (struct click_wifi) +
    WIFI_LLC_HEADER_LEN + 2 +
    sizeof (struct click_802_1x_header) +
    sizeof (struct click_wpa_eapol_key_descriptor) +
    56;

  WritablePacket *p = Packet::make(max_len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA);
  w->i_fc[1] = 0;
  w->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & WIFI_FC1_DIR_FROMDS);

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, bssid.data(), 6);


  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
  int actual_length = sizeof(struct click_wifi);

  /* LLC header */
  memcpy(ptr, WIFI_LLC_HEADER, WIFI_LLC_HEADER_LEN);
  ptr += WIFI_LLC_HEADER_LEN;
  actual_length += WIFI_LLC_HEADER_LEN;

  *(uint16_t *)ptr = cpu_to_le16(0x8e88); // type == 802.1X encap
  ptr += 2;
  actual_length += 2;

  /* 802.1X Header */
  struct click_802_1x_header *ah = (struct click_802_1x_header *) ptr;
  ah->version = 2;
  ah->type = 3; // Key
  ah->len = htons (sizeof (struct click_wpa_eapol_key_descriptor) + 56 /* key-data-lenght */);

  ptr += sizeof(struct click_802_1x_header);
  actual_length += sizeof(struct click_802_1x_header);

  /* Key descriptor */
  struct click_wpa_eapol_key_descriptor *kd = (struct click_wpa_eapol_key_descriptor *) ptr;
  kd->type = 2;
  kd->key_info = htons(0x13ca); //
  kd->key_len = htons(16);

  memset(kd->replay_counter, 0, sizeof(uint8_t) * 8);
  kd->replay_counter[7] = _sta_mapping_table.get(dst).replay_counter[7] + 1;
  memset(kd->key_nonce, 1, sizeof(uint8_t) * 32); // same as Anonce
  memset(kd->eapol_key_iv, 0, sizeof(uint8_t) * 16); // blank again
  memset(kd->rsc, 0, sizeof(uint8_t) * 8); // this should be blank as well
  memset(kd->key_identifier, 0, sizeof(uint8_t) * 8); // blank
  memset(kd->key_mic, 0, sizeof(uint8_t) * 16); // set to 0 for now
  kd->key_data_length = htons(56); // 22-bytes-RSN + 32-bytes-gtk + 2-bytes-gtk-N

  actual_length += sizeof(struct click_wpa_eapol_key_descriptor);

  /* Begin packing key-data */

  ptr += sizeof(struct click_wpa_eapol_key_descriptor);
  uint8_t *key_data = ptr; // pointer to starting point of key-data
  uint8_t *buf = (uint8_t *) malloc (56); // buf to pass plaintext

  /* First, we pack the RSN field */
  ptr[0] =  48; // tag id
  ptr[1] =  20; // len
  ptr += 2;
  actual_length += 2;
  *(uint16_t *)ptr = cpu_to_le16((uint16_t) 1); // version
  ptr += 2;
  actual_length += 2;
  *(uint32_t *)ptr = cpu_to_le32((uint32_t)0x04ac0f00); // group key suite
  ptr += 4;
  actual_length += 4;
  *(uint16_t *)ptr = cpu_to_le16((uint16_t) 1); // pairwise suite count
  ptr += 2;
  actual_length += 2;

  // NOTE: Only supports one for now
   *(uint32_t *)ptr = cpu_to_le32((uint32_t)0x04ac0f00); // pairwise suite list
  ptr += 4;
  actual_length += 4;

  *(uint16_t *)ptr = cpu_to_le16((uint16_t) 1); // authentication suite count
  ptr += 2;
  actual_length += 2;

  // NOTE: Only supports one for now
  *(uint32_t *)ptr = cpu_to_le32((uint32_t)0x02ac0f00); // authentication suite list
  ptr += 4;
  actual_length += 4;

  *(uint16_t *)ptr = cpu_to_le16((uint16_t)0x000c); // capabilities
  ptr += 2;
  actual_length += 2;

//   /* Now, pack the GTK */
//   memcpy (ptr, gtk, 32);
//   ptr += 32;
//   actual_length += 32;

//   /* And lastly, pack the GTK-N */
//   *(uint16_t *)ptr = htons(0x0001);
//   ptr += 2;
//   actual_length += 2;
// fprintf(stderr, "6666\n");


  // THIS IS TEMPORARY PLEASE REMOVE LATER THX
  uint8_t *tmp_gtk = reinterpret_cast<uint8_t *>(const_cast<char *>("\xdd\x16\x00\x0f\xac\x01\x01\x00\xf1\x7e\x0d\x78\xe2\xf7\x16\x88\x5a\xf3\xcc\xc3\xeb\xd2\xc3\x5d\xdd\x00"));
  for (uint8_t i = 0; i < 26; ++i)
  {
    memcpy(ptr,tmp_gtk,26);
  }

  memcpy(buf, key_data, 56);

  /* We need to encrypt the payload, and setup the MIC */
  aes_wrap(ptk->kek, (56 - 8)/8, buf, key_data);

  /* now update the MIC: something wrong here? */
  wpa_eapol_key_mic(ptk->kck, kd->key_info & WPA_KEY_INFO_TYPE_MASK,
                   (uint8_t *)ah, 
                   ntohs(ah->len) + sizeof(*ah), 
                   kd->key_mic);

  if (wpa_verify_key_mic (ptk, (uint8_t *)ah, ntohs(ah->len) + sizeof(*ah)))
    {
      if (_debug) {
        fprintf(stderr, "Error: 3/4 your own MIC verification failed ?!?!\n"); 
      }
      return;
    }
  
  if (_debug) {
    fprintf(stderr, "3/4: MIC verification success\n"); 
  }

  output(0).push(p);  
}

/**
 * Handle EAPOL frames from a client.
 * NOTE: Assumes only EAPOL-key types for
 *       WPA as of now.
 */
void
OdinAgent::recv_wpa_eapol_key (Packet *p)
{
  // We need to check which of the 4 handshake msgs
  // we've received but what the heck. :)
  struct click_wifi *w = (struct click_wifi *) p->data();

  EtherAddress dst = EtherAddress(w->i_addr1);
  EtherAddress src = EtherAddress(w->i_addr2);
  EtherAddress bssid = EtherAddress(w->i_addr3);

  if (_sta_mapping_table.get(src).state_4way == FOUR_WAY_STATE_1) {
    
    if (_debug)
      fprintf(stderr, "Received wpa_eapol_msg_2 from %s\n", src.unparse_colon().c_str());

    // Receiving message 2/4 of 4-way handshake
    _sta_mapping_table.get_pointer(src)->state_4way = FOUR_WAY_STATE_3;

    uint8_t *ptr;
    
    uint8_t *key = reinterpret_cast<uint8_t *>(const_cast<char *>("\x1e\xc1\x83\xfa\x15\xdf\x38\xcc\x4c\x00\x62\x5c\xd7\x74\x38\x8c\x65\x3b\x4f\x8f\xf5\x7f\x94\x12\x59\x51\x06\x44\x29\x4b\xb2\x58"));

    uint8_t *gmk = reinterpret_cast<uint8_t *>(const_cast<char *>("\x11\xc1\x83\xfa\x15\xdf\x38\xcc\x4c\x00\x62\x5c\xd7\x74\x38\x8c\x65\x3b\x4f\x8f\xf5\x7f\x94\x12\x59\x51\x06\x44\x29\x4b\xb2\x58"));  

    uint8_t *anonce = (uint8_t *) malloc (sizeof(uint8_t) * WPA_NONCE_LEN);
    uint8_t *gnonce = (uint8_t *) malloc (sizeof(uint8_t) * WPA_NONCE_LEN);
    struct wpa_ptk ptk;
    uint8_t gtk[32];

    memset(anonce, 1, sizeof(uint8_t) * WPA_NONCE_LEN);
    memset(gnonce, 1, sizeof(uint8_t) * WPA_NONCE_LEN);

    // Now at LLC header
    ptr = (uint8_t *) (w + 1);

    // At end of LLC header
    ptr += WIFI_LLC_HEADER_LEN + 2;

    struct click_802_1x_header *ah = (struct click_802_1x_header *) ptr;

    struct click_wpa_eapol_key_descriptor *kd = (struct click_wpa_eapol_key_descriptor *) (ah + 1);

    wpa_pmk_to_ptk (key, 32, "Pairwise key expansion", 
                    reinterpret_cast<const uint8_t *>(dst.data()), 
                    reinterpret_cast<const uint8_t *>(src.data()), 
                    anonce, kd->key_nonce, (uint8_t *) &ptk, 64, 0);

    if (_debug) {
      fprintf(stderr, "Calculated PTK: ");
      for (int i = 0; i < 64; ++i)
      {
        fprintf(stderr, "%hhx", ((uint8_t *)&ptk)[i]);
      }
      fprintf(stderr, "\n");
    }

    if (wpa_verify_key_mic (&ptk, (uint8_t *)ah, ntohs(ah->len) + sizeof(*ah)))
      {
        if (_debug)
          fprintf(stderr, "Error: MIC verification failed\n");

        return;
      }

    if (_debug)
      fprintf(stderr, "MIC verification successful\n");

    wpa_gmk_to_gtk (gmk, "Group key expansion",
                    dst.data(), gnonce,
                    gtk, 32);

    memcpy(_sta_mapping_table.get_pointer(src)->tk1, ptk.tk1, 16);

    send_wpa_eapol_key_3 (src, &ptk, gtk);
  }
  else if (_sta_mapping_table.get(src).state_4way == FOUR_WAY_STATE_3) {
    fprintf(stderr, "Client %s has installed keys and has sent wpa_eapol_msg_4\n", src.unparse_colon().c_str());

    FILE *keyidx_file = fopen ("/sys/kernel/debug/ieee80211/phy0/ath9k/keyidx","w");
    FILE *keyval_file = fopen ("/sys/kernel/debug/ieee80211/phy0/ath9k/keyval","w");
    FILE *keymac_file = fopen ("/sys/kernel/debug/ieee80211/phy0/ath9k/keymac","w");
    
    
    if (keyidx_file != NULL || keyval_file != NULL || keymac_file != NULL) {
        fprintf(stderr, "key-idx: %d\n", 1);
        fprintf(keyidx_file, "%d\n", 1);//, sa.take_string().c_str());
        fclose (keyidx_file);
        
        fprintf(stderr, "key-val: ");
        for (int i = 0; i < 16; ++i)
        {
          fprintf(stderr, "%02hhx", _sta_mapping_table.get(src).tk1[i]);
          fprintf(keyval_file, "%02hhx", _sta_mapping_table.get(src).tk1[i]);
        }

        //fprintf(keyval_file, "\n");
        fclose(keyval_file);

        fprintf(stderr, "\nkey-mac: %s\n", src.unparse_colon().c_str());
        fprintf(keymac_file, "%s", src.unparse_colon().c_str());//, sa.take_string().c_str());
        fclose (keymac_file);
    }
  }
  // else if (_sta_mapping_table.get(src).state_4way == FOUR_WAY_STATE_3) {
  //   // Receiving message 4/4 of 4-way handshake
  //   fprintf(stderr, "Received message 4/4 THX\n");

  //   struct nl_sock *sock;
  //   int family;
  //   struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);


  //   // Allocate and initialize a new netlink handle
  //   sock = nl_socket_alloc();

  //   if (sock == NULL) {
  //     fprintf(stderr, "Couldn't allocate nl_sock!!!!\n");
  //     return;
  //   }
    
  //   if (genl_connect(sock)){
  //     fprintf(stderr, "Failed to connect to general netlink!\n");
  //     return;
  //   }

  //   family = genl_ctrl_resolve(sock, "nl80211");
  //   if (family < 0) {
  //     fprintf(stderr, "genl_ctrl_resolve failed!\n");
  //     return; 
  //   }

  //   struct nl_msg *msg = nlmsg_alloc();

  //   if (!msg) {
  //     fprintf(stderr, "Not enough memory to allocate nl_msg!\n");
  //     return;
  //   }

  //   fprintf(stderr, "Key to inject:\n");
  //   for (int i = 0; i < 16; ++i)
  //   {
  //     fprintf(stderr, "%hhx", _sta_mapping_table.get_pointer(src)->tk1[i]);
  //   }
  //   fprintf(stderr, "\n");

  //   genlmsg_put(msg, 0, 0, family, 0, 0, NL80211_CMD_NEW_KEY, 0);
  //   nla_put(msg, NL80211_ATTR_KEY_DATA, 16, _sta_mapping_table.get_pointer(src)->tk1);
  //   nla_put_u32(msg, NL80211_ATTR_KEY_CIPHER, WLAN_CIPHER_SUITE_CCMP);
  //   nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, src.data());
  //   nla_put_u8(msg, NL80211_ATTR_KEY_IDX, 0);
  //   fprintf(stderr, "Ifindex: %d\n", if_nametoindex("mon0"));
  //   nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex("mon0"));
  //   int err = nl_send_auto_complete(sock, msg);
  //   if (err < 0) {
  //     fprintf(stderr, "Err after nl_send_auto_complete\n");
  //   }


  //   nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  //   nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  //   nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

  //   while (err > 0) {
  //     fprintf(stderr, "Receiving msgs\n");
  //     nl_recvmsgs(sock, cb);
  //   }

  //   nlmsg_free(msg);
  // }
}

/** 
 * Receive an Open Auth request. This code is
 * borrowed from the OpenAuthResponder element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::recv_open_auth_request (Packet *p) {
  struct click_wifi *w = (struct click_wifi *) p->data();

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);



  uint16_t algo = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;

  uint16_t seq = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;

  uint16_t status = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;


  EtherAddress src = EtherAddress(w->i_addr2);
  if (algo != WIFI_AUTH_ALG_OPEN) {
    // click_chatter("%{element}: auth %d from %s not supported\n",
      // this,
      // algo,
      // src.unparse().c_str());
    p->kill();
    return;
  }

  if (seq != 1) {
    // click_chatter("%{element}: auth %d weird sequence number %d\n",
      // this,
      // algo,
      // seq);
    p->kill();
    return;
  }

  send_open_auth_response(src, 2, WIFI_STATUS_SUCCESS);

  p->kill();
  return;
}


/** 
 * Send an Open Auth request. This code is
 * borrowed from the OpenAuthResponder element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::send_open_auth_response (EtherAddress dst, uint16_t seq, uint16_t status) {
  
  OdinStationState oss = _sta_mapping_table.get (dst);

  int len = sizeof (struct click_wifi) +
    2 +                  /* alg */
    2 +                  /* seq */
    2 +                  /* status */
    0;

  WritablePacket *p = Packet::make(len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT | WIFI_FC0_SUBTYPE_AUTH;
  w->i_fc[1] = WIFI_FC1_DIR_NODS;

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, oss._vap_bssid.data(), 6);
  memcpy(w->i_addr3, oss._vap_bssid.data(), 6);


  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  *(uint16_t *)ptr = cpu_to_le16(WIFI_AUTH_ALG_OPEN);
  ptr += 2;

  *(uint16_t *)ptr = cpu_to_le16(seq);
  ptr += 2;

  *(uint16_t *)ptr = cpu_to_le16(status);
  ptr += 2;

  output(0).push(p);
}


/** 
 * Encapsulate an ethernet frame with a 802.11 header.
 * Borrowed from WifiEncap element.
 * NOTE: This method uses the FromDS mode (0x02)
 */
 // 20120731 jsz: use OdinStationState ptr instead of MAC
 //OdinAgent::wifi_encap (Packet *p, EtherAddress bssid)
 Packet*
 OdinAgent::wifi_encap (Packet *p, OdinStationState *oss)
{
  EtherAddress src;
  EtherAddress dst;

  uint16_t ethtype;
  WritablePacket *p_out = 0;

  // 20120731 jsz: add bssid
  EtherAddress bssid = oss->_vap_bssid;

  if (p->length() < sizeof(struct click_ether)) {
    // click_chatter("%{element}: packet too small: %d vs %d\n",
    //   this,
    //   p->length(),
    //   sizeof(struct click_ether));

    p->kill();
    return 0;

  }

  click_ether *eh = (click_ether *) p->data();
  src = EtherAddress(eh->ether_shost);
  dst = EtherAddress(eh->ether_dhost);
  memcpy(&ethtype, p->data() + 12, 2);

  p_out = p->uniqueify();
  if (!p_out) {
    return 0;
  }


  p_out->pull(sizeof(struct click_ether));
  p_out = p_out->push(sizeof(struct click_llc));

  if (!p_out) {
    return 0;
  }

  memcpy(p_out->data(), WIFI_LLC_HEADER, WIFI_LLC_HEADER_LEN);
  memcpy(p_out->data() + 6, &ethtype, 2);

  if (!(p_out = p_out->push(sizeof(struct click_wifi))))
      return 0;
  struct click_wifi *w = (struct click_wifi *) p_out->data();

  memset(p_out->data(), 0, sizeof(click_wifi));
  w->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA);
  w->i_fc[1] = 0;
  w->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & WIFI_FC1_DIR_FROMDS);

  // Equivalent to mode 0x02
  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, src.data(), 6);

    /* check for LVAP crypto here */

  if(oss->state_4way == FOUR_WAY_STATE_GROUP) {
    if (!(p_out = p_out->push(WIFI_CCMP_HEADERSIZE)))
      return 0;

    //fprintf(stderr, "LOOK AT ME I INSIDE%s\n", );
    /* Move the 802.11 header to the begining */
    memmove((void *) p_out->data(), p_out->data() + WIFI_CCMP_HEADERSIZE, sizeof(click_wifi));

    w = (struct click_wifi *) p_out->data();

    //htons(*(uint16_t *)(&oss->replay_counter[6]))
    //htonl(*(uint16_t *)(&oss->replay_counter[2]))
    memcpy((void *) (p_out->data()+sizeof(click_wifi)), &oss->replay_counter[7], 1);
    oss->replay_counter[7] += 1;

    /* Zero reserved bits */
    memset((void *) (p_out->data()+sizeof(click_wifi) + 1), 0, 2);

    uint8_t keyid = 32;
    /* Set the keyid flag and unicast only */
    memcpy((void *) (p_out->data()+sizeof(click_wifi) + 3), &keyid, 1);
    memset((void *) (p_out->data()+sizeof(click_wifi) + 4), 0, 4);
    //memcpy((void *) (p_out->data()+sizeof(click_wifi) + 4), pn+4, 4);
    
    //w->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA);
    //w->i_fc[1] = 0;
    //w->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & _mode);
      /* Set crypto header flag */
    w->i_fc[1] |= WIFI_FC1_WEP;

    if (!(p_out = p_out->put(WIFI_CCMP_MICLEN)))
      return 0;

    /* Move the FCS to the end */
    memcpy((void *) (p_out->data()+ (p_out->length() - 4 )), (void *) (p_out->data()+ (p_out->length() - WIFI_CCMP_MICLEN - 4 )), 4);

    /* Zero the MIC */
    memset((void *) (p_out->data()+ (p_out->length() - WIFI_CCMP_MICLEN - 4 )), 0, 8);
  }

  return p_out;
}

Packet *
OdinAgent::wifi_decap (Packet *p)
{
  uint8_t dir;
  //uint8_t keyid;
  struct click_wifi *w = (struct click_wifi *) p->data();
  EtherAddress bssid;
  EtherAddress src;
  EtherAddress dst;

  int wifi_header_size = sizeof(struct click_wifi);
  if ((w->i_fc[1] & WIFI_FC1_DIR_MASK) == WIFI_FC1_DIR_DSTODS)
    wifi_header_size += WIFI_ADDR_LEN;
  if (WIFI_QOS_HAS_SEQ(w))
    wifi_header_size += sizeof(uint16_t);

  struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
  if ((ceh->magic == WIFI_EXTRA_MAGIC) && ceh->pad && (wifi_header_size & 3))
    wifi_header_size += 4 - (wifi_header_size & 3);

  if (p->length() < wifi_header_size + sizeof(struct click_llc)) {
    p->kill();
    return 0;
  }

  dir = w->i_fc[1] & WIFI_FC1_DIR_MASK;

  switch (dir) {
  case WIFI_FC1_DIR_NODS:
    dst = EtherAddress(w->i_addr1);
    src = EtherAddress(w->i_addr2);
    bssid = EtherAddress(w->i_addr3);
    break;
  case WIFI_FC1_DIR_TODS:
    bssid = EtherAddress(w->i_addr1);
    src = EtherAddress(w->i_addr2);
    dst = EtherAddress(w->i_addr3);
    break;
  case WIFI_FC1_DIR_FROMDS:
    dst = EtherAddress(w->i_addr1);
    bssid = EtherAddress(w->i_addr2);
    src = EtherAddress(w->i_addr3);
    break;
  case WIFI_FC1_DIR_DSTODS:
    dst = EtherAddress(w->i_addr1);
    src = EtherAddress(w->i_addr2);
    bssid = EtherAddress(w->i_addr3);
    break;
  default:
    dst = EtherAddress(w->i_addr1);
    src = EtherAddress(w->i_addr2);
    bssid = EtherAddress(w->i_addr3);
  }

  WritablePacket *p_out = p->uniqueify();
  if (!p_out) {
    return 0;
  }

  fprintf(stderr, "WiFi WEP CHECK BEFORE: %d\n", p_out->length());

  for (int i = 0; i < p_out->length(); ++i)
  {
    fprintf(stderr, "%02hhx ", p_out->data()[i]);
  }

  if (w->i_fc[1] & WIFI_FC1_WEP) {
    fprintf(stderr, "\nWiFi WEP CHECK INSIDE\n");

    const unsigned char* payload = p_out->data() + (wifi_header_size + WIFI_CCMP_HEADERSIZE);
    int payload_len = p_out->length() - (wifi_header_size + WIFI_CCMP_HEADERSIZE + WIFI_CCMP_MICLEN);

    /* strip the CCMP header off */
    memmove((void *)(p_out->data() + wifi_header_size), payload, payload_len);

  fprintf(stderr, "\npost-ccmp-header-strip: %d\n", p_out->length());    
  for (int i = 0; i < p_out->length(); ++i)
  {
    fprintf(stderr, "%02hhx ", p_out->data()[i]);
  }


    /* Strip the MIC off */
    //memmove((void *)(p_out->data() + (wifi_header_size + payload_len)), p_out->data()+ (p_out->length() - 4) , 4);


  // fprintf(stderr, "\npost-mic-strip: %d\n", p_out->length());    
  // for (int i = 0; i < p_out->length(); ++i)
  // {
  //   fprintf(stderr, "%02hhx ", p_out->data()[i]);
  // }
    
    /* strip the CCMP MIC and CCMP hdr off the tail of the packet */
    p_out->take(WIFI_CCMP_MICLEN + WIFI_CCMP_HEADERSIZE);


  fprintf(stderr, "\npost-tail-strip: %d\n", p_out->length());    
  for (int i = 0; i < p_out->length(); ++i)
  {
    fprintf(stderr, "%02hhx ", p_out->data()[i]);
  }

    w = (struct click_wifi *) p_out->data();
    w->i_fc[1] &= ~WIFI_FC1_WEP;
  }

  fprintf(stderr, "\nWiFi WEP CHECK AFTER: %d\n", p_out->length());


  uint16_t ether_type;
  memcpy(&ether_type, p_out->data() + wifi_header_size + sizeof(click_llc) - 2, 2);

  p_out->pull(wifi_header_size + sizeof(struct click_llc));

  fprintf(stderr, "WiFi decap push mac header before\n");

  p_out = p_out->push_mac_header(14);
  if (!p_out) {
    return 0;
  }

fprintf(stderr, "WiFi decap push mac header after\n");
  memcpy(p_out->data(), dst.data(), 6);
  memcpy(p_out->data() + 6, src.data(), 6);
  memcpy(p_out->data() + 12, &ether_type, 2);


  return p_out;
}

void
OdinAgent::update_rx_stats(Packet *p)
{
  struct click_wifi *w = (struct click_wifi *) p->data();
  EtherAddress src = EtherAddress(w->i_addr2);

  struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);

  StationStats stat;
  HashTable<EtherAddress, StationStats>::const_iterator it = _rx_stats.find(src);
  if (it == _rx_stats.end())
    stat = StationStats();
  else
    stat = it.value();

  stat._rate = ceh->rate;
  stat._noise = ceh->silence;
  stat._signal = ceh->rssi;
  stat._packets++;
  stat._last_received.assign_now();

  match_against_subscriptions(stat, src);

  _rx_stats.set (src, stat);
}

/** 
 * This element has two input ports and 4 output ports.
 *
 * In-port-0: Any 802.11 encapsulated frame. Expected
 *            to be coming from a physical device
 * In-port-1: Any ethernet encapsulated frame. Expected
 *            to be coming from a tap device
 *
 * Out-port-0: If in-port-0, and packet was a management frame,
 *             then send out management response.
 * Out-port-1: If in-port-0, and packet was a data frame,
 *             then push data frame to the higher layers.
 * Out-port-2: If in-port-1, and packet was destined to a client
 *              for which we have a VAP, then let it through.
 * Out-port-3: Used exclusively to talk to a Socket to be used
 *             to communicate with the OdinMaster. Should be removed
 *             later.
 */
void
OdinAgent::push(int port, Packet *p)
{
  // If port == 0, then the packet is an 802.11
  // frame, and could be of type data or Mgmnt.
  // We filter data frames by available VAPs,
  // and we handle Mgmnt frames accordingly.
  
  if (port == 0) {
    // if port == 0, paket is coming from the lower layer

    if (p->length() < sizeof(struct click_wifi)) {
      p->kill();
      return;
    }

    uint8_t type;
    uint8_t subtype;

    struct click_wifi *w = (struct click_wifi *) p->data();

    EtherAddress src = EtherAddress(w->i_addr2);
    struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);

    StationStats stat;
    HashTable<EtherAddress, StationStats>::const_iterator it = _rx_stats.find(src);
    if (it == _rx_stats.end())
      stat = StationStats();
    else
      stat = it.value();

    stat._rate = ceh->rate;
    stat._noise = ceh->silence;
    stat._signal = ceh->rssi;
    stat._packets++;
    stat._last_received.assign_now();

    match_against_subscriptions(stat, src);

    _rx_stats.set (src, stat);

    type = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
    subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;
  
    if (type == WIFI_FC0_TYPE_MGT) {
      // This is a management frame, now
      // we classify by subtype
      update_rx_stats(p);

      switch (subtype) {
        case WIFI_FC0_SUBTYPE_PROBE_REQ:
          {
            recv_probe_request (p);
            return;
          }
        case WIFI_FC0_SUBTYPE_ASSOC_REQ:
          {
            recv_assoc_request (p);
            return;
          }
        case WIFI_FC0_SUBTYPE_AUTH:
          {
            recv_open_auth_request (p);
            return;
          }
        default:
          {
            // Discard packet because we don't
            // need to handle other management
            // frame types for now.
            // FIXME: Need to handle DISSASOC
            p->kill ();
            return;
          }
      }
    }
    else if (type == WIFI_FC0_TYPE_DATA) {
      // This is a data frame, so we merely
      // filter against the VAPs.
      update_rx_stats(p);

      if (_sta_mapping_table.find (src) == _sta_mapping_table.end()) {
        // FIXME: Inform controller accordingly? We'll need this
        // for roaming.

        p->kill ();
        return;
      }

      fprintf(stderr, "Past STA check \n");
      /* We handle EAPOL frames but let everything else pass.
         TODO: We should probably have a port status on the LVAP? */
      uint16_t type = *(uint16_t *)(((uint8_t *)(w + 1)) + WIFI_LLC_HEADER_LEN);

      if (ntohs(type) == 0x888e) {
        recv_wpa_eapol_key (p);
        return;
      }

      fprintf(stderr, "WiFi Decap BEFORE \n");
      Packet *p_out = wifi_decap(p);

      if (p_out == 0)
          return;

      fprintf(stderr, "WiFi Decap AFTER \n");
      // There should be a WifiDecap element upstream.
      output(1).push(p_out);
      return;
    }
  }
  else if (port == 1) {
    // This means that the packet is coming from the higher layer,
    // so we simply filter by VAP and push out with the appropriate
    // bssid and wifi-encapsulation.
    const click_ether *e = (const click_ether *) (p->data() + 0 /*offset*/);
    const unsigned char *daddr = (const unsigned char *)e->ether_dhost;

    EtherAddress eth (daddr);

    // FIXME: We can avoid two lookups here
    if (_sta_mapping_table.find (eth) != _sta_mapping_table.end ())
    {
      OdinStationState oss = _sta_mapping_table.get (eth);
        
      // If the client tried to make an ARP request for
      // its default gateway, and there is a response coming from
      // upstream, we have to correct the resolved hw-addr with the 
      // VAP-BSSID to which the client corresponds.
      // This assumes there is an ARP responder element upstream
      // that can handle the _default_gw_addr
      if (ntohs(e->ether_type) == ETHERTYPE_ARP) {
        click_ether_arp *ea = (click_ether_arp *) (e + 1);
        if (ntohs(ea->ea_hdr.ar_hrd) == ARPHRD_ETHER
            && ntohs(ea->ea_hdr.ar_pro) == ETHERTYPE_IP
            && ntohs(ea->ea_hdr.ar_op) == ARPOP_REPLY) {
          
          IPAddress ipa = IPAddress(ea->arp_spa);
          if (ipa == _default_gw_addr)
            memcpy(ea->arp_sha, oss._vap_bssid.data(), 6);
        }
      }
      // 20120731 jsz: use LVAP pointer instead of MAC
      //Packet *p_out = wifi_encap (p, oss._vap_bssid);
      Packet *p_out = wifi_encap (p, &oss);
      output(2).push(p_out);
      return;
    }
  }

  p->kill();
  return;
}

void
OdinAgent::add_subscription (long subscription_id, EtherAddress addr, String statistic, relation_t r, double val)
{
  Subscription sub;
  sub.subscription_id = subscription_id;
  sub.sta_addr = addr;
  sub.statistic = statistic;
  sub.rel = r;
  sub.val = val;
  _subscription_list.push_back (sub);
}

void
OdinAgent::clear_subscriptions ()
{
  _subscription_list.clear();
}

void
OdinAgent::match_against_subscriptions(StationStats stats, EtherAddress src)
{
  if(_subscription_list.size() == 0)
    return;

  int count = 0;
  StringAccum subscription_matches;

  for (Vector<OdinAgent::Subscription>::const_iterator iter = _subscription_list.begin();
           iter != _subscription_list.end(); iter++) {
    
    Subscription sub = *iter;

    if (sub.sta_addr != EtherAddress() && sub.sta_addr != src)
      continue;

    /* TODO: Refactor to use a series of hash maps instead */
    switch (sub.rel) {
      case EQUALS: {
        if (sub.statistic == "signal" && stats._signal == sub.val) {
          subscription_matches << " " << sub.subscription_id << ":" << stats._signal;
          count++;
        } else if (sub.statistic == "rate" && stats._rate == sub.val) {
          subscription_matches << " " <<  sub.subscription_id << ":" << stats._rate;
          count++;
        } else if (sub.statistic == "noise" && stats._noise == sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._noise;
          count++;
        } else if (sub.statistic == "_packets" && stats._packets == sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._packets;
          count++;
        }
        break;
      }
      case GREATER_THAN: {
       if (sub.statistic == "signal" && stats._signal > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._signal;
          count++;
        } else if (sub.statistic == "rate" && stats._rate > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._rate;
          count++;
        } else if (sub.statistic == "noise" && stats._noise > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._noise;
          count++;
        } else if (sub.statistic == "_packets" && stats._packets > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._packets;
          count++;
        }
        break; 
      }
      case LESSER_THAN: {
        if (sub.statistic == "signal" && stats._signal < sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._signal;
          count++;
        } else if (sub.statistic == "rate" && stats._rate < sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._rate;
          count++;
        } else if (sub.statistic == "noise" && stats._noise < sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._noise;
          count++;
        } else if (sub.statistic == "_packets" && stats._packets < sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._packets;
          count++;
        }
        break;
      }
    }
  }


  StringAccum sa;
  sa << "publish " << src.unparse_colon().c_str() << " " << count << subscription_matches.take_string() << "\n";

  String payload = sa.take_string();
  WritablePacket *odin_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
  output(3).push(odin_probe_packet);
}

String
OdinAgent::read_handler(Element *e, void *user_data)
{
  OdinAgent *agent = (OdinAgent *) e;
  StringAccum sa;

  switch (reinterpret_cast<uintptr_t>(user_data)) {
    case handler_view_mapping_table: {
      for (HashTable<EtherAddress, OdinStationState>::iterator it 
          = agent->_sta_mapping_table.begin(); it.live(); it++)
        {
          sa << it.key().unparse_colon() 
            <<  " " << it.value()._vap_bssid.unparse_colon() 
            << " " << it.value()._vap_ssid
            << " " << it.value()._sta_ip_addr_v4 << "\n";
        }
      break;
    }
    case handler_channel: {
      sa << agent->_channel << "\n";
      break;
    }
    case handler_interval: {
      sa << agent->_interval_ms << "\n";
      break;
    }
    case handler_rxstat: {
      Timestamp now = Timestamp::now();

      for (HashTable<EtherAddress, StationStats>::const_iterator iter = agent->_rx_stats.begin();
           iter.live(); iter++) {

        OdinAgent::StationStats n = iter.value();
        Timestamp age = now - n._last_received;
        // Timestamp avg_signal;
        // Timestamp avg_noise;
        // if (n._packets) {
        //   avg_signal = Timestamp::make_msec(1000*n._sum_signal / n._packets);
        //   avg_noise = Timestamp::make_msec(1000*n._sum_noise / n._packets);
        // }
        sa << iter.key().unparse_colon();
        sa << " rate:" << n._rate;
        sa << " signal:" << n._signal;
        sa << " noise:" << n._noise;
        // sa << " avg_signal " << avg_signal;
        // sa << " avg_noise " << avg_noise;
        // sa << " total_signal " << n._sum_signal;
        // sa << " total_noise " << n._sum_noise;
        sa << " packets:" << n._packets;
        sa << " last_received:" << age << "\n";
      }

      break;
    }
    case handler_subscriptions: {

      for (Vector<OdinAgent::Subscription>::const_iterator iter = agent->_subscription_list.begin();
           iter != agent->_subscription_list.end(); iter++) {
        
        OdinAgent::Subscription sub = *iter;
        sa << "sub_id " << sub.subscription_id;
        sa << " addr " << sub.sta_addr.unparse_colon();
        sa << " stat " << sub.statistic;
        sa << " rel " << sub.rel;
        sa << " val " << sub.val;
        sa << "\n";
      }

      break;
    }
    case handler_debug: {
      sa << agent->_debug << "\n";
      break;
    }
  }

  return sa.take_string();
}

int
OdinAgent::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{

  OdinAgent *agent = (OdinAgent *) e;

  switch (reinterpret_cast<uintptr_t>(user_data)) {
    case handler_add_vap:{
      IPAddress sta_ip;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;
      String vap_ssid;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("STA_MAC", sta_mac)
            .read_mp("STA_IP", sta_ip)
            .read_mp("VAP_BSSID", vap_bssid)
            .read_mp("VAP_SSID", vap_ssid)
            .complete() < 0)
            {
              return -1;
            }

        if (agent->add_vap (sta_mac, sta_ip, vap_bssid, vap_ssid) < 0)
          {
            return -1;
          }
      break;
    }
    case handler_set_vap:{
      IPAddress sta_ip;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;
      String vap_ssid;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("STA_MAC", sta_mac)
            .read_mp("STA_IP", sta_ip)
            .read_mp("VAP_BSSID", vap_bssid)
            .read_mp("VAP_SSID", vap_ssid)
            .complete() < 0)
            {
              return -1;
            }

        if (agent->set_vap (sta_mac, sta_ip, vap_bssid, vap_ssid) < 0)
          {
            return -1;
          }
      break;
    }
    case handler_remove_vap:{
      EtherAddress sta_mac;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("STA_MAC", sta_mac)
        .complete() < 0)
        {
          return -1;
        }

      if (agent->remove_vap(sta_mac) < 0)
        {
          return -1;
        }
      break;
    }
    case handler_channel: {
      int channel;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("CHANNEL", channel)
        .complete() < 0)
        {
          return -1;
        }

      agent->_channel = channel;
      break;
    }
    case handler_interval: {
      int interval;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("INTERVAL", interval)
        .complete() < 0)
        {
          return -1;
        }

      agent->_interval_ms = interval;     
      break;
    }
    case handler_subscriptions: {
      /* Clear out subscriptions first */
      agent->clear_subscriptions();

      int num_rows;
      Args args(agent, errh);
      if (args.push_back_words(str)
        .read_mp("NUM_ROWS", num_rows)
        .consume() < 0)
        {
          return -1;
        }
      
      fprintf(stderr, "num_rows: %d\n", num_rows);
      for (int i = 0; i < num_rows; i++) {
        long sub_id;
        EtherAddress sta_addr;
        String statistic;
        int relation;
        double value;
        if (args
            .read_mp("sub_id", sub_id)
            .read_mp("addr", sta_addr)
            .read_mp("stat", statistic)
            .read_mp("rel", relation)
            .read_mp("val", value)
            .consume() < 0)
          {
            return -1;
          }

        agent->add_subscription (sub_id, sta_addr, statistic, static_cast<relation_t>(relation), value);
      }

      if (args.complete() < 0) {
        return -1;
      }
      break;
    }
    case handler_debug: {
      bool debug;
      if (!BoolArg().parse(str, debug))
        return -1;
      
      agent->_debug = debug;
      break;
    }
  }
  return 0;
}


void
OdinAgent::add_handlers()
{
  add_read_handler("table", read_handler, handler_view_mapping_table);
  add_read_handler("channel", read_handler, handler_channel);
  add_read_handler("interval", read_handler, handler_interval);
  add_read_handler("rxstats", read_handler, handler_rxstat);
  add_read_handler("subscriptions", read_handler, handler_subscriptions);
  add_read_handler("debug", read_handler, handler_debug);

  add_write_handler("add_vap", write_handler, handler_add_vap);
  add_write_handler("set_vap", write_handler, handler_set_vap);
  add_write_handler("remove_vap", write_handler, handler_remove_vap);
  add_write_handler("channel", write_handler, handler_channel);
  add_write_handler("interval", write_handler, handler_interval);
  add_write_handler("subscriptions", write_handler, handler_subscriptions);
  add_write_handler("debug", write_handler, handler_debug);
}


void
cleanup_lvap (Timer *timer, void *data)
{
  OdinAgent *agent = (OdinAgent *) data;

  Vector<EtherAddress> buf;

  // Clear out old rxstat entries.
  for (HashTable<EtherAddress, OdinAgent::StationStats>::const_iterator iter = agent->_rx_stats.begin();
        iter.live(); iter++)
  {
    Timestamp now = Timestamp::now();
    Timestamp age = now - iter.value()._last_received;
    
    if (age.sec() > 30)
    {
      buf.push_back (iter.key());
    }
  }

  for (Vector<EtherAddress>::const_iterator iter = buf.begin(); iter != buf.end(); iter++)
  {
    agent->_rx_stats.erase (*iter);
  }

  agent->_packet_buffer.clear();
  timer->reschedule_after_sec(50);
}



/******************* CRYPTO *************************/
/* Code shamelessly copy-pasted off hostapd and the
   Internetz */

int 
OdinAgent::wpa_pmk_to_ptk(const uint8_t *pmk, size_t pmk_len, const char *label,
        const uint8_t *addr1, const uint8_t *addr2,
        const uint8_t *nonce1, const uint8_t *nonce2,
        uint8_t *ptk, size_t ptk_len, int use_sha256)
{
  uint8_t data[2 * ETH_ALEN + 2 * WPA_NONCE_LEN];

  if (memcmp(addr1, addr2, ETH_ALEN) < 0) { 
    memcpy(data, addr1, ETH_ALEN);
    memcpy(data + ETH_ALEN, addr2, ETH_ALEN);
  } else {
    memcpy(data, addr2, ETH_ALEN);
    memcpy(data + ETH_ALEN, addr1, ETH_ALEN);
  }

  if (memcmp(nonce1, nonce2, WPA_NONCE_LEN) < 0) { 
    memcpy(data + 2 * ETH_ALEN, nonce1, WPA_NONCE_LEN);
    memcpy(data + 2 * ETH_ALEN + WPA_NONCE_LEN, nonce2,
        WPA_NONCE_LEN);
  } else {
    memcpy(data + 2 * ETH_ALEN, nonce2, WPA_NONCE_LEN);
    memcpy(data + 2 * ETH_ALEN + WPA_NONCE_LEN, nonce1,
        WPA_NONCE_LEN);
  }

  if (_debug) {
    fprintf(stderr, "\n== wpa_pmk_to_ptk() dump BEGIN ==\n");
    fprintf(stderr, "\nNonce1: ");
    for (int i = 0; i < WPA_NONCE_LEN; i++)
      fprintf(stderr, "%hhx", nonce1[i]);

    fprintf(stderr, "\nNonce2: ");
    for (int i = 0; i < WPA_NONCE_LEN; i++)
      fprintf(stderr, "%hhx", nonce2[i]);

    fprintf(stderr, "\nAddr1: ");
    for (int i = 0; i < 6; i++)
      fprintf(stderr, "%hhx:", addr1[i]);
    
    fprintf(stderr, "\nAddr2: ");
    for (int i = 0; i < 6; i++)
      fprintf(stderr, "%hhx:", addr2[i]);
    
    fprintf(stderr, "\nPMK: ");
    for (uint32_t i = 0; i < pmk_len; i++)
      fprintf(stderr, "%hhx", pmk[i]);
    
    fprintf(stderr, "\n== wpa_pmk_to_ptk() dump END == \n");
  }

  sha1_prf(pmk, pmk_len, label, data, sizeof(data), ptk, ptk_len);
  //sha1_prf((unsigned char *)pmk, pmk_len, data, sizeof(data), ptk, ptk_len);

  return 0;
}

#define SHA1_MAC_LEN 20


int
OdinAgent::sha1_prf(const uint8_t *key, size_t key_len, const char *label,
       const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len)
{
  uint8_t counter = 0;
  size_t pos, plen;
  uint8_t hash[SHA1_MAC_LEN];
  size_t label_len = strlen(label) + 1;
  const unsigned char *addr[3];
  size_t len[3];

  addr[0] = (uint8_t *) label;
  len[0] = label_len;
  addr[1] = data;
  len[1] = data_len;
  addr[2] = &counter;
  len[2] = 1;

  pos = 0;
  while (pos < buf_len) {
    plen = buf_len - pos;
    if (plen >= SHA1_MAC_LEN) {
      if (hmac_sha1_vector(key, key_len, 3, addr, len,
               &buf[pos]))
        return -1;
      pos += SHA1_MAC_LEN;
    } else {
      if (hmac_sha1_vector(key, key_len, 3, addr, len,
               hash))
        return -1;
      memcpy(&buf[pos], hash, plen);
      break;
    }
    counter++;
  }

  return 0;
}


int 
OdinAgent::sha1_vector(size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
  SHA_CTX ctx;
  size_t i;

  SHA1_Init(&ctx);

  for (i = 0; i < num_elem; i++){
    SHA1_Update(&ctx, addr[i], len[i]);
  }

  SHA1_Final(mac, &ctx);
  
  return 0;
}


int 
OdinAgent::hmac_sha1_vector(const uint8_t *key, size_t key_len, size_t num_elem,
         const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
  unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
  unsigned char tk[20];
  const uint8_t *_addr[6];
  size_t _len[6], i;


  if (num_elem > 5) {
    /*
     * Fixed limit on the number of fragments to avoid having to
     * allocate memory (which could fail).
     */
    return -1;
  }

  /* if key is longer than 64 bytes reset it to key = SHA1(key) */
  if (key_len > 64) {
    if (sha1_vector(1, &key, &key_len, tk))
      return -1;
    key = tk;
    key_len = 20;
  }


  /* the HMAC_SHA1 transform looks like:
   *
   * SHA1(K XOR opad, SHA1(K XOR ipad, text))
   *
   * where K is an n byte key
   * ipad is the byte 0x36 repeated 64 times
   * opad is the byte 0x5c repeated 64 times
   * and text is the data being protected */

  /* start out by storing key in ipad */
  memset(k_pad, 0, sizeof(k_pad));
  memcpy(k_pad, key, key_len);


  /* XOR key with ipad values */
  for (i = 0; i < 64; i++)
    k_pad[i] ^= 0x36;

  /* perform inner SHA1 */
  _addr[0] = k_pad;
  _len[0] = 64;
  for (i = 0; i < num_elem; i++) {
    _addr[i + 1] = addr[i];
    _len[i + 1] = len[i];
  }

  if (sha1_vector(1 + num_elem, _addr, _len, mac))
    return -1;

  memset(k_pad, 0, sizeof(k_pad));
  memcpy(k_pad, key, key_len);

  /* XOR key with opad values */
  for (i = 0; i < 64; i++)
    k_pad[i] ^= 0x5c;

  /* perform outer SHA1 */
  _addr[0] = k_pad;
  _len[0] = 64;
  _addr[1] = mac;
  _len[1] = SHA1_MAC_LEN;
  return sha1_vector(2, _addr, _len, mac);
}


int 
OdinAgent::wpa_gmk_to_gtk(const uint8_t *gmk, const char *label, const uint8_t *addr,
        const uint8_t *gnonce, uint8_t *gtk, size_t gtk_len)
{
  uint8_t data[ETH_ALEN + WPA_NONCE_LEN + 8 + 16]; 
  uint8_t *pos;
  int ret = 0; 

  /* GTK = PRF-X(GMK, "Group key expansion",
   *  AA || GNonce || Time || random data)
   * The example described in the IEEE 802.11 standard uses only AA and
   * GNonce as inputs here. Add some more entropy since this derivation
   * is done only at the Authenticator and as such, does not need to be
   * exactly same.
   */
  memcpy(data, addr, ETH_ALEN);
  memcpy(data + ETH_ALEN, gnonce, WPA_NONCE_LEN);
  pos = data + ETH_ALEN + WPA_NONCE_LEN;
  wpa_get_ntp_timestamp(pos);
  pos += 8;
  // if (random_get_bytes(pos, 16) < 0) 
  //   ret = -1;

  if (sha1_prf(gmk, 32, label, data, sizeof(data), gtk, gtk_len)
      < 0) 
    ret = -1;

  return ret; 
}


void 
OdinAgent::wpa_get_ntp_timestamp(uint8_t *buf)
{
  Timestamp now = Timestamp::now();
  uint32_t sec, usec;
  uint32_t tmp;

  /* 64-bit NTP timestamp (time from 1900-01-01 00:00:00) */
  sec = now.sec() + 2208988800U; /* Epoch to 1900 */
  /* Estimate 2^32/10^6 = 4295 - 1/32 - 1/512 */
  usec = now.usec();
  usec = 4295 * usec - (usec >> 5) - (usec >> 9);
  tmp = htons(sec);
  memcpy(buf, (uint8_t *) &tmp, 4);
  tmp = htons(usec);
  memcpy(buf + 4, (uint8_t *) &tmp, 4);
}


int 
OdinAgent::wpa_verify_key_mic(struct wpa_ptk *PTK, uint8_t *data, size_t data_len)
{
  struct click_802_1x_header *hdr;
  struct click_wpa_eapol_key_descriptor *key;
  uint16_t key_info;
  int ret = 0;
  uint8_t mic[16];

  if (data_len < sizeof(*hdr) + sizeof(*key))
    return -1;

  hdr = (struct click_802_1x_header *) data;
  key = (struct click_wpa_eapol_key_descriptor *) (hdr + 1);
  key_info = ntohs(key->key_info);
  memcpy(mic, key->key_mic, 16);
  memset(key->key_mic, 0, 16);

  if (_debug) {
    fprintf(stderr, "wpa_verify_key_mic(): MIC to get: ");
    for (int i = 0; i < 16; ++i)
    {
      fprintf(stderr, "%hhx",mic[i]);
    }
    fprintf(stderr, "\n");
  }

  if (wpa_eapol_key_mic(PTK->kck, key_info & WPA_KEY_INFO_TYPE_MASK,
            data, data_len, key->key_mic) ||
      memcmp(mic, key->key_mic, 16) != 0)
    ret = -1;
  memcpy(key->key_mic, mic, 16);
  return ret;
}   


int
OdinAgent::hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
         uint8_t *mac)
{
  return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}


int 
OdinAgent::wpa_eapol_key_mic(const uint8_t *key, int ver, const uint8_t *buf, size_t len,
          uint8_t *mic)
{
  uint8_t hash[20];

  if (hmac_sha1(key, 16, buf, len, hash))
      return -1;
  memcpy(mic, hash, 16);

  if (_debug) {
    fprintf(stderr, "wpa_eapol_key_mic(): Computed MIC: ");
    for (int i = 0; i < 16; ++i)
    {
      fprintf(stderr, "%hhx",mic[i]);
    }
    fprintf(stderr, "\n");
  }

  return 0;
} 


int
OdinAgent::aes_wrap(const uint8_t *kek, int n, const uint8_t *plain, uint8_t *cipher)
{
  uint8_t *a, *r, b[16];
  int i, j;
  void *ctx;

  a = cipher;
  r = cipher + 8;

  if (_debug)
  {
    fprintf(stderr, "aes_wrap(): Plaintext:\n");
    for (int i = 0; i < n*8; ++i)
    {
      fprintf(stderr, "%hhx", plain[i]);
    }
    fprintf(stderr, "\n");
  }
  /* 1) Initialize variables. */
  memset(a, 0xa6, 8); 
  memcpy(r, plain, 8 * n); 

  ctx = aes_encrypt_init(kek, 16);
  if (ctx == NULL)
    return -1; 

  /* 2) Calculate intermediate values.
   * For j = 0 to 5
   *     For i=1 to n
   *         B = AES(K, A | R[i])
   *         A = MSB(64, B) ^ t where t = (n*j)+i
   *         R[i] = LSB(64, B)
   */
  for (j = 0; j <= 5; j++) {
    r = cipher + 8;
    for (i = 1; i <= n; i++) {
      memcpy(b, a, 8); 
      memcpy(b + 8, r, 8); 
      aes_encrypt(ctx, b, b); 
      memcpy(a, b, 8); 
      a[7] ^= n * j + i;
      memcpy(r, b + 8, 8); 
      r += 8;
    }   
  }
  aes_encrypt_deinit(ctx);

  /* 3) Output the results.
   *
   * These are already in @cipher due to the location of temporary
   * variables.
   */

  return 0;
}


void * 
OdinAgent::aes_encrypt_init(const uint8_t *key, size_t len)
{
  AES_KEY *ak;
  ak = (AES_KEY *) malloc(sizeof(*ak));
  if (ak == NULL)
    return NULL;
  if (AES_set_encrypt_key(key, 8 * len, ak) < 0) {
    free(ak);
    return NULL;
  }
  return ak; 
}


void
OdinAgent::aes_encrypt(void *ctx, const uint8_t *plain, uint8_t *crypt)
{
  AES_encrypt(plain, crypt, (const AES_KEY *) ctx);
}


void
OdinAgent::aes_encrypt_deinit(void *ctx)
{
  free(ctx);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(OdinAgent)
ELEMENT_LIBS(-lssl -lnl-tiny)
ELEMENT_REQUIRES(userlevel)