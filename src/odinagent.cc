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
#include "odinagent.hh"

CLICK_DECLS


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

  // click_chatter("%{element}: request %s\n",
  // this,
  // sa.take_string().c_str());



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
Packet*
OdinAgent::wifi_encap (Packet *p, EtherAddress bssid)
{
  EtherAddress src;
  EtherAddress dst;

  uint16_t ethtype;
  WritablePacket *p_out = 0;

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

      // There should be a WifiDecap element upstream.
      output(1).push(p);
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
      Packet *p_out = wifi_encap (p, oss._vap_bssid);
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



CLICK_ENDDECLS
EXPORT_ELEMENT(OdinAgent)
ELEMENT_REQUIRES(userlevel)