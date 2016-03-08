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
#include <iostream>
#include <string>
#include <sstream>
#include <stdlib.h>
#include <stdio.h>

CLICK_DECLS


void misc_thread(Timer *timer, void *);
void cleanup_lvap(Timer *timer, void *);

int THRESHOLD_OLD_STATS = 30; //timer interval [sec] after which the stats of old clients will be removed
int RESCHEDULE_INTERVAL_GENERAL = 35; //time interval [sec] after which general_timer will be rescheduled
int RESCHEDULE_INTERVAL_STATS = 60; //time interval [sec] after which general_timer will be rescheduled
int THRESHOLD_REMOVE_LVAP = 80; //time interval [sec] after which an lvap will be removed if we didn't hear from the client
double THRESHOLD_PUBLISH_SENT = 0.0; //time interval [sec] after which a publish message can be sent again
int MULTICHANNEL_AGENTS = 0; //Odin environment with agents in several channels

OdinAgent::OdinAgent()
: _mean(0),
  _num_mean(0),
  _m2(0),
  _signal_offset(0),
  //_debug(true), //false
  _debug_level(0),
  _rtable(0),
  _associd(0),
  _beacon_timer(this),
  _debugfs_string(""),
  _ssid_agent_string("")
{
  _clean_stats_timer.assign(&cleanup_lvap, (void *) this);
  _general_timer.assign (&misc_thread, (void *) this);
}

OdinAgent::~OdinAgent()
{
}

int
OdinAgent::initialize(ErrorHandler*)
{
  _beacon_timer.initialize(this);
  _general_timer.initialize(this);
  _general_timer.schedule_now();
  _clean_stats_timer.initialize(this);
  _clean_stats_timer.schedule_now();
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
      // client corresponding to the LVAP. This should
      // prevent clients from seeing each others LVAPs

      for (int i = 0; i < it.value()._vap_ssids.size (); i++) {
        send_beacon (it.key(), it.value()._vap_bssid, it.value()._vap_ssids[i], false);
      }
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
  _new_channel = 1;
  _csa = false; //
  _csa_count_default = 49; // Wait (n+1) beacons before first channel switch announcement
  _csa_count = _csa_count_default; 
  _count_csa_beacon_default = 10; // Number of beacons before channel switch
  _count_csa_beacon = _count_csa_beacon_default;
  if (Args(conf, this, errh)
  .read_mp("HWADDR", _hw_mac_addr)
  .read_m("RT", ElementCastArg("AvailableRates"), _rtable)
  .read_m("CHANNEL", _channel)
  .read_m("DEFAULT_GW", _default_gw_addr)
  .read_m("DEBUGFS", _debugfs_string)
  .read_m("SSIDAGENT", _ssid_agent_string)
  .read_m("DEBUG_ODIN", _debug_level)
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
  FILE *debugfs_file = fopen (_debugfs_string.c_str(),"w");



  if (debugfs_file!=NULL)
    {
      if (_debug_level % 10 > 1)
			  fprintf(stderr, "[Odinagent.cc] bssid mask: %s\n", EtherAddress (bssid_mask).unparse_colon().c_str());
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
OdinAgent::add_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> vap_ssids)
{
  // First make sure that this VAP isn't here already, in which
  // case we'll just ignore the request
  if (_sta_mapping_table.find(sta_mac) != _sta_mapping_table.end())
  {
    if (_debug_level % 10 > 0)
		fprintf(stderr, "[Odinagent.cc] Ignoring VAP add request because it has already been assigned a slot\n");
    return -1;
  }

 if (_debug_level % 10 > 0) {
      //fprintf(stderr, "[Odinagent.cc] add_lvap %s\n", sta_mac.unparse_colon().c_str());
			if (_debug_level / 10 == 1)
				fprintf(stderr, "##################################################################\n");

      fprintf(stderr, "[Odinagent.cc] add_lvap (%s, %s, %s, %s)\n", sta_mac.unparse_colon().c_str()
                                                , sta_ip.unparse().c_str()
                                                , sta_bssid.unparse().c_str()
                                                , vap_ssids[0].c_str());
			if (_debug_level / 10 == 1)
				fprintf(stderr, "##################################################################\n\n");
  }

  OdinStationState state;
  state._vap_bssid = sta_bssid;
  state._sta_ip_addr_v4 = sta_ip;
  state._vap_ssids = vap_ssids;
  _sta_mapping_table.set(sta_mac, state);

  // We need to prime the ARP responders
  Router *r = router();

  if (_debug_level % 10 > 1)
		if ( r->find("fh_arpr" ) == NULL )
			fprintf(stderr, "[Odinagent.cc] addLVAP: fh_arpr element not found\n");

  // ARP response to the ARP requests from device (coming from the wired network)
  int result = HandlerCall::call_write (r->find("fh_arpr"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());
  if (_debug_level % 10 > 1)
		fprintf(stderr,"[Odinagent.cc] addLVAP: result of the fh_arpr call write: %i\n", result);

	if (_debug_level % 10 > 1)
		if ( r->find("arp_resp" ) == NULL )
			fprintf(stderr, "[Odinagent.cc] addLVAP: arp_resp element not found\n");

  // ARP response to the ARP requests from the wireless network
  result = HandlerCall::call_write (r->find("arp_resp"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());
	if (_debug_level % 10 > 1)
		fprintf(stderr,"[Odinagent.cc] addLVAP: result of the arp_resp call write: %i\n", result);

  compute_bssid_mask();

  // Start beacon generation
  if (_sta_mapping_table.size() == 1) {
      _beacon_timer.schedule_now();
  }

  // In case this invocation is in response to a page-faulted-probe-request,
  // then process the faulty packet
  HashTable<EtherAddress, String>::const_iterator it = _packet_buffer.find(sta_mac);
  if (it != _packet_buffer.end()) {
    OdinStationState oss = _sta_mapping_table.get (sta_mac);

    if (it.value() == "") {
      for (int i = 0; i < oss._vap_ssids.size(); i++) {
        send_beacon(sta_mac, oss._vap_bssid, oss._vap_ssids[i], true);
      }
    }
    else {
      for (int i = 0; i < oss._vap_ssids.size(); i++) {
        if (oss._vap_ssids[i] == it.value()) {
          send_beacon(sta_mac, oss._vap_bssid, it.value(), true);
          break;
        }
      }
    }

    _packet_buffer.erase(it.key());
  }

	if (_debug_level % 10 > 0)
		fprintf(stderr, "[Odinagent.cc] Lvap added\n");

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
OdinAgent::set_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> vap_ssids)
{
  if (_debug_level % 10 > 0) {
		if (_debug_level / 10 == 1)
			fprintf(stderr, "##################################################################\n");
    fprintf(stderr, "[Odinagent.cc] set_lvap (%s, %s, %s, %s)\n", sta_mac.unparse_colon().c_str()
                                                , sta_ip.unparse().c_str()
                                                , sta_bssid.unparse().c_str()
                                                , vap_ssids[0].c_str());
		if (_debug_level / 10 == 1)
			fprintf(stderr, "##################################################################\n\n");
  }

  // First make sure that this VAP isn't here already, in which
  // case we'll just ignore the request
  if (_sta_mapping_table.find(sta_mac) == _sta_mapping_table.end())
  {
		if (_debug_level % 10 > 0)
			fprintf(stderr, "[Odinagent.cc] Ignoring LVAP set request because the agent is not hosting the LVAP\n");
    return -1;
  }

  OdinStationState state;
  state._vap_bssid = sta_bssid;
  state._sta_ip_addr_v4 = sta_ip;
  state._vap_ssids = vap_ssids;
  _sta_mapping_table.set(sta_mac, state);

  // We need to update the ARP responder
  Router *r = router();

	if (_debug_level % 10 > 1)
		if ( r->find("fh_arpr" ) == NULL )
			fprintf(stderr, "[Odinagent.cc] setLVAP: fh_arpr element not found\n");

  // ARP response to the ARP requests from device (coming from the wired network)
  int result = HandlerCall::call_write (r->find("fh_arpr"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());
  //fprintf(stderr,"[Odinagent.cc] setLVAP: result of the fh_arpr call write: %i\n", result);

	if (_debug_level % 10 > 1)
		if ( r->find("arp_resp" ) == NULL )
			fprintf(stderr, "[Odinagent.cc] setLVAP: arp_resp element not found\n");

  // ARP response to the ARP requests from the wireless network
  result = HandlerCall::call_write (r->find("arp_resp"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());

	if (_debug_level % 10 > 1)
		fprintf(stderr,"[Odinagent.cc] setLVAP: result of the arp_resp call write: %i\n", result);

  compute_bssid_mask();

	if (_debug_level % 10 > 0)
		fprintf(stderr, "[Odinagent.cc] Lvap set\n");

  return 0;
}


/**
 * Invoking this implies knocking
 * a client off the access point
 */
int
OdinAgent::remove_vap (EtherAddress sta_mac)
{
  if (_debug_level % 10 > 0) {
		if (_debug_level / 10 == 1)
			fprintf(stderr, "##################################################################\n");

    fprintf(stderr, "[Odinagent.cc] remove_lvap (%s)\n", sta_mac.unparse_colon().c_str());

		if (_debug_level / 10 == 1)
			fprintf(stderr, "##################################################################\n\n");
  }

  HashTable<EtherAddress, OdinStationState>::iterator it = _sta_mapping_table.find (sta_mac);

  // VAP doesn't exist on this node. Ignore.
  if (it == _sta_mapping_table.end())
    return -1;

  // We need to un-prime the ARP responders
  // FIXME: Don't rely on labelled name
  Router *r = router();
  HandlerCall::call_write (r->find("fh_arpr"), "remove", it.value()._sta_ip_addr_v4.unparse() + "/32");
  HandlerCall::call_write (r->find("arp_resp"), "remove", it.value()._sta_ip_addr_v4.unparse() + "/32");

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
* Receive a deauthentication packet
*/
void
OdinAgent::recv_deauth (Packet *p) {

        struct click_wifi *w = (struct click_wifi *) p->data();
        //uint8_t *ptr;
        //ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

        /*uint16_t algo = le16_to_cpu(*(uint16_t *) ptr);
        ptr += 2;

        uint16_t seq = le16_to_cpu(*(uint16_t *) ptr);
        ptr += 2;

        uint16_t status = le16_to_cpu(*(uint16_t *) ptr);
        ptr += 2;
*/
        EtherAddress src = EtherAddress(w->i_addr2);

        //If we're not aware of this LVAP, ignore
        if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
                p->kill();
                return;
        }

/*
        if (algo != WIFI_FC0_SUBTYPE_DEAUTH) {
                // click_chatter("%{element}: auth %d from %s not supported\n",
                // this,
                // algo,
                // src.unparse().c_str());
                p->kill();
                return;
        }
*/
				if (_debug_level % 10 > 0)
					fprintf(stderr, "[Odinagent.cc] STA ---> AP (Deauthentication)\n");

        // Notify the master
        StringAccum sa;
        sa << "deauthentication " << src.unparse_colon().c_str() << "\n";

        String payload = sa.take_string();
        WritablePacket *odin_disconnect_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
        output(3).push(odin_disconnect_packet);

        p->kill();

        print_stations_state();

        return;
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
  //uint8_t *rates_l = NULL; commented becaus it was not used

  while (ptr < end) {
  switch (*ptr) {
  case WIFI_ELEMID_SSID:
    ssid_l = ptr;
    break;
  case WIFI_ELEMID_RATES:
    //rates_l = ptr;
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

	if (_debug_level % 10 > 1)
		fprintf(stderr, "[Odinagent.cc] SSID frame: %s SSID AP: %s\n", ssid.c_str(), _ssid_agent_string.c_str());

  //If we're not aware of this LVAP, then send to the controller.
  if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
	  if ((ssid == "") || (ssid == _ssid_agent_string)) {  //if the ssid is blank (broadcast probe) or it is targetted to our SSID, forward it to the controller
		if (_debug_level % 10 > 1)
			fprintf(stderr, "[Odinagent.cc] Received probe request: not aware of this LVAP -> probe req sent to the controller\n");
		StringAccum sa;
		sa << "probe " << src.unparse_colon().c_str() << " " << ssid << "\n";
		String payload = sa.take_string();
		WritablePacket *odin_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
		output(3).push(odin_probe_packet);
		_packet_buffer.set (src, ssid);
	  }

    p->kill();
    return;
  }

  OdinStationState oss = _sta_mapping_table.get (src);

  /* If the client is performing an active scan, then
   * then respond from all available SSIDs. Else, if
   * the client is probing for a particular SSID, check
   * if we're indeed hosting that SSID and respond
   * accordingly. */
  if (ssid == "") {
      for (int i = 0; i < oss._vap_ssids.size(); i++) {
          send_beacon(src, oss._vap_bssid, oss._vap_ssids[i], true);
      }
  }

  //specific probe request
  if (ssid != "") {
    for (int i = 0; i < oss._vap_ssids.size(); i++) {
      if (oss._vap_ssids[i] == ssid) {
				if (_debug_level % 10 > 1)
					fprintf(stderr, "[Odinagent.cc] Received probe request, sending beacon...\n");
        send_beacon(src, oss._vap_bssid, ssid, true);
        break;
      }
    }
  }

  p->kill();
  return;
}


/** 
 * Send a beacon/probe-response. This code is
 * borrowed from the BeaconSource element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table.
 * 
 * Modified from the original in order to include a 
 * CSA-Beacon (channel switch announcement)
 * which is sent to a client but does not change the 
 * agent channel.
 * 
 * @author Luis Sequeira <sequeira@unizar.es>
 * 
 */
void
OdinAgent::send_beacon (EtherAddress dst, EtherAddress bssid, String my_ssid, bool probe) {
	if ( _csa == true && !(probe) ) { // For channel switch announcement
	  
		if (_debug_level % 10 > 1)
			fprintf(stderr, "[Odinagent.cc] Sending beacon for csa\n");// For testing only
	  
		/* send_beacon after channel switch */
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
	    5 +			/* csa */
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

	  ptr[2] = 0; 		//count
	  ptr[3] = 1; 		//period
	  ptr[4] = 0; 		//bitmap control
	  ptr[5] = 0; 		//paritial virtual bitmap
	  ptr += 2 + 4; 	// Channel Switch Count
	  actual_length += 2 + 4;
	  
	  /* csa */
	  
	  ptr[0] = 37;	// Element ID 
	  ptr[1] = 3; 	// Length
	  ptr[2] = 0; 	// Channel Switch Mode
	  ptr[3] = _new_channel; 	// New Channel Number
	  ptr[4] = _count_csa_beacon--; // Countdown
	  ptr += 5;
	  actual_length += 5;

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

	  Timestamp now = Timestamp::now();
	  Timestamp old =  _mean_table.get (dst);

	  if (old != NULL) {

	    Timestamp diff = now - old;
	    double new_val = diff.sec() * 1000000000 + diff.usec();

			if (_debug_level % 10 > 1)
				fprintf(stderr, "[Odinagent.cc] Out: %f\n", new_val);

	    _num_mean++;
	    double delta = new_val - _mean;
	    _mean = _mean + delta/_num_mean;
	    _m2 = _m2 + delta * (new_val - _mean);
	    _mean_table.erase (dst);
	  }

	  output(0).push(p);
	}

	else { // For NO channel switch announcement or probe responder
		
  /* For testing only */
  /*if ( probe ) {
		if (_debug_level % 10 > 1)
			fprintf(stderr, "[Odinagent.cc] Sending Probe Response\n");
  }
  else {
		if (_debug_level % 10 >1)
			fprintf(stderr, "[Odinagent.cc] Sending beacon for NO csa\n");
  }*/
		
  /* send_beacon before channel switch or probe response */
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

  Timestamp now = Timestamp::now();
  Timestamp old =  _mean_table.get (dst);

  if (old != NULL) {

    Timestamp diff = now - old;
    double new_val = diff.sec() * 1000000000 + diff.usec();

		if (_debug_level % 10 > 1)
			fprintf(stderr, "[Odinagent.cc] Out: %f\n", new_val);

    _num_mean++;
    double delta = new_val - _mean;
    _mean = _mean + delta/_num_mean;
    _m2 = _m2 + delta * (new_val - _mean);
    _mean_table.erase (dst);
  }

  output(0).push(p);
}
		

  /** 
   * Give some time before channel switch 
   * Used for testing only
   */
  /*if ( _csa_count == 0 ) {
	  _csa = true;
	  if (_debug_level % 10 > 1)
			fprintf(stderr, "[Odinagent.cc] _csa is true\n");
  }
  else {
	  _csa_count--;
	  if (_debug_level % 10 > 1)
			fprintf(stderr, "[Odinagent.cc] Decreasing _csa_count = %d\n", _csa_count);
  }*/
  
  /* Reset counters after channel switch */
  if ( _count_csa_beacon < 0 ) {
    	  _count_csa_beacon = _count_csa_beacon_default;
	  //_csa_count = _csa_count_default;
	  _csa = false;
  }
	

}


/**
* Receive an Open Auth request. This code is
* borrowed from the OpenAuthResponder element
* and is modified to retrieve the BSSID/SSID
* from the sta_mapping_table
*/
void
OdinAgent::recv_open_auth_request (Packet *p) {
    //if (_debug_level % 10 > 1)
		//	fprintf(stderr, "[Odinagent.cc] Inside recv_auth_request\n");

    struct click_wifi *w = (struct click_wifi *) p->data();
    uint8_t *ptr;
    ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

    uint16_t algo = le16_to_cpu(*(uint16_t *) ptr);
    ptr += 2;

    uint16_t seq = le16_to_cpu(*(uint16_t *) ptr);
    ptr += 2;

    //uint16_t status = le16_to_cpu(*(uint16_t *) ptr); commented because it was not used
    ptr += 2;

    EtherAddress src = EtherAddress(w->i_addr2);
    EtherAddress dst = EtherAddress(w->i_addr1);

    //If we're not aware of this LVAP, ignore
    if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
        p->kill();
        return;
    }

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

	  if (_debug_level % 10 > 0) {
			if (_debug_level / 10 == 1)
				fprintf(stderr, "##################################################################\n");

	    fprintf(stderr, "[Odinagent.cc] OpenAuth request     STA (%s) ----> AP (%s)\n", src.unparse_colon().c_str(), dst.unparse_colon().c_str());
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

        EtherAddress src = EtherAddress(w->i_addr2);

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

				if (_debug_level % 10 > 0)
						fprintf(stderr, "[Odinagent.cc] OpenAuth response    STA (%s) <---- AP (%s)\n", dst.unparse_colon().c_str(), src.unparse_colon().c_str());
    }

/**
 * Receive an association request. This code is
 * borrowed from the AssociationResponder element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::recv_assoc_request (Packet *p) {
  //if (_debug_level % 10 > 1)
	//	fprintf(stderr, "[Odinagent.cc] Inside recv_assoc_request\n");

  struct click_wifi *w = (struct click_wifi *) p->data();

  EtherAddress dst = EtherAddress(w->i_addr1);
  EtherAddress src = EtherAddress(w->i_addr2);
  //EtherAddress bssid = EtherAddress(w->i_addr3); commented because it was not used

  // Do not respond to node who's LVAP we're not
  // hosting.
  if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
    p->kill();
    return;
  }

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  /*capabilty */
  //uint16_t capability = le16_to_cpu(*(uint16_t *) ptr); commented because it was not used
  ptr += 2;

  /* listen interval */
  //uint16_t lint = le16_to_cpu(*(uint16_t *) ptr); commented because it was not used
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

  OdinStationState *oss = _sta_mapping_table.get_pointer (src);

  if (oss == NULL) {
    p->kill();
    return;
  }

  String ssid;
  String my_ssid = oss->_vap_ssids[0];
  if (ssid_l && ssid_l[1]) {
    ssid = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
  } else {
    /* there was no element or it has zero length */
    ssid = "";
  }

  uint16_t associd = 0xc000 | _associd++;
	if (_debug_level % 10 > 0)
		fprintf(stderr, "[Odinagent.cc] Association request  STA (%s) ----> AP (%s)\n", src.unparse_colon().c_str(), dst.unparse_colon().c_str());

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

  EtherAddress src = EtherAddress(w->i_addr2);

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

	if (_debug_level % 10 > 0) {
		fprintf(stderr, "[Odinagent.cc] Association response STA (%s) <---- AP (%s)\n", dst.unparse_colon().c_str(), src.unparse_colon().c_str());

		if (_debug_level / 10 == 1)
			fprintf(stderr, "##################################################################\n\n");

	}
  //Notify the master that a client has completed the auth/assoc procedure so it can stop the timer and prevent it from removing the lvap
  StringAccum sa;
  sa << "association " << dst.unparse_colon().c_str() << "\n";

  String payload = sa.take_string();
  WritablePacket *odin_association_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
  output(3).push(odin_association_packet);

  //print_stations_state();


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
  stat._signal = ceh->rssi + _signal_offset;
  stat._packets++;
  stat._last_received.assign_now();
/*
  if (_debug_level % 10 > 1){
        FILE * fp;
        fp = fopen ("/root/spring/shared/updated_stats.txt", "w");
        fprintf(fp, "* update_rx_stats: src = %s, rate = %i, noise = %i, signal = %i (%i dBm)\n", src.unparse_colon().c_str(), stat._rate, stat._noise, stat._signal, (stat._signal - 128)*-1); //-(value - 128)
        fclose(fp);
  }
*/
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
    // struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);

    // StationStats stat;
    // HashTable<EtherAddress, StationStats>::const_iterator it = _rx_stats.find(src);
    // if (it == _rx_stats.end())
    //   stat = StationStats();
    // else
    //   stat = it.value();

    // stat._rate = ceh->rate;
    // stat._noise = ceh->silence;
    // stat._signal = ceh->rssi + _signal_offset;
    // stat._packets++;
    // stat._last_received.assign_now();

    // _rx_stats.set (src, stat);
    update_rx_stats(p);

    type = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
    subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

    if (type == WIFI_FC0_TYPE_MGT) {

      // This is a management frame, now
      // we classify by subtype
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
          case WIFI_FC0_SUBTYPE_DEAUTH:
          {
             recv_deauth (p);
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
      if (_sta_mapping_table.find (src) == _sta_mapping_table.end()) {
        // FIXME: Inform controller accordingly? We'll need this
        // for roaming.

        p->kill ();
        return;
      }

			// Get the destination address
			EtherAddress dst = EtherAddress(w->i_addr3);

			// if the destination address is a known LVAP
			if (_sta_mapping_table.find (dst) != _sta_mapping_table.end()) {

				// Destination station is a Odin client
				WritablePacket *p_out = 0;	// make the packet writable, to be sent to the network
				p_out = p->uniqueify();
				if (!p_out) {
					return;
				}
		
				// Wifi encapsulation
				struct click_wifi *w_out = (struct click_wifi *) p_out->data();

				memset(p_out->data(), 0, sizeof(click_wifi));
				w_out->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA);
				w_out->i_fc[1] = 0;
				w_out->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & WIFI_FC1_DIR_FROMDS);
				
				// modify the MAC address fields of the Wi-Fi frame
				OdinStationState oss = _sta_mapping_table.get (dst);
				memcpy(w_out->i_addr1, dst.data(), 6);
				memcpy(w_out->i_addr2, oss._vap_bssid.data(), 6);
				memcpy(w_out->i_addr3, src.data(), 6);

				// send the frame by the output number 2
				output(2).push(p_out);
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
      //if (ntohs(e->ether_type) == ETHERTYPE_ARP) {
      //  click_ether_arp *ea = (click_ether_arp *) (e + 1);
      //  if (ntohs(ea->ea_hdr.ar_hrd) == ARPHRD_ETHER
      //      && ntohs(ea->ea_hdr.ar_pro) == ETHERTYPE_IP
      //      && ntohs(ea->ea_hdr.ar_op) == ARPOP_REPLY) {

      //    IPAddress ipa = IPAddress(ea->arp_spa);
      //    if (ipa == _default_gw_addr)
      //      memcpy(ea->arp_sha, oss._vap_bssid.data(), 6);
      //  }
      //}
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
  sub.last_publish_sent= Timestamp::now(); //this stores the last timestamp when a Publish was sent
  _subscription_list.push_back (sub);

	if (_debug_level % 10 > 0)
	 fprintf(stderr, "[Odinagent.cc] Subscription added\n");

}

void
OdinAgent::clear_subscriptions ()
{
  _subscription_list.clear();
  if (!_station_subs_table.empty())
	  _station_subs_table.clear();	//clear time table
	if (_debug_level % 10 > 0)
		fprintf(stderr, "[Odinagent.cc] Subscriptions cleared\n");

}

void
OdinAgent::match_against_subscriptions(StationStats stats, EtherAddress src)
{
  if(_subscription_list.size() == 0)
    return;

    if (MULTICHANNEL_AGENTS == 1) {
       // if the MAC is not in the mapping table, end the function
	   if (_sta_mapping_table.find (src) == _sta_mapping_table.end()) 
		      return;
	   if (_debug_level % 10 > 1)
		      fprintf(stderr, "[Odinagent.cc] MAC %s is in the mapping table\n",src.unparse_colon().c_str());
  }

  Timestamp now = Timestamp::now();
  Timestamp age;
  int count = 0;
  int i = 0; 
  int matched = 0;
  
  StringAccum subscription_matches_prev;
  StringAccum subscription_matches;

  for (Vector<OdinAgent::Subscription>::const_iterator iter = _subscription_list.begin();
           iter != _subscription_list.end(); iter++) {

    Subscription sub = *iter;
	i++;
	subscription_matches_prev.clear();

	// EtherAddress builds a 00:00:00:00:00:00 MAC address (this is for dealing with '*' subscriptions)
	// First I check if the address of the arrived packet matches
    if (sub.sta_addr != EtherAddress() && sub.sta_addr != src)
      continue;

	if (_debug_level % 10 > 1)
		fprintf(stderr, "[Odinagent.cc]  MAC %s in subscription list\n",sub.sta_addr.unparse_colon().c_str());

    /* TODO: Refactor to use a series of hash maps instead */
    switch (sub.rel) {
      case EQUALS: {
        if (sub.statistic == "signal" && stats._signal == sub.val) {
          subscription_matches_prev << " " << sub.subscription_id << ":" << stats._signal; 
		  matched = 1;
        } else if (sub.statistic == "rate" && stats._rate == sub.val) {
          subscription_matches_prev << " " <<  sub.subscription_id << ":" << stats._rate;
		  matched = 1;
        } else if (sub.statistic == "noise" && stats._noise == sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._noise;
		  matched = 1;
        } else if (sub.statistic == "_packets" && stats._packets == sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._packets;
		  matched = 1;
        }
        break;
      }
      case GREATER_THAN: {
       if (sub.statistic == "signal" && stats._signal > sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._signal;
		  matched = 1;
        } else if (sub.statistic == "rate" && stats._rate > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._rate;
		  matched = 1;
        } else if (sub.statistic == "noise" && stats._noise > sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._noise;
		  matched = 1;
        } else if (sub.statistic == "_packets" && stats._packets > sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._packets;
		  matched = 1;
        }
        break;
      }
      case LESSER_THAN: {
        if (sub.statistic == "signal" && stats._signal < sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._signal;
		  matched = 1;
        } else if (sub.statistic == "rate" && stats._rate < sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._rate;
		  matched = 1;
        } else if (sub.statistic == "noise" && stats._noise < sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._noise;
		  matched = 1;
        } else if (sub.statistic == "_packets" && stats._packets < sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._packets;
		  matched = 1;
        }
        break;
      }
    }

	if (matched) {
			if (sub.sta_addr != EtherAddress()) {
			// It is a specific subscription for a single MAC (not '*')
    			// Calculate the time since the last publish was sent
				if (_debug_level % 10 > 1)
					fprintf(stderr, "[Odinagent.cc]  It is a specific subscription for a single MAC (%s)\n",sub.sta_addr.unparse_colon().c_str());
				age = now - sub.last_publish_sent;
				if (_debug_level % 10 > 1)
					fprintf(stderr, "[Odinagent.cc]  Age: %s   Now: %s   last_publish_sent: %s\n",age.unparse().c_str(),now.unparse().c_str(), sub.last_publish_sent.unparse().c_str());
				if (age.sec() < THRESHOLD_PUBLISH_SENT)
					continue; // do not send the publish
				_subscription_list.at(i-1).last_publish_sent = now; // update the timestamp
				++count;
				subscription_matches << subscription_matches_prev.take_string();
				if (_debug_level % 10 > 1)
					fprintf(stderr, "[Odinagent.cc]  Update timestamp for subscription:  src: %s   timestamp: %s\n",sub.sta_addr.unparse_colon().c_str(), _subscription_list.at(i-1).last_publish_sent.unparse().c_str());
			}

			else { 
			// it is a '*' subscription:
				// check the table with pairs of 'src' and timestamps
				  if (_debug_level % 10 > 1)
						fprintf(stderr, "[Odinagent.cc]  It is a '*' subscription MAC (%s)\n",EtherAddress().unparse_colon().c_str());
				  if(_station_subs_table.find(src) != _station_subs_table.end()){
						// the src is already in the table
						 age = now - _station_subs_table.get (src);
						 if (_debug_level % 10 > 1)
							 fprintf(stderr, "[Odinagent.cc]  Age: %s   Now: %s   last_publish_sent: %s\n",age.unparse().c_str(),now.unparse().c_str(), _station_subs_table.get(src).unparse().c_str());
						 if (age.sec() < THRESHOLD_PUBLISH_SENT)
								 continue;
				   }
				   // I add a new register in the table or/and update it if exists
				   _station_subs_table.set (src, now);
				   ++count;
				   subscription_matches << subscription_matches_prev.take_string();
				   if (_debug_level % 10 > 1)
						 fprintf(stderr, "[Odinagent.cc]  Add/Update register _station_subs_table  src: %s   timestamp: %s\n", src.unparse_colon().c_str(), _station_subs_table.get(src).unparse().c_str());
				 } 
		  matched = 0;

	}
  }
  if (count > 0) { // if there are no matches, do not send anything to the controller

	StringAccum sa;
	
	sa << "publish " << src.unparse_colon().c_str() << " " << count << subscription_matches.take_string() << "\n";
	
	String payload = sa.take_string();
	if (_debug_level % 10 > 1)
		fprintf(stderr, "[Odinagent.cc]  Publish sent %s\n",payload.c_str());
	WritablePacket *odin_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
	output(3).push(odin_probe_packet);
  }


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
            << " " << it.value()._sta_ip_addr_v4
            <<  " " << it.value()._vap_bssid.unparse_colon();

          for (int i = 0; i < it.value()._vap_ssids.size(); i++) {
            sa << " " << it.value()._vap_ssids[i];
          }

          sa << "\n";
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
      sa << agent->_debug_level << "\n";
      break;
    }
    case handler_report_mean: {
      double variance = agent->_m2 / (agent->_num_mean -1);
      sa << agent->_mean <<  " " <<  agent->_num_mean << " " << variance << "\n";
      break;
    }
  }

  return sa.take_string();
}

/*
 * We have include new handlers an modified others
 * 
 * @author Luis Sequeira <sequeira@unizar.es>
 * 
 * */

int
OdinAgent::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{

  OdinAgent *agent = (OdinAgent *) e;

  switch (reinterpret_cast<uintptr_t>(user_data)) {
    case handler_add_vap:{
      IPAddress sta_ip;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;

      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("STA_IP", sta_ip)
            .read_mp("VAP_BSSID", vap_bssid)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }

      if (agent->add_vap (sta_mac, sta_ip, vap_bssid, ssidList) < 0)
        {
          return -1;
        }
      break;
    }
    case handler_set_vap:{
      IPAddress sta_ip;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;

      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("STA_IP", sta_ip)
            .read_mp("VAP_BSSID", vap_bssid)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }

      if (agent->set_vap (sta_mac, sta_ip, vap_bssid, ssidList) < 0)
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
    case handler_channel: { // Modified, now it change the physical channel
      int channel;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("CHANNEL", channel)
        .complete() < 0)
        {
          return -1;
        }

      agent->_channel = channel;
			if (agent->_debug_level % 10 > 0)
				fprintf(stderr, "[Odinagent.cc] ########### Changing to channel::::::::::::::::::::::::::::::::::::" + channel);
      std::stringstream ss;
      ss << "iw dev mon0 set channel " << channel;
      std::string str = ss.str();
      char *cstr = new char[str.length() + 1];
      strcpy(cstr, str.c_str());
      system(cstr);
      system("iw mon0 info");
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

			if (agent->_debug_level % 10 > 1)
				fprintf(stderr, "[Odinagent.cc] num_rows: %d\n", num_rows);

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
       	if (agent->_debug_level % 10 > 1)
					fprintf(stderr, "[Odinagent.cc] Subscription: %ld %s %s %i %f\n", sub_id, sta_addr.unparse_colon().c_str(), statistic.c_str(), relation, value);

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

      agent->_debug_level = debug;
      break;
    }
    case handler_probe_response: {

      EtherAddress sta_mac;
      EtherAddress vap_bssid;

      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("VAP_BSSID", vap_bssid)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }

      for (Vector<String>::const_iterator it = ssidList.begin();
            it != ssidList.end(); it++) {
        agent->send_beacon (sta_mac, vap_bssid, *it, true);
      }
      break;
    }
    case handler_probe_request: {
      EtherAddress sta_mac;
      String ssid = "";

      Args args = Args(agent, errh).push_back_words(str);

      if (args.read_mp("STA_MAC", sta_mac)
          .consume() < 0)
        {
          return -1;
        }

      if (!args.empty()) {
        if (args.read_mp("SSID", ssid)
              .consume() < 0)
          {
            return -1;
          }
      }
      StringAccum sa;
      sa << "probe " << sta_mac.unparse_colon().c_str() << " " << ssid << "\n";
      String payload = sa.take_string();

      agent->_mean_table.set (sta_mac, Timestamp::now());
      WritablePacket *odin_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
      agent->output(3).push(odin_probe_packet);
      break;
    }
    case handler_update_signal_strength: {
      EtherAddress sta_mac;
      int value;

      Args args = Args(agent, errh).push_back_words(str);

      if (args.read_mp("STA_MAC", sta_mac)
          .read_mp("VALUE", value)
          .consume() < 0)
        {
          return -1;
        }

      StationStats stat;
      HashTable<EtherAddress, StationStats>::const_iterator it = agent->_rx_stats.find(sta_mac);

      if (it == agent->_rx_stats.end())
        stat = StationStats();
      else
        stat = it.value();

      stat._signal = value;
      stat._packets++;
      stat._last_received.assign_now();

      agent->match_against_subscriptions(stat, sta_mac);
      agent->_rx_stats.set (sta_mac, stat);

      break;
    }
    case handler_signal_strength_offset: {
      int value;
      Args args = Args(agent, errh).push_back_words(str);

      if (args.read_mp("VALUE", value)
          .consume() < 0)
        {
          return -1;
        }

      agent->_signal_offset = value;
      break;
    }
    case handler_channel_switch_announcement: { // New handler for CSA-Beacon
      int new_channel;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;

			if (agent->_debug_level % 10 > 0)
				fprintf(stderr, "[Odinagent.cc] #################### Setting new channel and csa ::::::::::::::");      
      
      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("VAP_BSSID", vap_bssid)
	    .read_mp("CHANNEL", new_channel)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }
      
      agent->_new_channel = new_channel;//How to put the channel into new_channel?
      agent->_csa = true;

      for (Vector<String>::const_iterator it = ssidList.begin();
            it != ssidList.end(); it++) {
        agent->send_beacon (sta_mac, vap_bssid, *it, false);
      }
      
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
  add_read_handler("report_mean", read_handler, handler_report_mean);

  add_write_handler("add_vap", write_handler, handler_add_vap);
  add_write_handler("set_vap", write_handler, handler_set_vap);
  add_write_handler("remove_vap", write_handler, handler_remove_vap);
  add_write_handler("channel", write_handler, handler_channel);
  add_write_handler("interval", write_handler, handler_interval);
  add_write_handler("subscriptions", write_handler, handler_subscriptions);
  add_write_handler("debug", write_handler, handler_debug);
  add_write_handler("send_probe_response", write_handler, handler_probe_response);
  add_write_handler("testing_send_probe_request", write_handler, handler_probe_request);
  add_write_handler("handler_update_signal_strength", write_handler, handler_update_signal_strength);
  add_write_handler("signal_strength_offset", write_handler, handler_signal_strength_offset);
  add_write_handler("channel_switch_announcement", write_handler, handler_channel_switch_announcement);
}

/* This debug function prints info about clients */
void
OdinAgent::print_stations_state()
{
	if (_debug_level % 10 > 0) {
		if (_debug_level / 10 == 1)
			fprintf(stderr, "##################################################################\n");

		fprintf(stderr,"[Odinagent.cc] ##### Periodic report. Number of stations associated: %i\n", _sta_mapping_table.size());
		
		if(_sta_mapping_table.size() != 0) {

			// Initialize the statistics
			HashTable<EtherAddress, OdinAgent::StationStats>::const_iterator iter = _rx_stats.begin();
			
			// For each VAP
			for (HashTable<EtherAddress, OdinStationState>::iterator it	= _sta_mapping_table.begin(); it.live(); it++) {

				// Each VAP may have a number of SSIDs
				//for (int i = 0; i < it.value()._vap_ssids.size (); i++) {
					fprintf(stderr,"[Odinagent.cc]        Station -> BSSID: %s\n", (it.value()._vap_bssid).unparse_colon().c_str());
					fprintf(stderr,"[Odinagent.cc]                -> IP addr: %s\n", it.value()._sta_ip_addr_v4.unparse().c_str());
				//}

				//stats
				//Print info from our stations if available
				HashTable<EtherAddress, OdinAgent::StationStats>::const_iterator iter = _rx_stats.find(it.key());
				if (iter != _rx_stats.end()){
					fprintf(stderr,"[Odinagent.cc]                -> rate: %i (%i kbps)\n", iter.value()._rate,iter.value()._rate * 500 );
					fprintf(stderr,"[Odinagent.cc]                -> noise: %i\n", (iter.value()._noise));
					fprintf(stderr,"[Odinagent.cc]                -> signal: %i (%i dBm)\n", iter.value()._signal, iter.value()._signal - 256 ); // value - 256)
					fprintf(stderr,"[Odinagent.cc]                -> packets: %i\n", (iter.value()._packets));
					fprintf(stderr,"[Odinagent.cc]                -> last heard: %d.%06d \n", (iter.value()._last_received).sec(), (iter.value()._last_received).subsec());
					fprintf(stderr,"[Odinagent.cc]\n");
				}
			}
			if (_debug_level / 10 == 1)
				fprintf(stderr, "##################################################################\n\n");
		}
	}
}

/* This function erases the rx_stats of old clients */
void
cleanup_lvap (Timer *timer, void *data)
{

    OdinAgent *agent = (OdinAgent *) data;
    Vector<EtherAddress> buf;

    // Clear out old rxstat entries.
    for (HashTable<EtherAddress, OdinAgent::StationStats>::const_iterator iter = agent->_rx_stats.begin();
    iter.live(); iter++){

        Timestamp now = Timestamp::now();
        Timestamp age = now - iter.value()._last_received;

        if (age.sec() > THRESHOLD_OLD_STATS){
            buf.push_back (iter.key());
        }
        //If out station has been inactive longer than the given threshold we remove the lvap and info at the master, then the stats will be removed too
        if(age > THRESHOLD_REMOVE_LVAP && agent->_sta_mapping_table.find(iter.key()) != agent->_sta_mapping_table.end()){

            // Notify the master to remove client info and lvap, then agent clears the lvap
            StringAccum sa;
            sa << "deauthentication " << iter.key().unparse_colon().c_str() << "\n";

            String payload = sa.take_string();
            WritablePacket *odin_disconnect_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
            agent->output(3).push(odin_disconnect_packet);

        }
    }

    	if (agent->_debug_level % 10 > 0)
				fprintf(stderr,"\n[Odinagent.cc] Cleaning old info from stations not associated\n");

    for (Vector<EtherAddress>::const_iterator iter = buf.begin(); iter != buf.end(); iter++){

        //If its our station we dont remove, we need the _last_received to see if its inactive or not
        if(agent->_sta_mapping_table.find(*iter) != agent->_sta_mapping_table.end())
            continue;

				if (agent->_debug_level % 10 > 1)
					fprintf(stderr, "[Odinagent.cc]   station with MAC addr: %s\n", iter->unparse_colon().c_str());
        agent->_rx_stats.erase (*iter);
    }

    agent->_packet_buffer.clear();
    timer->reschedule_after_sec(RESCHEDULE_INTERVAL_STATS);
}

/* Thread for general purpose (i.e. print debug info about them)*/
void misc_thread(Timer *timer, void *data){

    OdinAgent *agent = (OdinAgent *) data;

    agent->print_stations_state();

    timer->reschedule_after_sec(RESCHEDULE_INTERVAL_GENERAL);

}


CLICK_ENDDECLS
EXPORT_ELEMENT(OdinAgent)
ELEMENT_REQUIRES(userlevel)