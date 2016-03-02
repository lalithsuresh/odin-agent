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


#ifndef CLICK_ODINAGENT_HH
#define CLICK_ODINAGENT_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashtable.hh>
#include <click/ipaddress.hh>
#include <click/deque.hh>
#include <elements/wifi/availablerates.hh>
CLICK_DECLS

/*
=c
OdinAgent

=s basictransfer
No ports

=d
Acts as an agent for the Odin controller

=a
Whatever
*/

class OdinAgent : public Element {
public:
  OdinAgent();
  ~OdinAgent();

  // From Click
  const char *class_name() const	{ return "OdinAgent"; }
  const char *port_count() const  { return "2/4"; }
  const char *processing() const  { return PUSH; }
  int initialize(ErrorHandler *); // initialize element
  int configure(Vector<String> &, ErrorHandler *);
  void add_handlers();
  void run_timer(Timer *timer);
  void push(int, Packet *);


  // Extend this struct to add
  // new per-sta VAP state
  class OdinStationState {
    public:
      //OdinStationState() {_vap_bssid = EtherAddress(); _sta_ip_addr_v4 = IPAddress(); _vap_ssid = String();}
      EtherAddress _vap_bssid;
      IPAddress _sta_ip_addr_v4; // Might need to change for v6
      Vector<String> _vap_ssids;
  };

  enum relation_t {
    EQUALS = 0,
    GREATER_THAN = 1,
    LESSER_THAN = 2,
  };

  class Subscription {
    public:
        long subscription_id;
        EtherAddress sta_addr;
        String statistic;
        relation_t rel;
        double val;
		Timestamp last_publish_sent; // Stores the timestamp when the last publish has been sent for a single subscription
  };

  // Methods to handle and send
  // 802.11 management messages
  void recv_probe_request (Packet *p);
  void recv_deauth (Packet *p);
  void send_beacon (EtherAddress dst, EtherAddress bssid, String my_ssid, bool probe);
  void recv_assoc_request (Packet *p);
  void send_assoc_response (EtherAddress, uint16_t status, uint16_t associd);
  void recv_open_auth_request (Packet *p);
  void send_open_auth_response (EtherAddress dst, uint16_t seq, uint16_t status);
  Packet* wifi_encap (Packet *p, EtherAddress bssid);

  // Methods to handle pub-sub
  void add_subscription (long subscription_id, EtherAddress addr, String statistic, relation_t r, double val);
  void clear_subscriptions ();

  // Methods to add/remove VAPs.
  int add_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> sta_ssid);
  int set_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> vap_ssid);
  int remove_vap (EtherAddress sta_mac);

  //debug
  void print_stations_state();


  // Read/Write handlers
  static String read_handler(Element *e, void *user_data);
  static int write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh);


  // Extend this enum table to add
  // new handlers.
  enum {
    handler_view_mapping_table,
    handler_num_slots,
    handler_add_vap,
    handler_set_vap,
    handler_rxstat,
    handler_remove_vap,
    handler_channel,
    handler_interval,
    handler_subscriptions,
    handler_debug,
    handler_probe_response,
    handler_probe_request,
    handler_report_mean,
    handler_update_signal_strength,
    handler_signal_strength_offset,
    handler_channel_switch_announcement,
  };

  // Rx-stats about stations
  class StationStats {
  public:
    int _rate;
    int _noise;
    int _signal;

    int _packets;
    Timestamp _last_received;

    StationStats() {
      memset(this, 0, sizeof(*this));
    }
  };

  // All VAP related information should be accessible here on
  // a per client basis
  HashTable<EtherAddress, OdinStationState> _sta_mapping_table;
  HashTable<EtherAddress, Timestamp> _mean_table;
  HashTable<EtherAddress, Timestamp> _station_subs_table; // Table storing the last time when a publish for an ETH address has been sent

  // For stat collection
  double _mean;
  double _num_mean;
  double _m2; // for estimated variance
  int _signal_offset;

  // Keep track of rx-statistics of stations from which
  // we hear frames. Only keeping track of data frames for
  // now.
  HashTable<EtherAddress, StationStats> _rx_stats;

  int _interval_ms; // Beacon interval: common between all VAPs for now
  int _channel; // Channel to be shared by all VAPs.
  int _new_channel; // New channel for CSA
  bool _csa; // For channel switch announcement
  int _count_csa_beacon; // For channel switch announcement
  int _count_csa_beacon_default; // Default number of beacons before channel switch
  int _csa_count; // For _csa FALSE-->TRUE
  int _csa_count_default;
  Vector<Subscription> _subscription_list;
  bool _debug;
  HashTable<EtherAddress, String> _packet_buffer;
  void match_against_subscriptions(StationStats stats, EtherAddress src);

private:
  void compute_bssid_mask ();
  void update_rx_stats(Packet *p);
  EtherAddress _hw_mac_addr;
  class AvailableRates *_rtable;
  int _associd;
  Timer _beacon_timer;
  Timer _clean_stats_timer;
  Timer _general_timer;
  IPAddress _default_gw_addr;
  String _debugfs_string;
  String _ssid_agent_string;	// stores the SSID of the agent
};


CLICK_ENDDECLS
#endif
