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
      String _vap_ssid;
      uint8_t state_4way;
      uint8_t replay_counter[8];
      uint8_t tk1[16];
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
  };

  // Methods to handle and send
  // 802.11 management messages
  void recv_probe_request (Packet *p);
  void send_beacon (EtherAddress dst, EtherAddress bssid, String my_ssid, bool probe);
  void recv_assoc_request (Packet *p);
  void send_assoc_response (EtherAddress, uint16_t status, uint16_t associd);
  void recv_open_auth_request (Packet *p);
  void send_open_auth_response (EtherAddress dst, uint16_t seq, uint16_t status);
  void send_wpa_eapol_key_1 (EtherAddress dst);
  void send_wpa_eapol_key_3 (EtherAddress dst, struct wpa_ptk *ptk, uint8_t *gtk);
  void recv_wpa_eapol_key (Packet *p);

  Packet* wifi_encap (Packet *p, EtherAddress bssid);

  // Methods to handle pub-sub
  void add_subscription (long subscription_id, EtherAddress addr, String statistic, relation_t r, double val);
  void clear_subscriptions ();

  // Methods to add/remove VAPs.
  int add_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, String sta_ssid);
  int set_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, String vap_ssid);
  int remove_vap (EtherAddress sta_mac);

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

  // Keep track of rx-statistics of stations from which
  // we hear frames. Only keeping track of data frames for
  // now.
  HashTable<EtherAddress, StationStats> _rx_stats;

  int _interval_ms; // Beacon interval: common between all VAPs for now
  int _channel; // Channel to be shared by all VAPs.
  Vector<Subscription> _subscription_list;
  bool _debug;
  HashTable<EtherAddress, void *> _packet_buffer;

private:
  void compute_bssid_mask ();
  void match_against_subscriptions(StationStats stats, EtherAddress src);
  void update_rx_stats(Packet *p);
  EtherAddress _hw_mac_addr;
  class AvailableRates *_rtable;
  int _associd;
  Timer _beacon_timer;
  Timer _cleanup_timer;
  IPAddress _default_gw_addr;

  /* Crypto code */
  int wpa_pmk_to_ptk(const uint8_t *pmk, size_t pmk_len, const char *label,
        const uint8_t *addr1, const uint8_t *addr2,
        const uint8_t *nonce1, const uint8_t *nonce2,
        uint8_t *ptk, size_t ptk_len, int use_sha256);
  int sha1_prf(const uint8_t *key, size_t key_len, const char *label,
       const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len);
  void wpa_get_ntp_timestamp(uint8_t *buf);
  int wpa_gmk_to_gtk(const uint8_t *gmk, const char *label, const uint8_t *addr,
        const uint8_t *gnonce, uint8_t *gtk, size_t gtk_len);
  int wpa_verify_key_mic(struct wpa_ptk *PTK, uint8_t *data, size_t data_len);

  //void sha1_prf(unsigned char *base, size_t bl, unsigned char *dist, size_t dl, unsigned char *out, size_t ol);
  int sha1_vector(size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac);
  int hmac_sha1_vector(const uint8_t *key, size_t key_len, size_t num_elem,
         const uint8_t *addr[], const size_t *len, uint8_t *mac);
  int wpa_eapol_key_mic(const uint8_t *key, int ver, const uint8_t *buf, size_t len,
          uint8_t *mic);
  int hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac);
  void * aes_encrypt_init(const uint8_t *key, size_t len);
  void aes_encrypt(void *ctx, const uint8_t *plain, uint8_t *crypt);
  void aes_encrypt_deinit(void *ctx);
  int aes_wrap(const uint8_t *kek, int n, const uint8_t *plain, uint8_t *cipher);


  struct HookPair {
     OdinAgent *obj;
     EtherAddress dst;
     HookPair(OdinAgent *o, EtherAddress _dst) {obj = o; dst = _dst; }
   private:
     HookPair() { }
   };
   
  static void send_eapol_hook(Timer*, void *v) {
  
  ((HookPair *) v)->obj->send_wpa_eapol_key_1(((HookPair *) v)->dst);
  //delete t;
  };
};


CLICK_ENDDECLS
#endif