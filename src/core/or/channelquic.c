// // Created by jaap on 17-12-20.
//

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */
#define CHANNEL_OBJECT_PRIVATE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>
#include <netdb.h>
#include <event.h>
#include <lib/tls/x509.h>


#define ORCONN_EVENT_PRIVATE

#include "core/or/or.h"
#include "core/or/channel.h"
#include "core/or/channelquic.h"
#include "app/config/resolve_addr.h"
#include "core/or/circuitmux_ewma.h"
#include "core/or/extendinfo.h"
#include "core/or/cell_st.h"
#include "core/or/cell_queue_st.h"
#include "core/or/connection_or.h"
#include "core/proto/proto_cell.h"
#include "connection_st.h"
#include "trunnel/link_handshake.h"
#include "scheduler.h"
#include "command.h"
#include "feature/relay/relay_handshake.h"
#include "feature/relay/routerkeys.h"
#include "var_cell_st.h"
#include "feature/nodelist/torcert.h"
#include "lib/evloop/compat_libevent.h"
#include "lib/tls/tortls.h"
#include "feature/relay/router.h"
#include "core/or/orconn_event.h"
#include "core/or/circuitstats.h"
#include "feature/stats/rephist.h"
#include "feature/dirauth/authmode.h"
#include "feature/dirauth/reachability.h"
#include "feature/control/control_events.h"

static void channel_quic_close_method(channel_t *chan);

static const char *channel_quic_describe_transport_method(channel_t *chan);

static void channel_quic_free_method(channel_t *chan);

static double channel_quic_get_overhead_estimate_method(channel_t *chan);

static int channel_quic_get_remote_addr_method(const channel_t *chan,
                                               tor_addr_t *addr_out);

static int
channel_quic_get_transport_name_method(channel_t *chan, char **transport_out);

static const char *channel_quic_describe_peer_method(const channel_t *chan);

static int channel_quic_has_queued_writes_method(channel_t *chan);

static int channel_quic_is_canonical_method(channel_t *chan);

static int
channel_quic_matches_extend_info_method(channel_t *chan,
                                        extend_info_t *extend_info);

static int channel_quic_matches_target_method(channel_t *chan,
                                              const tor_addr_t *target);

static int channel_quic_num_cells_writeable_method(channel_t *chan);

static size_t channel_quic_num_bytes_queued_method(channel_t *chan);

static int channel_quic_write_cell_method(channel_t *chan,
                                          cell_t *cell);

static int channel_quic_write_packed_cell_method(channel_t *chan,
                                                 packed_cell_t *packed_cell);

static int channel_quic_write_var_cell_method(channel_t *chan,
                                              var_cell_t *var_cell);

static char *fmt_quic_id(uint8_t *array);

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len);


static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len);

static void stateless_retry(const uint8_t *scid, size_t scid_len, const uint8_t *dcid,
                            size_t dcid_len, uint8_t *token, size_t token_len,
                            uint32_t version, struct sockaddr_storage *peer_addr,
                            socklen_t peer_addr_len);

static void channel_quic_ensure_socket(void);

static void channel_quic_read_streams(channel_quic_t *quicchan);

static uint64_t get_stream_id_for_circuit(channel_quic_t *quicchan, circid_t circ_id);

static void cell_unpack(cell_t *dest, const char *src, int wide_circ_ids);

static void channel_quic_on_incoming_cell(channel_quic_t *quicchan, cell_t *cell);

static void channel_quic_on_incoming_var_cell(channel_quic_t *quicchan, var_cell_t *var_cell);

static void on_connection_established(channel_quic_t *quicchan);

static void channel_quic_state_publish(channel_quic_t *quicchan, uint8_t state);

static void insert_stream_id(channel_quic_t *quicchan, uint64_t stream_id, circid_t circ_id);

static void channel_quic_timeout_cb(evutil_socket_t listener, short event, void *arg);

static tor_socket_t udp_socket;

/**
 * Hashmap that maps (chan_id:circ_id) to stream_id
 */
static HT_HEAD(circid_ht, circid_ht_entry_t) circs = HT_INITIALIZER();

HT_PROTOTYPE(circid_ht, circid_ht_entry_t, node, circid_entry_hash, circid_entry_equal);
HT_GENERATE2(circid_ht, circid_ht_entry_t, node, circid_entry_hash, circid_entry_equal, 0.6, tor_reallocarray,
             tor_free);


static HT_HEAD(channel_quic_ht, channel_quic_t) quic_ht = HT_INITIALIZER();

HT_PROTOTYPE(channel_quic_ht, channel_quic_t, node, channel_quic_hash, channel_quic_equal);

void channel_process_auth_challenge_cell(channel_quic_t *quicchan, var_cell_t *cell);

void channel_quic_handle_id_cert_cell(channel_quic_t *quicchan, var_cell_t *cell);

HT_GENERATE2(channel_quic_ht, channel_quic_t, node, channel_quic_hash, channel_quic_equal,
             0.6, tor_reallocarray, tor_free_);


channel_quic_t *
channel_quic_create(struct sockaddr_in *peer_addr, uint8_t cid[CONN_ID_LEN], quiche_conn *conn, bool started_here) {
  log_info(LD_CHANNEL, "QUIC: Creating channel cid=%s, addr=%s", fmt_quic_id(cid),
           tor_sockaddr_to_str(
               (const struct sockaddr *) peer_addr));
  channel_quic_t *quicchan = tor_malloc_zero(sizeof(*quicchan));
  channel_t *chan = &(quicchan->base_);
  channel_quic_common_init(quicchan);
  quicchan->started_here = started_here;
  quicchan->is_established = 0;
  quicchan->addr = malloc(sizeof(struct sockaddr));
  memcpy(quicchan->addr, peer_addr, sizeof(struct sockaddr_in));
  quicchan->next_stream_id = 4; // Least significant bit of stream ID determines whether client/server initiated
  memcpy(quicchan->cid, cid, CONN_ID_LEN);
  quicchan->quiche_conn = conn;

  tor_addr_t tor_addr;
  uint16_t port;
  tor_addr_from_sockaddr(&tor_addr, (struct sockaddr *) quicchan->addr, &port);
  chan->is_local = is_local_to_resolve_addr(&tor_addr);
  chan->wide_circ_ids = 1;
  if (started_here) {
    channel_mark_outgoing(chan);
  } else {
    channel_mark_incoming(chan);
  }

  struct event *timeout_event =
      evtimer_new(tor_libevent_get_base(), channel_quic_timeout_cb, (void *) quicchan);
  quicchan->timer = timeout_event;
  event_add(timeout_event, NULL);

  command_setup_channel(chan);
  log_debug(LD_CHANNEL, "streamid: new channel=%lu stream_id=%lu, addr=%s", chan->global_identifier,
            quicchan->next_stream_id,
            tor_sockaddr_to_str((const struct sockaddr *) quicchan->addr));
  channel_quic_state_publish(quicchan, OR_CONN_STATE_CONNECTING);

  channel_quic_flush_egress(quicchan);
  HT_REPLACE(channel_quic_ht, &quic_ht, quicchan);
  log_debug(LD_CHANNEL, "QUIC: Inserted cid=%s into HT", fmt_quic_id(cid));
  return quicchan;
}


channel_t *channel_quic_connect(const tor_addr_t *addr, uint16_t port, const char *id_digest,
                                const struct ed25519_public_key_t *ed_id) {
  struct sockaddr_in *sock_addr;
  sock_addr = tor_malloc(sizeof(struct sockaddr_storage));
  tor_addr_to_sockaddr(addr, port, (struct sockaddr *) sock_addr, sizeof(struct sockaddr_storage));

  quiche_config *config = create_quiche_config(true);
  uint8_t scid[CONN_ID_LEN];
  fill_with_random_bytes(scid, CONN_ID_LEN);

  log_info(LD_CHANNEL, "QUIC: connecting addr=%s, cid=%s", tor_sockaddr_to_str((struct sockaddr *) sock_addr),
           fmt_quic_id(scid));

  char host[TOR_ADDR_BUF_LEN];
  tor_addr_to_str(host, addr, sizeof(host), 0);

  quiche_conn *conn = quiche_connect(host, scid, CONN_ID_LEN, config);
  if (conn == NULL) {
    fprintf(stderr, "QUIC: failed to create connection\n");
    return NULL;
  }
  channel_quic_t *quicchan = channel_quic_create(sock_addr, scid, conn, true);
  channel_t *chan = QUIC_CHAN_TO_BASE(quicchan);
  channel_set_identity_digest(chan, id_digest, ed_id);
  channel_register(chan);
  return chan;
}


/**
 * Called on incoming data on the UDP listener socket.
 *
 * Extract the connection id from QUIC headers.
 * Look up the corresponding channel, or create a new one if none found.
 *
 *
 * @param sock
 * @return
 */
int channel_quic_on_incoming(tor_socket_t sock) {
  static uint8_t buf[65535];

  struct sockaddr_in peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);
  memset(&peer_addr, 0, peer_addr_len);

  ssize_t read = recvfrom(sock, buf, sizeof(buf), 0,
                          (struct sockaddr *) &peer_addr, &peer_addr_len);

  circuit_build_times_network_is_live(get_circuit_build_times_mutable());
  if (read < 0) {
    log_warn(LD_CHANNEL, "QUIC: read() error %zd", read);
    return -1;
  }
  uint8_t type;
  uint32_t version;

  uint8_t scid[CONN_ID_LEN];
  size_t scid_len = sizeof(scid);

  uint8_t dcid[CONN_ID_LEN];
  size_t dcid_len = sizeof(dcid);

  uint8_t odcid[CONN_ID_LEN];
  size_t odcid_len = sizeof(odcid);

  uint8_t token[MAX_TOKEN_LEN];
  size_t token_len = sizeof(token);

  int rc =
      quiche_header_info(buf, read, CONN_ID_LEN, &version, &type, scid,
                         &scid_len, dcid, &dcid_len, token, &token_len);
  if (rc < 0) {
    log_warn(LD_CHANNEL, "QUIC: Quiche header info error");
    return -1;
  }
  channel_quic_t channel_key;
  memcpy(channel_key.cid, dcid, dcid_len);
  channel_quic_t *quicchan = HT_FIND(channel_quic_ht, &quic_ht, &channel_key);

  if (quicchan) {
    ssize_t recv = quiche_conn_recv(quicchan->quiche_conn, buf, read);
    if (recv < 0) {
      log_warn(LD_CHANNEL, "QUIC: Receive error on existing channel, recv=%zd", recv);
    }
    quicchan->bootstrap_stage += 1;
    if (quicchan->bootstrap_stage == 1) {
      channel_quic_state_publish(quicchan, OR_CONN_STATE_TLS_HANDSHAKING);
    } else if (quicchan->bootstrap_stage == 2) {
      channel_quic_state_publish(quicchan, OR_CONN_STATE_OR_HANDSHAKING_V3);
    }
    int established = quiche_conn_is_established(quicchan->quiche_conn);
    if (established) {
      if (!quicchan->is_established) {
        on_connection_established(quicchan);
      }
      channel_quic_read_streams(quicchan);
    }
    log_debug(LD_CHANNEL, "QUIC: rx existing recv=%zdb, cid=%s, addr=%s, established=%d", recv,
              fmt_quic_id(dcid),
              tor_sockaddr_to_str(
                  (const struct sockaddr *) &peer_addr), established);
    channel_quic_flush_egress(quicchan);
  } else {
    if (!quiche_version_is_supported(version)) {
      log_warn(LD_CHANNEL, "QUIC: Version unsupported, version=%d", version);
      return 0; // TODO
    }
    if (token_len == 0) {
      stateless_retry(scid, scid_len, dcid, dcid_len, token, token_len,
                      version, (struct sockaddr_storage *) &peer_addr, peer_addr_len);
      return 0;
    }
    if (!validate_token(token, token_len, (struct sockaddr_storage *) &peer_addr, peer_addr_len, odcid, &odcid_len)) {
      log_warn(LD_CHANNEL, "QUIC: Token validation failed");
      return -1;
    }

    quiche_config *config = create_quiche_config(false);
    quiche_conn *conn = quiche_accept(dcid, dcid_len, odcid, odcid_len, config);
    ssize_t recv = quiche_conn_recv(conn, buf, read);
    if (recv < 0) {
      log_warn(LD_CHANNEL, "QUIC: receive error, %zd", recv);
    }
    log_debug(LD_CHANNEL, "QUIC: rx new recv=%zdb, cid=%s, addr=%s", recv, fmt_quic_id(dcid),
              tor_sockaddr_to_str(
                  (const struct sockaddr *) &peer_addr));
    quicchan = channel_quic_create(&peer_addr, dcid, conn, false);
    channel_register(QUIC_CHAN_TO_BASE(quicchan));
  }
  return 0;
}


static void stateless_retry(const uint8_t *scid, size_t scid_len, const uint8_t *dcid,
                            size_t dcid_len, uint8_t *token, size_t token_len,
                            uint32_t version, struct sockaddr_storage *peer_addr,
                            socklen_t peer_addr_len) {
  static uint8_t out[MAX_DATAGRAM_SIZE];
  log_info(LD_CHANNEL, "QUIC: performing Stateless retry");

  mint_token(dcid, dcid_len, peer_addr, peer_addr_len, token, &token_len);

  uint8_t new_cid[CONN_ID_LEN];
  if (fill_with_random_bytes(new_cid, CONN_ID_LEN) == NULL) {
    log_warn(LD_CHANNEL, "QUIC: Created cid for retry packet failed");
    return;
  }

  ssize_t written =
      quiche_retry(scid, scid_len, dcid, dcid_len, new_cid, CONN_ID_LEN,
                   token, token_len, version, out, sizeof(out));

  if (written < 0) {
    log_warn(LD_CHANNEL, "QUIC: failed to create retry packet: %zd", written);
    return;
  }

  channel_quic_ensure_socket();
  log_info(LD_CHANNEL, "QUIC: Sending %zd bytes to %s over %d", written, tor_sockaddr_to_str(
      (const struct sockaddr *) peer_addr), udp_socket);
  ssize_t sent = sendto(udp_socket, out, written, 0,
                        (struct sockaddr *) peer_addr, peer_addr_len);
  if (sent != written) {
    log_warn(LD_CHANNEL, "QUIC: failed to send retry packet, rv=%zd, errno=%d", sent, errno);
    return;
  }
  log_info(LD_CHANNEL, "QUIC: Sent retry packet, sent=%zdb", sent);
}


static void debug_log(const char *line, void *argp) {
  // Unused param
  (void) argp;
  log_debug(LD_CHANNEL, "%s", line);
}

quiche_config *create_quiche_config(bool is_client) {
  quiche_enable_debug_logging(debug_log, NULL);
  quiche_config *config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if (config == NULL) {
    log_info(LD_CHANNEL, "QUIC: failed to create config");
    return NULL;
  }

  quiche_config_set_application_protos(config,
                                       (uint8_t *) "\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 27);
  quiche_config_set_max_idle_timeout(config, 3600000);
  quiche_config_set_max_udp_payload_size(config, MAX_DATAGRAM_SIZE);
  quiche_config_set_initial_max_data(config, 1000000000);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 100000000);
  quiche_config_set_initial_max_stream_data_bidi_remote(config, 100000000);
  quiche_config_set_initial_max_streams_bidi(config, 100);
  quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);


  if (!is_client) {
    log_debug(LD_CHANNEL, "QUIC: loading certs");
    int rv = quiche_config_load_cert_chain_from_pem_file(config, "keys/link_cert.pem");
    if (rv < 0) {
      log_warn(LD_CHANNEL, "QUIC: Loading cert failed");
    }
    rv = quiche_config_load_priv_key_from_pem_file(config, "keys/link_key.pem");
    if (rv < 0) {
      log_warn(LD_CHANNEL, "QUIC: Loading key failed");
    }
  }

  return config;
}

static int get_rng(void) {
  int rng = open("/dev/urandom", O_RDONLY);
  if (rng < 0) {
    log_warn(LD_CHANNEL, "QUIC: failed to open /dev/urandom");
  }
  return rng;
}

uint8_t *fill_with_random_bytes(uint8_t *array, size_t array_len) {
  int rng = get_rng();
  ssize_t ret = read(rng, array, array_len);
  if (ret < 0) {
    perror("Failed to read random bytes");
  }
  return array;
}

static void
channel_quic_close_method(channel_t *chan) {
  log_info(LD_CHANNEL, "QUIC: close chan");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  tor_assert(quicchan);
  int ret = quiche_conn_close(quicchan->quiche_conn, false, 0, (uint8_t *) "close called", 0);
  if (ret < 0) {
    perror("Closing connection failed");
  }
}

channel_quic_t *
channel_quic_from_base(channel_t *chan) {
  if (!chan) return NULL;

  tor_assert(chan->magic == QUIC_CHAN_MAGIC);

  return (channel_quic_t *) (chan);
}

channel_t *
channel_quic_to_base(channel_quic_t *quicchan) {
  if (!quicchan) return NULL;

  return &(quicchan->base_);
}


static const char *
channel_quic_describe_transport_method(channel_t *chan) {
  if (!chan) {
    return "QUIC channel (null)";
  }
  return "QUIC channel";
}

static void
channel_quic_free_method(channel_t *chan) {
  log_info(LD_CHANNEL, "QUIC: free method");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);

  if (quicchan->quiche_conn) {
    quiche_conn_free(quicchan->quiche_conn);
  }
}


static double
channel_quic_get_overhead_estimate_method(channel_t *chan) {
  if (!chan) {
    log_warn(LD_CHANNEL, "channel_quic_get_overhead_estimate_method called without channel");
  }
  log_info(LD_CHANNEL, "QUIC: overhead estimate requested");
  double overhead = 1.0;
  // TODO
  return overhead;
}


static int
channel_quic_get_remote_addr_method(const channel_t *chan,
                                    tor_addr_t *addr_out) {

  log_info(LD_CHANNEL, "QUIC: remote addr requested");
  const channel_quic_t *quicchan = CONST_BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(addr_out);

  uint16_t port;
  tor_addr_from_sockaddr(addr_out, (const struct sockaddr *) quicchan->addr, &port);

  return 1;
}

static const char *
channel_quic_describe_peer_method(const channel_t *chan) {
  const channel_quic_t *quicchan = CONST_BASE_CHAN_TO_QUIC(chan);
  tor_assert(quicchan);


  if (*quicchan->cid) {
    return "<QUIC channel>";
  } else {
    return "(No connection)";
  }
}

static int
channel_quic_get_transport_name_method(channel_t *chan, char **transport_out) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(transport_out);
  tor_assert(quicchan->quiche_conn);


  *transport_out = tor_strdup("QUIC Transport");
  return 0;
}


static int
channel_quic_has_queued_writes_method(channel_t *chan) {
  log_info(LD_CHANNEL, "QUIC: has queued writes requestsed");
//  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return 1; // TODO
}

int channel_quic_is_canonical_method(channel_t *chan) {
  log_info(LD_CHANNEL, "QUIC: is_canonical requested");
  return 1;
}

int channel_quic_matches_extend_info_method(channel_t *chan, extend_info_t *extend_info) {
  log_info(LD_CHANNEL, "QUIC: matches extend info requested");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  tor_assert(quicchan);
  tor_addr_t tor_addr;
  uint16_t port;
  tor_addr_from_sockaddr(&tor_addr, (const struct sockaddr *) quicchan->addr, &port);
  return extend_info_has_orport(extend_info,
                                &tor_addr,
                                quicchan->addr->sin_port);
}

int channel_quic_matches_target_method(channel_t *chan, const tor_addr_t *target) {
  log_info(LD_CHANNEL, "QUIC: matches target method requestsed");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(target);
  tor_addr_t tor_addr;
  uint16_t port;
  tor_addr_from_sockaddr(&tor_addr, (const struct sockaddr *) quicchan->addr, &port);
  return tor_addr_eq(&tor_addr, target);
}

int channel_quic_num_cells_writeable_method(channel_t *chan) {
  log_info(LD_CHANNEL, "QUIC: num bytes cells writable requested");
  // Amount of cells within one Datagram, TODO: that's probably not the way, set to higher?
  return MAX_DATAGRAM_SIZE / get_cell_network_size(chan->wide_circ_ids);
}

size_t channel_quic_num_bytes_queued_method(channel_t *chan) {
  log_info(LD_CHANNEL, "QUIC: num bytes queued requested");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return sizeof(quicchan->outbuf);
}


int channel_quic_write_cell_method(channel_t *chan, cell_t *cell) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  log_info(LD_CHANNEL, "QUIC: Writing cell addr=%s circ_id=%u", tor_sockaddr_to_str(
      (const struct sockaddr *) quicchan->addr), cell->circ_id);
  packed_cell_t networkcell;
  cell_pack(&networkcell, cell, chan->wide_circ_ids);
  channel_quic_write_packed_cell_method(chan, &networkcell);
  return 0;
}

int channel_quic_write_packed_cell_method(channel_t *chan, packed_cell_t *packed_cell) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  log_info(LD_CHANNEL, "QUIC: Writing packed cell addr=%s circ_id=%u", tor_sockaddr_to_str(
      (const struct sockaddr *) quicchan->addr), packed_cell->circ_id);
  tor_assert(quicchan);
  uint64_t stream_id = get_stream_id_for_circuit(quicchan, packed_cell->circ_id);
  size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);
  ssize_t sent = quiche_conn_stream_send(quicchan->quiche_conn, stream_id, (uint8_t *) packed_cell->body,
                                         cell_network_size, 0);
  if (sent < 0) {
    log_warn(LD_CHANNEL, "QUIC: packed cell quiche send failed: %zd", sent);
  }
  channel_quic_flush_egress(quicchan);
  return 0;
}

int channel_quic_write_var_cell_method(channel_t *chan, var_cell_t *var_cell) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  log_info(LD_CHANNEL, "QUIC: Writing var cell addr=%s circ_id=%u", tor_sockaddr_to_str(
      (const struct sockaddr *) quicchan->addr), var_cell->circ_id);
  static char buf[MAX_DATAGRAM_SIZE];
  tor_assert(MAX_DATAGRAM_SIZE > VAR_CELL_MAX_HEADER_SIZE + var_cell->payload_len);
  int n;
  n = var_cell_pack_header(var_cell, buf, chan->wide_circ_ids);
  memcpy(buf + n, var_cell->payload, var_cell->payload_len);
  uint64_t stream_id = get_stream_id_for_circuit(quicchan, var_cell->circ_id);
  ssize_t sent = quiche_conn_stream_send(quicchan->quiche_conn, stream_id, (uint8_t *) buf, n + var_cell->payload_len,
                                         0);
  if (sent < 0) {
    log_warn(LD_CHANNEL,
             "QUIC: var cell send failed: %zd, capacity=%zd, address=%s, len=%d, stream_id=%lu, started_here=%d", sent,
             quiche_conn_stream_capacity(quicchan->quiche_conn, stream_id), tor_sockaddr_to_str(
        (const struct sockaddr *) quicchan->addr), n + var_cell->payload_len, stream_id, quicchan->started_here);
    tor_fragile_assert();
  }
  channel_quic_flush_egress(quicchan);
  return 1;
}

void
channel_quic_common_init(channel_quic_t *quicchan) {
  channel_t *chan;

  tor_assert(quicchan);

  chan = &(quicchan->base_);
  channel_init(chan);
  chan->magic = QUIC_CHAN_MAGIC;
  chan->state = CHANNEL_STATE_OPENING;
  chan->close = channel_quic_close_method;
  chan->describe_transport = channel_quic_describe_transport_method;
  chan->free_fn = channel_quic_free_method;
  chan->get_overhead_estimate = channel_quic_get_overhead_estimate_method;
  chan->get_remote_addr = channel_quic_get_remote_addr_method;
  chan->describe_peer = channel_quic_describe_peer_method;
  chan->get_transport_name = channel_quic_get_transport_name_method;
  chan->has_queued_writes = channel_quic_has_queued_writes_method;
  chan->is_canonical = channel_quic_is_canonical_method;
  chan->matches_extend_info = channel_quic_matches_extend_info_method;
  chan->matches_target = channel_quic_matches_target_method;
  chan->num_bytes_queued = channel_quic_num_bytes_queued_method;
  chan->num_cells_writeable = channel_quic_num_cells_writeable_method;
  chan->write_cell = channel_quic_write_cell_method;
  chan->write_packed_cell = channel_quic_write_packed_cell_method;
  chan->write_var_cell = channel_quic_write_var_cell_method;

  chan->cmux = circuitmux_alloc();
  /* We only have one policy for now so always set it to EWMA. */
  circuitmux_set_policy(chan->cmux, &ewma_policy);
}


static char *fmt_quic_id(uint8_t *array) {
  char *out = malloc(CONN_ID_LEN * 2 + 1);
  char *idx = &out[0];
  for (unsigned long i = 0; i < CONN_ID_LEN; i++) {
    idx += sprintf(idx, "%02x", array[i]);
  }
  return out;
}

static void channel_quic_read_cb(tor_socket_t s, short event, void *arg) {
  // Unused params
  (void) event;
  (void) arg;
  channel_quic_on_incoming(s);
}

static void channel_quic_ensure_socket(void) {
  if (udp_socket) return;
  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_socket < 0) {
    log_warn(LD_CHANNEL, "QUIC: creating UDP socket failed");
  }
  evutil_make_socket_nonblocking(udp_socket);

  struct sockaddr_in listen_addr;
  memset(&listen_addr, 0, sizeof(listen_addr));
  listen_addr.sin_family = AF_INET;
  listen_addr.sin_port = htons(0);
  listen_addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(udp_socket, (const struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
    log_warn(LD_CHANNEL, "QUIC: UDP socket bind failed");
  }

  socklen_t socklen;
  int rt = getsockname(udp_socket, (struct sockaddr *) &listen_addr, &socklen);
  if (rt < 0) {
    log_warn(LD_CHANNEL, "QUIC: getsockname on bound UDP port failed, rt=%d, errno=%d", rt, errno);
  }
  log_info(LD_CHANNEL, "QUIC: UDP socket bound to %s", tor_sockaddr_to_str((const struct sockaddr *) &listen_addr));

  struct event *read_event = tor_event_new(tor_libevent_get_base(),
                                           udp_socket, EV_READ | EV_PERSIST, channel_quic_read_cb, NULL);
  event_add(read_event, NULL);
}


int channel_quic_flush_egress(channel_quic_t *channel) {
  channel_quic_ensure_socket();
  while (1) {
    ssize_t written = quiche_conn_send(channel->quiche_conn, channel->outbuf, sizeof(channel->outbuf));

    if (written == QUICHE_ERR_DONE) {
      break;
    }
    if (written < 0) {
      log_warn(LD_CHANNEL, "QUIC: failed to create packet: %zd", written);
      return 1;
    }

    ssize_t sent = sendto(udp_socket, channel->outbuf, written, 0, (const struct sockaddr *) channel->addr,
                          sizeof(struct sockaddr_in));
    log_debug(LD_CHANNEL, "QUIC: flushed %zdb", sent);
    if (sent != written) {
      struct sockaddr_in local_addr;
      socklen_t local_addr_len;
      getsockname(udp_socket, (struct sockaddr *) &local_addr, &local_addr_len);
      log_warn(LD_CHANNEL, "QUIC: failed to send rv: %zd, addr: %s, size: %zd, err: %d, socket: %d, local_addr: %s",
               sent,
               tor_sockaddr_to_str((const struct sockaddr *) channel->addr),
               written, errno, udp_socket,
               tor_sockaddr_to_str((const struct sockaddr *) &local_addr));

      return 1;
    }

    log_debug(LD_CHANNEL, "QUIC: tx sent=%zdb, cid=%s, addr=%s", sent, fmt_quic_id(channel->cid),
              tor_sockaddr_to_str(
                  (const struct sockaddr *) channel->addr));
    channel_timestamp_active(QUIC_CHAN_TO_BASE(channel));
  }
  uint64_t timeout_nanos = quiche_conn_timeout_as_nanos(channel->quiche_conn);
  struct timeval timeout = {timeout_nanos / 1000000000, timeout_nanos / 1000 % 1000000};
  evtimer_add(channel->timer, &timeout);
  return 0;
}

int channel_quic_on_listener_initialized(connection_t *conn) {
  if (conn->socket_family != AF_INET) {
    log_debug(LD_CHANNEL, "QUIC: Not using listener of family %s", fmt_af_family(conn->socket_family));
    return 0;
  }
  log_info(LD_CHANNEL, "QUIC: listener initialized, socket: %d, port=%d", conn->s, conn->port);
  udp_socket = conn->s;
  return 0;
}


static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {

  if ((token_len < sizeof("quiche") - 1) ||
      memcmp(token, "quiche", sizeof("quiche") - 1)) {
    return false;
  }

  token += sizeof("quiche") - 1;
  token_len -= sizeof("quiche") - 1;

  if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
    return false;
  }

  token += addr_len;
  token_len -= addr_len;

  if (*odcid_len < token_len) {
    return false;
  }

  memcpy(odcid, token, token_len);
  *odcid_len = token_len;

  return true;
}

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
  memcpy(token, "quiche", sizeof("quiche") - 1);
  memcpy(token + sizeof("quiche") - 1, addr, addr_len);
  memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

  *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

void channel_quic_read_streams(channel_quic_t *quicchan) {
  static uint8_t buf[65535];
  if (!quiche_conn_is_established(quicchan->quiche_conn)) return;
  log_debug(LD_CHANNEL, "QUIC: reading streams for %s", fmt_quic_id(quicchan->cid));
  uint64_t s = 0;
  quiche_stream_iter *readable = quiche_conn_readable(quicchan->quiche_conn);

  while (quiche_stream_iter_next(readable, &s)) {
    log_debug(LD_CHANNEL, "QUIC: %s: %lu is readable", fmt_quic_id(quicchan->cid), s);
    bool fin = false;
    ssize_t recv_len =
        quiche_conn_stream_recv(quicchan->quiche_conn, s, buf, sizeof(buf), &fin);
    if (is_var_cell((char *) buf, MAX_LINK_PROTO)) {
      var_cell_t *cell;
      fetch_var_cell_from_buffer((char *) buf, recv_len, &cell, MAX_LINK_PROTO);
      log_debug(LD_CHANNEL, "QUIC: unpacked var cell, command=%d, payload_len=%d, circ_id=%u", cell->command,
                cell->payload_len, cell->circ_id);
      insert_stream_id(quicchan, s, cell->circ_id);
      channel_quic_on_incoming_var_cell(quicchan, cell);
    } else {
      cell_t cell;
      cell_unpack(&cell, (char *) buf, QUIC_CHAN_TO_BASE(quicchan)->wide_circ_ids);
      log_debug(LD_CHANNEL, "QUIC: unpacked cell, circ_id=%u, command=%d", cell.circ_id, cell.command);
      insert_stream_id(quicchan, s, cell.circ_id);
      channel_quic_on_incoming_cell(quicchan, &cell);
    }
  }
}


/**
 * We have a circid -> stream_id hashmap circs.
 *
 * Look up the stream id for this circuit, else use and increment the next stream id.
 *
 * @param quicchan
 * @param circ_id
 * @return
 */
static uint64_t get_stream_id_for_circuit(channel_quic_t *quicchan, circid_t circ_id) {
  struct circid_ht_entry_t *key = malloc(sizeof(struct circid_ht_entry_t));
  tor_assert(key);
  channel_t *chan = QUIC_CHAN_TO_BASE(quicchan);
  tor_assert(chan);
  key->chan_id = chan->global_identifier;
  key->circ_id = circ_id;
  struct circid_ht_entry_t *entry = HT_FIND(circid_ht, &circs, key);
  if (entry) {
    log_debug(LD_CHANNEL, "streamid: channel=%lu found stream_id=%lu for %d",
              QUIC_CHAN_TO_BASE(quicchan)->global_identifier, entry->stream_id, circ_id);
    return entry->stream_id;
  } else {
    key->stream_id = quicchan->next_stream_id;
    if (!quicchan->started_here) {
      key->stream_id += 1;
    }
    log_debug(LD_CHANNEL, "streamid: channel=%lu no stream for circ_id=%u, using new stream_id=%lu, started_here=%d",
              QUIC_CHAN_TO_BASE(quicchan)->global_identifier, circ_id, key->stream_id, quicchan->started_here);
    quicchan->next_stream_id += 4;

    log_debug(LD_CHANNEL, "streamid: inserting %lu", key->chan_id);
    HT_INSERT(circid_ht, &circs, key);
    return key->stream_id;
  }
}

void insert_stream_id(channel_quic_t *quicchan, uint64_t stream_id, circid_t circ_id) {
  log_debug(LD_CHANNEL, "streamid: incoming channel=%lu stream_id=%lu, addr=%s",
            QUIC_CHAN_TO_BASE(quicchan)->global_identifier, quicchan->next_stream_id,
            tor_sockaddr_to_str((const struct sockaddr *) quicchan->addr));
  struct circid_ht_entry_t *key = malloc(sizeof(struct circid_ht_entry_t));
  tor_assert(key);
  channel_t *chan = QUIC_CHAN_TO_BASE(quicchan);
  tor_assert(chan);
  key->chan_id = chan->global_identifier;
  key->circ_id = circ_id;
  struct circid_ht_entry_t *entry = HT_FIND(circid_ht, &circs, key);
  if (entry) {
    if (entry->stream_id != stream_id) {
      log_debug(LD_CHANNEL, "QUIC: received stream_id=%lu doesn't match local stream_id=%lu, circ_id=%u", stream_id,
                entry->stream_id, circ_id);
      return;
    };
  } else {
    log_debug(LD_CHANNEL, "streamid: channel=%lu circ_id=%u for new stream_id=%lu, inserting...",
              QUIC_CHAN_TO_BASE(quicchan)->global_identifier, circ_id, stream_id);
    key->stream_id = stream_id;
    HT_INSERT(circid_ht, &circs, key);
  }
}

const channel_quic_t *channel_quic_from_base_const(const channel_t *chan) {
  return channel_quic_from_base((channel_t *) chan);
}

const channel_t *channel_quic_to_base_const(const channel_quic_t *quicchan) {
  return channel_quic_to_base((channel_quic_t *) quicchan);
}


int
channel_quic_equal(const channel_quic_t *c1, const channel_quic_t *c2) {
  return tor_memeq(c1->cid, c2->cid, CONN_ID_LEN);
}

unsigned
channel_quic_hash(const channel_quic_t *d) {

  return (unsigned) siphash24g(&d->cid, CONN_ID_LEN);
}

struct chan_circ_id {
    uint64_t chan_id;
    circid_t circ_id;
};

unsigned circid_entry_hash(struct circid_ht_entry_t *c) {
  struct chan_circ_id chan_circ_id = {
      .chan_id = c->chan_id,
      .circ_id = c->circ_id
  };
  return (unsigned) siphash24g(&chan_circ_id, sizeof(struct chan_circ_id));
}

int circid_entry_equal(struct circid_ht_entry_t *c1, struct circid_ht_entry_t *c2) {
  tor_assert(c1);
  tor_assert(c2);
  if (c1->chan_id != c2->chan_id) return false;
  if (c1->circ_id != c2->circ_id) return false;
  return true;
}


static void cell_unpack(cell_t *dest, const char *src, int wide_circ_ids) {
  if (wide_circ_ids) {
    dest->circ_id = ntohl(get_uint32(src));
    src += 4;
  } else {
    dest->circ_id = ntohs(get_uint16(src));
    src += 2;
  }
  dest->command = get_uint8(src);
  memcpy(dest->payload, src + 1, CELL_PAYLOAD_SIZE);
}

static void channel_quic_on_incoming_cell(channel_quic_t *quicchan, cell_t *cell) {
  if (QUIC_CHAN_TO_BASE(quicchan)->state == CHANNEL_STATE_OPENING) {
    log_warn(LD_CHANNEL, "QUIC: incoming cell while opening");
  }
  switch (cell->command) {
    case CELL_CREATE:
    case CELL_CREATE_FAST:
    case CELL_CREATED:
    case CELL_CREATED_FAST:
    case CELL_RELAY:
    case CELL_RELAY_EARLY:
    case CELL_DESTROY:
    case CELL_CREATE2:
    case CELL_CREATED2:
      channel_process_cell(QUIC_CHAN_TO_BASE(quicchan), cell);
      break;
    default:
      log_warn(LD_CHANNEL, "QUIC: Cell of unknown type (%d) received. Dropping.", cell->command);
      break;
  }
}

void channel_quic_on_incoming_var_cell(channel_quic_t *quicchan, var_cell_t *var_cell) {
  switch (var_cell->command) {
    case CELL_ID_DIGEST:
      channel_quic_handle_id_cert_cell(quicchan, var_cell);
      break;
    default:
      log_warn(LD_CHANNEL, "QUIC: Var cell of unknown type (%d) received. Dropping.", var_cell->command);
  }
}

void channel_quic_handle_id_cert_cell(channel_quic_t *quicchan, var_cell_t *cell) {
  char their_id[DIGEST_LEN];
  memcpy(their_id, cell->payload, DIGEST_LEN);
  int ed_sign_len = cell->payload_len - DIGEST_LEN;
  int has_ed_cert = ed_sign_len > 0;
  tor_cert_t *ed_sign_cert;
  if (has_ed_cert) {
    log_info(LD_CHANNEL, "QUIC: received id: %s, ed_size_len: %d from %s", hex_str(their_id, DIGEST_LEN), ed_sign_len,
             tor_sockaddr_to_str((const struct sockaddr *) quicchan->addr));
    uint8_t encoded_ed_id_sign[ed_sign_len];
    memcpy(encoded_ed_id_sign, cell->payload + DIGEST_LEN, ed_sign_len);
    ed_sign_cert = tor_cert_parse(encoded_ed_id_sign, ed_sign_len);
    tor_assert(ed_sign_cert);
    tor_assert(&ed_sign_cert->signing_key);
  } else {
    log_info(LD_CHANNEL, "QUIC: received id: %s, no ed cert from %s", hex_str(their_id, DIGEST_LEN),
             tor_sockaddr_to_str((const struct sockaddr *) quicchan->addr));
  }

  if (QUIC_CHAN_TO_BASE(quicchan)->state != CHANNEL_STATE_OPEN) {
    channel_t *chan = QUIC_CHAN_TO_BASE(quicchan);
    tor_assert(chan);
    // Emulate receiving NETINFO for our test setup
    chan->is_canonical_to_peer = 1;
    tor_addr_t my_tor_addr;
    tor_addr_from_ipv4n(&my_tor_addr, inet_addr("127.0.0.1"));
    tor_addr_copy(&chan->addr_according_to_peer, &my_tor_addr);

    tor_addr_t peer_addr;
    uint16_t peer_port;
    tor_addr_from_sockaddr(&peer_addr, (const struct sockaddr *) quicchan->addr, &peer_port);


    log_info(LD_CHANNEL, "QUIC: opening channel");
    channel_set_circid_type(chan, NULL, 0);
    if (has_ed_cert) {
      channel_set_identity_digest(chan, their_id, &ed_sign_cert->signing_key);
    } else {
      channel_set_identity_digest(chan, their_id, NULL);
    }

    if (authdir_mode_tests_reachability(get_options())) {
      // We don't want to use canonical_orport here -- we want the address
      // that we really used.
      if (has_ed_cert) {
        dirserv_orconn_tls_done(&peer_addr, peer_port,
                                (const char *) their_id, &ed_sign_cert->signing_key);
      } else {
        dirserv_orconn_tls_done(&peer_addr, peer_port,
                                (const char *) their_id, NULL);
      }
    }
    channel_change_state_open(QUIC_CHAN_TO_BASE(quicchan));
    scheduler_channel_wants_writes(chan);
//    channel_quic_state_publish(quicchan, OR_CONN_STATE_OPEN);
  }
}

void on_connection_established(channel_quic_t *quicchan) {
  log_info(LD_CHANNEL, "QUIC: Connection established, sending id cell, addr=%s", tor_sockaddr_to_str(
      (const struct sockaddr *) quicchan->addr));
  rep_hist_note_negotiated_link_proto(3, quicchan->started_here);
  quicchan->is_established = 1;
  channel_quic_state_publish(quicchan, OR_CONN_STATE_OPEN);

  crypto_pk_t *my_key;
  if (quicchan->started_here) {
    my_key = get_tlsclient_identity_key();
  } else {
    my_key = get_server_identity_key();
  }
  char my_digest[DIGEST_LEN];
  crypto_pk_get_digest(my_key, my_digest);

  char my_hex_digest[HEX_DIGEST_LEN + 1];
  base16_encode(my_hex_digest, HEX_DIGEST_LEN + 1, my_digest, DIGEST_LEN);

  var_cell_t *cell = channel_quic_create_id_digest_cell(my_digest, quicchan->started_here);
  channel_quic_write_var_cell_method(QUIC_CHAN_TO_BASE(quicchan), cell);
}

void channel_quic_state_publish(channel_quic_t *quicchan, uint8_t state) {
  orconn_state_msg_t *msg = tor_malloc(sizeof(*msg));
  const channel_t *chan = CONST_QUIC_CHAN_TO_BASE(quicchan);
  msg->gid = chan->global_identifier;
  msg->proxy_type = PROXY_NONE;
  msg->state = state;
  msg->chan = chan->global_identifier;
  orconn_state_publish(msg);
  control_event_or_conn_status_quic(quicchan, state, 0);
}

void channel_quic_timeout_cb(int listener, short event, void *arg) {
  log_info(LD_CHANNEL, "QUIC: timeout cb");
  struct channel_quic_t *quicchan = arg;
  quiche_conn_on_timeout(quicchan->quiche_conn);
  if (quiche_conn_is_closed(quicchan->quiche_conn)) {
    log_info(LD_CHANNEL, "QUIC: Connection closed due to timeout");
    channel_change_state(QUIC_CHAN_TO_BASE(quicchan), CHANNEL_STATE_CLOSED);
  }
}
