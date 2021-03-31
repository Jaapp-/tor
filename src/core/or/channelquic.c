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
#include <lib/evloop/compat_libevent.h>

#include "core/or/or.h"
#include "core/or/channel.h"
#include "core/or/channelquic.h"
#include "app/config/resolve_addr.h"
#include "lib/quiche/include/quiche.h"
#include "core/or/circuitmux_ewma.h"
#include "core/or/extendinfo.h"
#include "core/or/cell_st.h"
#include "core/or/cell_queue_st.h"
#include "core/or/connection_or.h"
#include "connection_st.h"

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

static char *fmt_quic_id(uint8_t array[], size_t array_len);


static tor_socket_t udp_socket;


int
channel_quic_equal(const struct channel_quic_t *c1, const struct channel_quic_t *c2) {
  return tor_memeq(c1->cid, c2->cid, CONN_ID_LEN);
}

unsigned
channel_quic_hash(const struct channel_quic_t *d) {

  return (unsigned) siphash24g(&d->cid, CONN_ID_LEN);
}

static HT_HEAD(channel_quic_ht, channel_quic_t) quic_ht = HT_INITIALIZER();

HT_PROTOTYPE(channel_quic_ht, // The name of the hashtable struct
             channel_quic_t,    // The name of the element struct,
             node,        // The name of HT_ENTRY member
             channel_quic_hash, channel_quic_equal);

HT_GENERATE2(channel_quic_ht, channel_quic_t, node, channel_quic_hash, channel_quic_equal,
             0.6, tor_reallocarray, tor_free_);


channel_quic_t *
channel_quic_create(struct sockaddr_in *peer_addr, uint8_t cid[CONN_ID_LEN], quiche_conn *conn) {
  log_debug(LD_CHANNEL, "QUIC: Creating channel cid=%s, addr=%s", fmt_quic_id(cid, CONN_ID_LEN),
            tor_sockaddr_to_str(
                (const struct sockaddr *) peer_addr));
  channel_quic_t *quicchan = tor_malloc_zero(sizeof(*quicchan));
  channel_t *chan = &(quicchan->base_);
  channel_quic_common_init(quicchan);
  quicchan->addr = peer_addr;
  memcpy(quicchan->cid, cid, CONN_ID_LEN);
  quicchan->quiche_conn = conn;

  tor_addr_t tor_addr;
  uint16_t port;
  tor_addr_from_sockaddr(&tor_addr, (struct sockaddr *) quicchan->addr, &port);
  chan->is_local = is_local_to_resolve_addr(&tor_addr);
  channel_mark_incoming(chan);
  channel_register(chan);

  channel_quic_flush_egress(quicchan);
  HT_REPLACE(channel_quic_ht, &quic_ht, quicchan);
  log_debug(LD_CHANNEL, "QUIC: Inserted cid=%s into HT", fmt_quic_id(cid, CONN_ID_LEN));
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

  log_notice(LD_CHANNEL, "QUIC: connecting addr=%s, cid=%s", tor_sockaddr_to_str((struct sockaddr *) sock_addr),
             fmt_quic_id(scid, CONN_ID_LEN));

  char host[TOR_ADDR_BUF_LEN];
  tor_addr_to_str(host, addr, sizeof(host), 0);

  quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid,
                                     sizeof(scid), config);
  if (conn == NULL) {
    fprintf(stderr, "QUIC: failed to create connection\n");
    return NULL;
  }
  channel_quic_t *quicchan = channel_quic_create(sock_addr, scid, conn);
  return QUIC_CHAN_TO_BASE(quicchan);
}


int channel_quic_on_incoming(tor_socket_t sock) {
  static uint8_t buf[65535];
  log_debug(LD_CHANNEL, "QUIC: incoming data, %s", quiche_version());

  struct sockaddr_in peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);
  memset(&peer_addr, 0, peer_addr_len);

  ssize_t read = recvfrom(sock, buf, sizeof(buf), 0,
                          (struct sockaddr *) &peer_addr, &peer_addr_len);
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
  if (!quiche_version_is_supported(version)) {
    log_warn(LD_CHANNEL, "QUIC: Version unsupported, version=%d", version);
    return -1;
  }

  struct channel_quic_t channel_key;
  memcpy(channel_key.cid, dcid, dcid_len);
  struct channel_quic_t *found = HT_FIND(channel_quic_ht, &quic_ht, &channel_key);
  if (found) {
    int recv = quiche_conn_recv(found->quiche_conn, buf, read);
    if (recv < 0) {
      log_warn(LD_CHANNEL, "QUIC: Receive error on existing channel, recv=%d", recv);
    }
    log_notice(LD_CHANNEL, "QUIC: rx existing recv=%db, cid=%s, addr=%s", recv, fmt_quic_id(dcid, dcid_len),
               tor_sockaddr_to_str(
                   (const struct sockaddr *) &peer_addr));
    channel_quic_flush_egress(found);
  } else {
    quiche_config *config = create_quiche_config(false);
    quiche_conn *conn = quiche_accept(dcid, dcid_len, odcid, odcid_len, config);
    int recv = quiche_conn_recv(conn, buf, read);
    if (recv < 0) {
      log_warn(LD_CHANNEL, "QUIC: receive error, %d", recv);
    }
    log_notice(LD_CHANNEL, "QUIC: rx new recv=%db, cid=%s, addr=%s", recv, fmt_quic_id(dcid, dcid_len),
               tor_sockaddr_to_str(
                   (const struct sockaddr *) &peer_addr));
    channel_quic_create(&peer_addr, dcid, conn);
  }
  return 0;
}


static void debug_log(const char *line, void *argp) {
  log_info(LD_CHANNEL, "%s", line);
}

quiche_config *create_quiche_config(bool is_client) {
  quiche_enable_debug_logging(debug_log, NULL);
  quiche_config *config = quiche_config_new(0xff00001d);
  if (config == NULL) {
    log_info(LD_CHANNEL, "QUIC: failed to create config");
    return NULL;
  }

  quiche_config_set_application_protos(config,
                                       (uint8_t *) "\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 27);
  quiche_config_set_max_idle_timeout(config, 5000);
  quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
  quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
  quiche_config_set_initial_max_data(config, 10000000);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
  quiche_config_set_initial_max_stream_data_uni(config, 1000000);
  quiche_config_set_initial_max_streams_bidi(config, 100);
  quiche_config_set_initial_max_streams_uni(config, 100);
  quiche_config_set_disable_active_migration(config, true);

  if (!is_client) {
    log_info(LD_CHANNEL, "QUIC: loading certs");
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

static int get_rng() {
  int rng = open("/dev/urandom", O_RDONLY);
  if (rng < 0) {
    log_warn(LD_CHANNEL, "QUIC: failed to open /dev/urandom");
  }
  return rng;
}

uint8_t *fill_with_random_bytes(uint8_t *array, size_t array_len) {
  int rng = get_rng();
  int ret = read(rng, array, array_len);
  if (ret < 0) {
    perror("Failed to read random bytes");
  }
  return array;
}

static void
channel_quic_close_method(channel_t *chan) {
  log_notice(LD_CHANNEL, "QUIC: close chan");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  int ret = quiche_conn_close(quicchan->quiche_conn, false, 0, "", 0);
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

const channel_t *
channel_quic_to_base_const(const channel_quic_t *quicchan) {
  return channel_quic_to_base((channel_quic_t *) quicchan);
}

const channel_quic_t *
channel_quic_from_base_const(const channel_t *chan) {
  return channel_quic_from_base((channel_t *) chan);
}


static const char *
channel_quic_describe_transport_method(channel_t *chan) {
  return "QUIC channel";
}

static void
channel_quic_free_method(channel_t *chan) {
  log_notice(LD_CHANNEL, "QUIC: free method");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);

  if (quicchan->quiche_conn) {
    quiche_conn_free(quicchan->quiche_conn);
  }
}


static double
channel_quic_get_overhead_estimate_method(channel_t *chan) {
  log_notice(LD_CHANNEL, "QUIC: overhead estimate requested");
  double overhead = 1.0;
  // TODO
  return overhead;
}


static int
channel_quic_get_remote_addr_method(const channel_t *chan,
                                    tor_addr_t *addr_out) {

  log_notice(LD_CHANNEL, "QUIC: remote addr requested");
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
  log_notice(LD_CHANNEL, "QUIC: has queued writes requestsed");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return 1; // TODO
}

int channel_quic_is_canonical_method(channel_t *chan) {
  log_notice(LD_CHANNEL, "QUIC: isprintf(buffer,s canonical requestsed");
  return 0; // TODO
}

int channel_quic_matches_extend_info_method(channel_t *chan, extend_info_t *extend_info) {
  log_notice(LD_CHANNEL, "QUIC: matches extend info requested");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  tor_addr_t tor_addr;
  uint16_t port;
  tor_addr_from_sockaddr(&tor_addr, (const struct sockaddr *) quicchan->addr, &port);
  return extend_info_has_orport(extend_info,
                                &tor_addr,
                                quicchan->addr->sin_port);
}

int channel_quic_matches_target_method(channel_t *chan, const tor_addr_t *target) {
  log_notice(LD_CHANNEL, "QUIC: matches target method requestsed");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(target);

  return tor_addr_eq(quicchan->addr, target);
}

int channel_quic_num_cells_writeable_method(channel_t *chan) {
  log_notice(LD_CHANNEL, "QUIC: num bytes cells writable requested");
  // Amount of cells within one Datagram, TODO: that's probably not the way, set to higher?
  return MAX_DATAGRAM_SIZE / get_cell_network_size(chan->wide_circ_ids);
}

size_t channel_quic_num_bytes_queued_method(channel_t *chan) {
  log_notice(LD_CHANNEL, "QUIC: num bytes queued requested");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return sizeof(quicchan->outbuf);
}

uint64_t get_cell_stream_id(packed_cell_t *cell) {
  if (cell->circ_id <= 0) {
    log_warn(LD_CHANNEL, "Converting bad circ_id to stream_id: %d", cell->circ_id);
  }
  return cell->circ_id;
}

int channel_quic_write_cell_method(channel_t *chan, cell_t *cell) {
  log_notice(LD_CHANNEL, "QUIC: write cell");
  packed_cell_t networkcell;
  cell_pack(&networkcell, cell, chan->wide_circ_ids);
  channel_quic_write_packed_cell_method(chan, &networkcell);
  return 0;
}

int channel_quic_write_packed_cell_method(channel_t *chan, packed_cell_t *packed_cell) {
  log_notice(LD_CHANNEL, "QUIC: write packed cell");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  uint64_t stream_id = get_cell_stream_id(packed_cell);
  size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);
  quiche_conn_stream_send(quicchan->quiche_conn, stream_id, (uint8_t *) packed_cell->body, cell_network_size, false);
  return 0;
}

int channel_quic_write_var_cell_method(channel_t *chan, var_cell_t *var_cell) {
  log_notice(LD_CHANNEL, "QUIC: write var cell");
  log_warn(LD_CHANNEL, "channelquic: Writing var_cell is not yet implemented");
  return 1; // TODO
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


static char *fmt_quic_id(uint8_t array[], size_t array_len) {
  char *out = malloc(array_len * 2 + 1);
  char *idx = &out[0];
  for (unsigned long i = 0; i < array_len; i++) {
    idx += sprintf(idx, "%02x", array[i]);
  }
  return out;
}

static void channel_quic_read_cb(tor_socket_t s, short event, void *arg) {
  channel_quic_on_incoming(s);
}

static void channel_quic_ensure_socket() {
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

//  struct sockaddr_in test_addr;
//  memset(&test_addr, 0, sizeof(test_addr));
//  test_addr.sin_family = AF_INET;
//  test_addr.sin_port = htons(8080);
//  test_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
//  char message[5] = "Heya";
//  int srv = sendto(udp_socket, message, sizeof(message), 0, (const struct sockaddr *) &test_addr, sizeof(test_addr));
//  log_info(LD_CHANNEL, "QUIC: sent on udp sock: %d", srv);
//

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


int channel_quic_flush_egress(struct channel_quic_t *channel) {
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

    log_notice(LD_CHANNEL, "QUIC: tx sent=%zdb, cid=%s, addr=%s", sent, fmt_quic_id(channel->cid, CONN_ID_LEN),
               tor_sockaddr_to_str(
                   (const struct sockaddr *) channel->addr));
  }
  return 0;
//    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
//    conn_io->timer.repeat = t;
//    ev_timer_again(loop, &conn_io->timer);
}

int channel_quic_on_listener_initialized(connection_t *conn) {
  if (conn->socket_family != AF_INET) {
    log_debug(LD_CHANNEL, "QUIC: Not using listener of family %s", fmt_af_family(conn->socket_family));
    return 0;
  }
  log_debug(LD_CHANNEL, "QUIC: listener initialized, socket: %d", conn->s);
  udp_socket = conn->s;
  return 0;
}
