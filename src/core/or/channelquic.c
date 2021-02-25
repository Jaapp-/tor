//
// Created by jaap on 17-12-20.
//

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */
#define CHANNEL_OBJECT_PRIVATE

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "core/or/or.h"
#include "core/or/channel.h"
#include "core/or/channelquic.h"
#include "lib/quiche/include/quiche.h"
#include "core/or/circuitmux_ewma.h"
#include "core/or/extendinfo.h"
#include "core/or/cell_st.h"
#include "core/or/cell_queue_st.h"
#include "core/or/connection_or.h"


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
//
///* channel_listener_quic_t method declarations */
//
//static void channel_quic_listener_close_method(channel_listener_t *chan_l);
//static const char *
//channel_quic_listener_describe_transport_method(channel_listener_t *chan_l);

static void debug_log(const char *line, void *argp) {
  log_debug(LD_CHANNEL, "%s", line);
}

static quiche_config *init_quiche() {
  quiche_enable_debug_logging(debug_log, NULL);
  quiche_config *config = quiche_config_new(0xbabababa);
  if (config == NULL) {
    fprintf(stderr, "failed to create config\n");
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
  return config;
}

static int get_rng() {
  int rng = open("/dev/urandom", O_RDONLY);
  if (rng < 0) {
    perror("failed to open /dev/urandom");
  }
  return rng;
}

static uint8_t *fill_with_random_bytes(uint8_t *array, size_t array_len) {
  int rng = get_rng();
  int ret = read(rng, array, array_len);
  if (ret < 0) {
    perror("Failed to read random bytes");
  }
  return array;
}

static void
channel_quic_close_method(channel_t *chan) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  int ret = quiche_conn_close(quicchan->conn, false, 0, "", 0);
  if (ret < 0) {
    perror("Closing connection failed");
  }
}

/**
 *
 * Cast a channel_t to a channel_quic_t, with appropriate type-checking
 * asserts.
 */
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
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);

  if (quicchan->conn) {
    quiche_conn_free(quicchan->conn);
  }
}


static double
channel_quic_get_overhead_estimate_method(channel_t *chan) {
  double overhead = 1.0;
  // TODO
  return overhead;
}


static int
channel_quic_get_remote_addr_method(const channel_t *chan,
                                    tor_addr_t *addr_out) {
  const channel_quic_t *quicchan = CONST_BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(addr_out);

  if (quicchan->conn == NULL) {
    tor_addr_make_unspec(addr_out);
    return 0;
  }

  /* They want the real address, so give it to them. */
  tor_addr_copy(addr_out, quicchan->addr);

  return 1;
}

static const char *
channel_quic_describe_peer_method(const channel_t *chan) {
  const channel_quic_t *quicchan = CONST_BASE_CHAN_TO_QUIC(chan);
  tor_assert(quicchan);

  if (quicchan->conn) {
    return "<QUIC addr>";
  } else {
    return "(No connection)";
  }
}

static int
channel_quic_get_transport_name_method(channel_t *chan, char **transport_out) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(transport_out);
  tor_assert(quicchan->conn);


  *transport_out = tor_strdup("QUIC Transport");
  return 0;
}


static int
channel_quic_has_queued_writes_method(channel_t *chan) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return 1; // TODO
}

int channel_quic_is_canonical_method(channel_t *chan) {
  return 0; // TODO
}

int channel_quic_matches_extend_info_method(channel_t *chan, extend_info_t *extend_info) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return extend_info_has_orport(extend_info,
                                quicchan->addr,
                                *quicchan->port);
}

int channel_quic_matches_target_method(channel_t *chan, const tor_addr_t *target) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(target);

  /* Never match if we have no conn */
  if (!(quicchan->conn)) {
    log_info(LD_CHANNEL,
             "something called matches_target on a quicchan "
             "(%p with ID %"PRIu64 " but no conn",
             chan, (chan->global_identifier));
    return 0;
  }
  return tor_addr_eq(quicchan->addr, target);
}

int channel_quic_num_cells_writeable_method(channel_t *chan) {
  // Amount of cells within one Datagram, TODO: that's probably not the way, set to higher?
  return MAX_DATAGRAM_SIZE / get_cell_network_size(chan->wide_circ_ids);
}

size_t channel_quic_num_bytes_queued_method(channel_t *chan) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return sizeof(quicchan->out);
}

uint64_t get_cell_stream_id(packed_cell_t *cell) {
  if (cell->circ_id <= 0) {
    log_warn(LD_CHANNEL, "Converting bad circ_id to stream_id: %d", cell->circ_id);
  }
  return cell->circ_id;
}

int channel_quic_write_cell_method(channel_t *chan, cell_t *cell) {
  packed_cell_t networkcell;
  cell_pack(&networkcell, cell, chan->wide_circ_ids);
  channel_quic_write_packed_cell_method(chan, &networkcell);
  return 0;
}

int channel_quic_write_packed_cell_method(channel_t *chan, packed_cell_t *packed_cell) {
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  uint64_t stream_id = get_cell_stream_id(packed_cell);
  size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);
  quiche_conn_stream_send(quicchan->conn, stream_id, (uint8_t *) packed_cell.body, cell_network_size, false);
  return 0;
}

int channel_quic_write_var_cell_method(channel_t *chan, var_cell_t *var_cell) {
  log_warn(LD_CHANNEL, "channelquic: Writing var_cell is not yet implemented");
  return 1; // TODO
}

static void
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

channel_t *channel_quic_connect(const tor_addr_t *addr, uint16_t port, const char *id_digest,
                                const struct ed25519_public_key_t *ed_id) {
  printf("Creating quiche connection, quiche version: %s\n", quiche_version());


  channel_quic_t *quicchan = tor_malloc_zero(sizeof(*quicchan));
  channel_t *chan = &(quicchan->base_);

  struct sockaddr *sock_addr;
  sock_addr = tor_malloc(sizeof(struct sockaddr_storage));
  socklen_t sock_len = tor_addr_to_sockaddr(addr, port, sock_addr, sizeof(struct sockaddr_storage));

  int sock = socket(addr->family, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("failed to create socket");
    return NULL;
  }

  if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
    perror("failed to make socket non-blocking");
    return NULL;
  }

  if (connect(sock, sock_addr, sock_len) < 0) {
    perror("failed to connect socket");
    return NULL;
  }

  quiche_config *config = init_quiche();
  uint8_t scid[LOCAL_CONN_ID_LEN];
  fill_with_random_bytes(scid, LOCAL_CONN_ID_LEN);

  char host[TOR_ADDR_BUF_LEN];
  tor_addr_to_str(host, addr, sizeof(host), 0);

  quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid,
                                     sizeof(scid), config);
  if (conn == NULL) {
    fprintf(stderr, "failed to create connection\n");
    return NULL;
  }
  quicchan->conn = conn;
  quicchan->addr = addr;
  quicchan->port = port;

  return chan;
}


