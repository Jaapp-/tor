// // Created by jaap on 17-12-20.
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

int quic_ht_is_initialized;
tor_socket_t udp_socket;


int
channel_quic_equal(const struct channel_quic_t *c1, const struct channel_quic_t *c2)
{
  return memcmp(c1->cid, c2->cid, sizeof(c1->cid)) == 0;
}

unsigned
channel_quic_hash(const struct channel_quic_t *d)
{

  return (unsigned) siphash24g(d->cid, sizeof(d->cid));
}


HT_PROTOTYPE(channel_quic_ht, // The name of the hashtable struct
             channel_quic_t,    // The name of the element struct,
             node,        // The name of HT_ENTRY member
             channel_quic_hash, channel_quic_equal);

HT_GENERATE2(channel_quic_ht, channel_quic_t, node, channel_quic_hash, channel_quic_equal,
             0.6, tor_reallocarray, tor_free_);


channel_quic_ht_t *quic_ht;


static void quic_init_ht()
{
  if (quic_ht_is_initialized) return;
  quic_ht = tor_malloc(sizeof(channel_quic_ht_t));
  HT_INIT(channel_quic_ht, quic_ht);
}


channel_t *channel_quic_connect(const tor_addr_t *addr, uint16_t port, const char *id_digest,
                                const struct ed25519_public_key_t *ed_id)
{
  log_notice(LD_CHANNEL, "QUIC: connect");

  channel_quic_t *quicchan = tor_malloc_zero(sizeof(*quicchan));
  channel_t *chan = &(quicchan->base_);

  channel_quic_common_init(quicchan);

  struct sockaddr *sock_addr;
  sock_addr = tor_malloc(sizeof(struct sockaddr_storage));
  socklen_t sock_len = tor_addr_to_sockaddr(addr, port, sock_addr, sizeof(struct sockaddr_storage));
  log_notice(LD_CHANNEL, "QUIC: connecting to %s", tor_sockaddr_to_str(sock_addr));

  quiche_config *config = create_quiche_config();
  uint8_t scid[LOCAL_CONN_ID_LEN];
  fill_with_random_bytes(scid, LOCAL_CONN_ID_LEN);

  char host[TOR_ADDR_BUF_LEN];
  tor_addr_to_str(host, addr, sizeof(host), 0);

  quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid,
                                     sizeof(scid), config);
  if (conn == NULL) {
    fprintf(stderr, "QUIC: failed to create connection\n");
    return NULL;
  }
  log_info(LD_CHANNEL, "QUIC: Creating connection, scid=%s", fmt_quic_id(scid, LOCAL_CONN_ID_LEN));
  quicchan->quiche_conn = conn;
  quicchan->addr = addr;
  quicchan->port = port;
  memcpy(quicchan->cid, scid, LOCAL_CONN_ID_LEN);

  quic_channel_start_listening(quicchan);
  channel_quic_flush_egress(quicchan);

  return chan;
}

int channel_quic_on_incoming(tor_socket_t sock)
{
  static uint8_t buf[65535];
  log_notice(LD_CHANNEL, "QUIC: incoming data");

  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);
  memset(&peer_addr, 0, peer_addr_len);

  ssize_t read = recvfrom(sock, buf, sizeof(buf), 0,
                          (struct sockaddr *) &peer_addr, &peer_addr_len);
  if (read < 0) {
    log_warn(LD_CHANNEL, "QUIC: read() error %zd", read);
    return -1;
  }
  log_notice(LD_CHANNEL, "QUIC: read %zd bytes", read);
  uint8_t type;
  uint32_t version;

  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  size_t scid_len = sizeof(scid);

  uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
  size_t dcid_len = sizeof(dcid);

  uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
  size_t odcid_len = sizeof(odcid);

  uint8_t token[MAX_TOKEN_LEN];
  size_t token_len = sizeof(token);

  int rc =
      quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version, &type, scid,
                         &scid_len, dcid, &dcid_len, token, &token_len);
  if (rc < 0) {
    log_warn(LD_CHANNEL, "QUIC: Quiche header info error");
    return -1;
  }
  log_notice(LD_CHANNEL, "QUIC: Received initial data");
  log_info(LD_CHANNEL, "QUIC: received conn scid=%s, dcid=%s", fmt_quic_id(scid, scid_len),
           fmt_quic_id(dcid, dcid_len));

  quic_init_ht();

  struct channel_quic_t channel_key;
  memcpy(channel_key.cid, dcid, dcid_len);
  struct channel_quic_t *found = HT_FIND(channel_quic_ht, quic_ht, &channel_key);
  if (found) {
    log_info(LD_CHANNEL, "QUIC: Found channel");
  } else {
    log_info(LD_CHANNEL, "QUIC: Didn't find channel");

    channel_quic_t *quicchan = tor_malloc_zero(sizeof(*quicchan));
    channel_t *chan = &(quicchan->base_);
    tor_addr_t addr;
    uint16_t port;
    tor_addr_from_sockaddr(&addr, (struct sockaddr *) &peer_addr, &port);
    quicchan->addr = &addr;
    quicchan->port = port;
    memcpy(quicchan->cid, dcid, dcid_len);

    channel_quic_common_init(quicchan);

    chan->is_local = is_local_to_resolve_addr(quicchan->addr);

    channel_mark_incoming(chan);

    channel_register(chan);

    quic_channel_start_listening(quicchan);
    channel_quic_flush_egress(quicchan);
    HT_INSERT(channel_quic_ht, quic_ht, quicchan);
    log_notice(LD_CHANNEL, "QUIC: Inserted dcid=%s into HT", fmt_quic_id(dcid, dcid_len));
  }
  return 0;
}


static void debug_log(const char *line, void *argp)
{
  log_debug(LD_CHANNEL, "%s", line);
}

quiche_config *create_quiche_config()
{
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

static int get_rng()
{
  int rng = open("/dev/urandom", O_RDONLY);
  if (rng < 0) {
    perror("failed to open /dev/urandom");
  }
  return rng;
}

uint8_t *fill_with_random_bytes(uint8_t *array, size_t array_len)
{
  int rng = get_rng();
  int ret = read(rng, array, array_len);
  if (ret < 0) {
    perror("Failed to read random bytes");
  }
  return array;
}

static void
channel_quic_close_method(channel_t *chan)
{
  log_notice(LD_CHANNEL, "QUIC: close chan");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  int ret = quiche_conn_close(quicchan->quiche_conn, false, 0, "", 0);
  if (ret < 0) {
    perror("Closing connection failed");
  }
}

channel_quic_t *
channel_quic_from_base(channel_t *chan)
{
  if (!chan) return NULL;

  tor_assert(chan->magic == QUIC_CHAN_MAGIC);

  return (channel_quic_t *) (chan);
}

channel_t *
channel_quic_to_base(channel_quic_t *quicchan)
{
  if (!quicchan) return NULL;

  return &(quicchan->base_);
}

const channel_t *
channel_quic_to_base_const(const channel_quic_t *quicchan)
{
  return channel_quic_to_base((channel_quic_t *) quicchan);
}

const channel_quic_t *
channel_quic_from_base_const(const channel_t *chan)
{
  return channel_quic_from_base((channel_t *) chan);
}


static const char *
channel_quic_describe_transport_method(channel_t *chan)
{
  return "QUIC channel";
}

static void
channel_quic_free_method(channel_t *chan)
{
  log_notice(LD_CHANNEL, "QUIC: free method");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);

  if (quicchan->quiche_conn) {
    quiche_conn_free(quicchan->quiche_conn);
  }
}


static double
channel_quic_get_overhead_estimate_method(channel_t *chan)
{
  log_notice(LD_CHANNEL, "QUIC: overhead estimate requested");
  double overhead = 1.0;
  // TODO
  return overhead;
}


static int
channel_quic_get_remote_addr_method(const channel_t *chan,
                                    tor_addr_t *addr_out)
{

  log_notice(LD_CHANNEL, "QUIC: remote addr requested");
  const channel_quic_t *quicchan = CONST_BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(addr_out);

  /* They want the real address, so give it to them. */
  tor_addr_copy(addr_out, quicchan->addr);

  return 1;
}

static const char *
channel_quic_describe_peer_method(const channel_t *chan)
{
  const channel_quic_t *quicchan = CONST_BASE_CHAN_TO_QUIC(chan);
  tor_assert(quicchan);


  if (*quicchan->cid) {
    return "<QUIC channel>";
  } else {
    return "(No connection)";
  }
}

static int
channel_quic_get_transport_name_method(channel_t *chan, char **transport_out)
{
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(transport_out);
  tor_assert(quicchan->quiche_conn);


  *transport_out = tor_strdup("QUIC Transport");
  return 0;
}


static int
channel_quic_has_queued_writes_method(channel_t *chan)
{
  log_notice(LD_CHANNEL, "QUIC: has queued writes requestsed");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return 1; // TODO
}

int channel_quic_is_canonical_method(channel_t *chan)
{
  log_notice(LD_CHANNEL, "QUIC: isprintf(buffer,s canonical requestsed");
  return 0; // TODO
}

int channel_quic_matches_extend_info_method(channel_t *chan, extend_info_t *extend_info)
{
  log_notice(LD_CHANNEL, "QUIC: matches extend info requestsed");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return extend_info_has_orport(extend_info,
                                quicchan->addr,
                                quicchan->port);
}

int channel_quic_matches_target_method(channel_t *chan, const tor_addr_t *target)
{
  log_notice(LD_CHANNEL, "QUIC: matches target method requestsed");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

  tor_assert(quicchan);
  tor_assert(target);

  return tor_addr_eq(quicchan->addr, target);
}

int channel_quic_num_cells_writeable_method(channel_t *chan)
{
  log_notice(LD_CHANNEL, "QUIC: num bytes cells writable requested");
  // Amount of cells within one Datagram, TODO: that's probably not the way, set to higher?
  return MAX_DATAGRAM_SIZE / get_cell_network_size(chan->wide_circ_ids);
}

size_t channel_quic_num_bytes_queued_method(channel_t *chan)
{
  log_notice(LD_CHANNEL, "QUIC: num bytes queued requested");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  return sizeof(quicchan->outbuf);
}

uint64_t get_cell_stream_id(packed_cell_t *cell)
{
  if (cell->circ_id <= 0) {
    log_warn(LD_CHANNEL, "Converting bad circ_id to stream_id: %d", cell->circ_id);
  }
  return cell->circ_id;
}

int channel_quic_write_cell_method(channel_t *chan, cell_t *cell)
{
  log_notice(LD_CHANNEL, "QUIC: write cell");
  packed_cell_t networkcell;
  cell_pack(&networkcell, cell, chan->wide_circ_ids);
  channel_quic_write_packed_cell_method(chan, &networkcell);
  return 0;
}

int channel_quic_write_packed_cell_method(channel_t *chan, packed_cell_t *packed_cell)
{
  log_notice(LD_CHANNEL, "QUIC: write packed cell");
  channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
  uint64_t stream_id = get_cell_stream_id(packed_cell);
  size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);
  quiche_conn_stream_send(quicchan->quiche_conn, stream_id, (uint8_t *) packed_cell->body, cell_network_size, false);
  return 0;
}

int channel_quic_write_var_cell_method(channel_t *chan, var_cell_t *var_cell)
{
  log_notice(LD_CHANNEL, "QUIC: write var cell");
  log_warn(LD_CHANNEL, "channelquic: Writing var_cell is not yet implemented");
  return 1; // TODO
}

void
channel_quic_common_init(channel_quic_t *quicchan)
{
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


static char *fmt_quic_id(uint8_t array[], size_t array_len)
{
  char *out = malloc(array_len * 2 + 1);
  char *idx = &out[0];
  for (unsigned long i = 0; i < array_len; i++) {
    idx += sprintf(idx, "%02x", array[i]);
  }
  return out;
}

void print_array_hex(uint8_t array[], size_t array_len)
{
  for (unsigned long i = 0; i < array_len; i++) {
    printf("%02x", array[i]);
  }
  printf("\n");
}


int channel_quic_flush_egress(struct channel_quic_t *channel)
{
  log_notice(LD_CHANNEL, "QUIC: flushing");
  while (1) {
    ssize_t written = quiche_conn_send(channel->quiche_conn, channel->outbuf, sizeof(channel->outbuf));

    if (written == QUICHE_ERR_DONE) {
      break;
    }

    if (written < 0) {
      log_warn(LD_CHANNEL, "QUIC: failed to create packet: %zd", written);
      return 1;
    }


    ssize_t sent = sendto(udp_socket, channel->outbuf, written, 0, channel->addr, sizeof(channel->addr));
    if (sent != written) {
      log_warn(LD_CHANNEL, "QUIC failed to send");
      return 1;
    }

    log_notice(LD_CHANNEL, "QUIC: sent %zd bytes", sent);
  }
  return 0;
//    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
//    conn_io->timer.repeat = t;
//    ev_timer_again(loop, &conn_io->timer);
}

int channel_quic_on_listener_initialized(connection_t *conn)
{
  log_notice(LD_CHANNEL, "QUIC listener initialized, socket=%d", conn->s);
  udp_socket = conn->s;
  return 0;
}
