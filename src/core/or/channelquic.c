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
#include "or_connection_st.h"

/** Active listener, if any */
static channel_listener_t *channel_quic_listener = NULL;

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

static int channel_quic_flush_egress(struct channel_quic_t *channel);

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
    log_notice(LD_CHANNEL, "QUIC: close chan");
    channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
    int ret = quiche_conn_close(quicchan->quiche_conn, false, 0, "", 0);
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

    if (quicchan->or_conn == NULL) {
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

    if (quicchan->or_conn) {
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
    tor_assert(quicchan->quiche_conn);
    tor_assert(quicchan->or_conn);


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
    log_notice(LD_CHANNEL, "QUIC: is canonical requestsed");
    return 0; // TODO
}

int channel_quic_matches_extend_info_method(channel_t *chan, extend_info_t *extend_info) {
    log_notice(LD_CHANNEL, "QUIC: matches extend info requestsed");
    channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);
    return extend_info_has_orport(extend_info,
                                  quicchan->addr,
                                  quicchan->port);
}

int channel_quic_matches_target_method(channel_t *chan, const tor_addr_t *target) {
    log_notice(LD_CHANNEL, "QUIC: matches target method requestsed");
    channel_quic_t *quicchan = BASE_CHAN_TO_QUIC(chan);

    tor_assert(quicchan);
    tor_assert(target);

    /* Never match if we have no conn */
    if (!(quicchan->or_conn)) {
        log_info(LD_CHANNEL,
                 "something called matches_target on a quicchan "
                 "(%p with ID %"PRIu64 " but no conn",
                 chan, (chan->global_identifier));
        return 0;
    }
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
    log_notice(LD_CHANNEL, "QUIC: connect");


    channel_quic_t *quicchan = tor_malloc_zero(sizeof(*quicchan));
    channel_t *chan = &(quicchan->base_);

    channel_quic_common_init(quicchan);

    struct sockaddr *sock_addr;
    sock_addr = tor_malloc(sizeof(struct sockaddr_storage));
    socklen_t sock_len = tor_addr_to_sockaddr(addr, port, sock_addr, sizeof(struct sockaddr_storage));

    quicchan->sock = socket(addr->family, SOCK_DGRAM, 0);
    if (quicchan->sock < 0) {
        perror("failed to create socket");
        return NULL;
    }

    if (fcntl(quicchan->sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return NULL;
    }

    if (connect(quicchan->sock, sock_addr, sock_len) < 0) {
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
    quicchan->quiche_conn = conn;
    quicchan->addr = addr;
    quicchan->port = port;

    quic_channel_start_listening(quicchan);

    return chan;
}

int channel_quic_on_incoming(tor_socket_t news, tor_addr_t *addr, uint16_t port) {
    log_notice(LD_CHANNEL, "QUIC: incoming connection");

    channel_quic_t *quicchan = tor_malloc_zero(sizeof(*quicchan));
    channel_t *chan = &(quicchan->base_);
    quicchan->sock = news;
    quicchan->addr = addr;
    quicchan->port = port;

    channel_quic_common_init(quicchan);

    chan->is_local = is_local_to_resolve_addr(quicchan->addr);

    channel_mark_incoming(chan);

    channel_register(chan);

    quic_channel_start_listening(quicchan);
    channel_quic_flush_egress(quicchan);

    return 0;
}

int quic_channel_start_listening(struct channel_quic_t *quicchan) {
    quicchan->read_event = tor_event_new(tor_libevent_get_base(),
                                         quicchan->sock, EV_READ | EV_PERSIST, channel_quic_read_callback, quicchan);
    quicchan->write_event = tor_event_new(tor_libevent_get_base(),
                                          quicchan->sock, EV_WRITE | EV_PERSIST, channel_quic_write_callback, quicchan);
    event_add(quicchan->read_event, NULL);
    event_add(quicchan->write_event, NULL);
    return 0;
}


int channel_quic_flush_egress(struct channel_quic_t *channel) {
    log_notice(LD_CHANNEL, "QUIC: flushing");
    while (1) {
        ssize_t written = quiche_conn_send(channel->quiche_conn, channel->outbuf, sizeof(channel->outbuf));

        if (written == QUICHE_ERR_DONE) {
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return 1;
        }

        ssize_t sent = send(channel->sock, channel->outbuf, written, 0);
        if (sent != written) {
            perror("failed to send");
            return 1;
        }

        log_notice(LD_CHANNEL, "QUIC: sent %zd bytes", sent);
    }
//    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
//    conn_io->timer.repeat = t;
//    ev_timer_again(loop, &conn_io->timer);
}

void channel_quic_read_callback(int fd, short event, void *_quicchan) {
    log_notice(LD_CHANNEL, "QUIC: read callback");
}

void channel_quic_write_callback(int fd, short event, void *_quicchan) {
    log_notice(LD_CHANNEL, "QUIC: write callback");
}
