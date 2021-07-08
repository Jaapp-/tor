#ifndef TOR_CHANNELQUIC_H
#define TOR_CHANNELQUIC_H

#include "lib/quiche/include/quiche.h"

#define QUIC_CHAN_MAGIC 0x75cd0b9c
#define CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350
#define MAX_TOKEN_LEN                                                          \
  sizeof("quiche") - 1 + sizeof(struct sockaddr_storage) +                     \
      QUICHE_MAX_CONN_ID_LEN

struct circid_ht_entry_t {
    HT_ENTRY(circid_ht_entry_t) node;
    uint64_t chan_id;
    circid_t circ_id;
    uint64_t stream_id;
};

struct buf_ht_entry_t {
    HT_ENTRY(buf_ht_entry_t) node;
    uint64_t chan_id;
    uint64_t stream_id;
    bool is_outgoing;
    buf_t *buf;
};

struct channel_quic_t {
    channel_t base_;
    HT_ENTRY(channel_quic_t) node;
    uint8_t cid[CONN_ID_LEN];
    quiche_conn *quiche_conn;
    struct sockaddr_in *addr;
    uint8_t outbuf[MAX_DATAGRAM_SIZE];
    uint8_t inbuf[MAX_DATAGRAM_SIZE];
    uint64_t next_stream_id;
    int started_here;
    int is_established;
    int bootstrap_stage;
    int queued_cells;
    struct event *timer;
};

#define BASE_CHAN_TO_QUIC(c) (channel_quic_from_base((c)))
#define QUIC_CHAN_TO_BASE(c) (channel_quic_to_base((c)))
#define CONST_BASE_CHAN_TO_QUIC(c) (channel_quic_from_base_const((c)))
#define CONST_QUIC_CHAN_TO_BASE(c) (channel_quic_to_base_const((c)))

/* Casts */
channel_t *channel_quic_to_base(channel_quic_t *quicchan);

channel_quic_t *channel_quic_from_base(channel_t *chan);

const channel_t *channel_quic_to_base_const(const channel_quic_t *quicchan);

const channel_quic_t *channel_quic_from_base_const(const channel_t *chan);


channel_t *channel_quic_connect(const tor_addr_t *addr, uint16_t port,
                                const char *id_digest,
                                const struct ed25519_public_key_t *ed_id);

//channel_listener_t *channel_quic_get_listener(void);
//
//channel_listener_t *channel_quic_start_listener(void);

int channel_quic_on_incoming(tor_socket_t sock);

/* Cleanup at shutdown */
void channel_quic_free_all(void);

channel_quic_t *channel_quic_create(struct sockaddr_in *peer_addr, uint8_t *scid, quiche_conn *conn, bool started_here);

int channel_quic_on_listener_initialized(connection_t *conn);

void channel_quic_common_init(channel_quic_t *quicchan);

quiche_config *create_quiche_config(bool is_client);

uint8_t *fill_with_random_bytes(uint8_t *array, size_t array_len);

int channel_quic_flush_egress(struct channel_quic_t *channel);

int channel_quic_equal(const struct channel_quic_t *c1, const struct channel_quic_t *c2);

unsigned channel_quic_hash(const struct channel_quic_t *d);

int circid_entry_equal(struct circid_ht_entry_t *c1, struct circid_ht_entry_t *c2);

unsigned circid_entry_hash(struct circid_ht_entry_t *c);

#endif //TOR_CHANNELQUIC_H
