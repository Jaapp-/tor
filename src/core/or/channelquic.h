#ifndef TOR_CHANNELQUIC_H
#define TOR_CHANNELQUIC_H

#include "lib/quiche/include/quiche.h"

#define QUIC_CHAN_MAGIC 0x75cd0b9c
#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350
#define MAX_TOKEN_LEN                                                          \
  sizeof("quiche") - 1 + sizeof(struct sockaddr_storage) +                     \
      QUICHE_MAX_CONN_ID_LEN


struct channel_quic_t {
    HT_ENTRY(channel_quic_t) node;

    // QUIC's connection id is the channel's primary key.
    uint8_t *scid[LOCAL_CONN_ID_LEN];
    uint8_t *dcid;
    size_t dcid_len;
    channel_t base_;
    quiche_conn *quiche_conn;
//    or_connection_t *or_conn;
    struct sockaddr_in *addr;
//    struct tor_addr_t *tor_addr;
//    uint16_t port;
    uint8_t outbuf[MAX_DATAGRAM_SIZE];
    uint8_t inbuf[MAX_DATAGRAM_SIZE];
//    tor_socket_t sock;
};


typedef HT_HEAD(channel_quic_ht, channel_quic_t) channel_quic_ht_t;


#define BASE_CHAN_TO_QUIC(c) (channel_quic_from_base((c)))
#define QUIC_CHAN_TO_BASE(c) (channel_quic_to_base((c)))
#define CONST_BASE_CHAN_TO_QUIC(c) (channel_quic_from_base_const((c)))
#define CONST_QUIC_CHAN_TO_BASE(c) (channel_quic_to_base_const((c)))

/* Casts */
channel_t *channel_quic_to_base(channel_quic_t *quicchan);

channel_quic_t *channel_quic_from_base(channel_t *chan);


channel_t *channel_quic_connect(const tor_addr_t *addr, uint16_t port,
                                const char *id_digest,
                                const struct ed25519_public_key_t *ed_id);

//channel_listener_t *channel_quic_get_listener(void);
//
//channel_listener_t *channel_quic_start_listener(void);


/* Things for connection_or.c to call back into */
void channel_quic_handle_cell(cell_t *cell, or_connection_t *conn);

void channel_quic_handle_state_change_on_orconn(channel_quic_t *chan,
                                                or_connection_t *conn,
                                                uint8_t state);

void channel_quic_handle_var_cell(var_cell_t *var_cell,
                                  or_connection_t *conn);

void channel_quic_update_marks(or_connection_t *conn);


//int channel_quic_handle_read(connection_t *conn);

int channel_quic_on_incoming(tor_socket_t sock);

/* Cleanup at shutdown */
void channel_quic_free_all(void);


void channel_quic_read_callback(tor_socket_t fd, short event, void *_quicchan);

void channel_quic_write_callback(tor_socket_t fd, short event, void *_quicchan);

channel_quic_t *channel_quic_create(struct sockaddr_in *peer_addr, uint8_t *scid, quiche_conn *conn);

int channel_quic_on_listener_initialized(connection_t *conn);

void channel_quic_common_init(channel_quic_t *quicchan);

quiche_config *create_quiche_config(void);

uint8_t *fill_with_random_bytes(uint8_t *array, size_t array_len);

int channel_quic_flush_egress(struct channel_quic_t *channel);

int
channel_quic_equal(const struct channel_quic_t *c1, const struct channel_quic_t *c2);

unsigned
channel_quic_hash(const struct channel_quic_t *d);

#endif //TOR_CHANNELQUIC_H
