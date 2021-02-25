#ifndef TOR_CHANNELQUIC_H
#define TOR_CHANNELQUIC_H

#include "lib/quiche/include/quiche.h"

#define QUIC_CHAN_MAGIC 0x75cd0b9c
#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350

struct channel_quic_t {
    /* Base channel_t struct */
    channel_t base_;
    quiche_conn *conn;
    tor_addr_t *addr;
    uint16_t *port;
    uint8_t out[MAX_DATAGRAM_SIZE];
};


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

channel_listener_t *channel_quic_get_listener(void);

channel_listener_t *channel_quic_start_listener(void);

channel_t *channel_quic_handle_incoming(or_connection_t *orconn);


/* Things for connection_or.c to call back into */
void channel_quic_handle_cell(cell_t *cell, or_connection_t *conn);

void channel_quic_handle_state_change_on_orconn(channel_quic_t *chan,
                                                or_connection_t *conn,
                                                uint8_t state);

void channel_quic_handle_var_cell(var_cell_t *var_cell,
                                  or_connection_t *conn);

void channel_quic_update_marks(or_connection_t *conn);

/* Cleanup at shutdown */
void channel_quic_free_all(void);

#endif //TOR_CHANNELQUIC_H
