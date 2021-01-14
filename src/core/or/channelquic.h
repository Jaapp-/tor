#ifndef TOR_CHANNELQUIC_H
#define TOR_CHANNELQUIC_H

struct channel_quic_t {
    /* Base channel_t struct */
    channel_t base_;
//    /* or_connection_t pointer */
//    or_connection_t *conn;
};


#define BASE_CHAN_TO_QUIC(c) (channel_quic_from_base((c)))
#define QUIC_CHAN_TO_BASE(c) (channel_quic_to_base((c)))

/* Casts */
channel_t * channel_quic_to_base(channel_quic_t *quicchan);
channel_quic_t * channel_quic_from_base(channel_t *chan);


channel_t * channel_quic_connect(const tor_addr_t *addr, uint16_t port,
                                const char *id_digest,
                                const struct ed25519_public_key_t *ed_id);
channel_listener_t * channel_quic_get_listener(void);
channel_listener_t * channel_quic_start_listener(void);
channel_t * channel_quic_handle_incoming(or_connection_t *orconn);

#endif //TOR_CHANNELQUIC_H
