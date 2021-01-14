//
// Created by jaap on 17-12-20.
//

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */
#define CHANNEL_OBJECT_PRIVATE

#include "core/or/or.h"
#include "core/or/channel.h"
#include "core/or/channelquic.h"
#include "lib/quiche/include/quiche.h"

channel_t *channel_quic_connect(const tor_addr_t *addr, uint16_t port, const char *id_digest,
                                const struct ed25519_public_key_t *ed_id) {
  printf("Quiche version: %s\n", quiche_version());
  return NULL;
}
