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

static void debug_log(const char *line, void *argp) {
  fprintf(stderr, "%s\n", line);
}

channel_t *channel_quic_connect(const tor_addr_t *addr, uint16_t port, const char *id_digest,
                                const struct ed25519_public_key_t *ed_id) {
  printf("Creating quiche connection, quiche version: %s\n", quiche_version());

  quiche_enable_debug_logging(debug_log, NULL);

  struct sockaddr *sock_addr;
  sock_addr = tor_malloc(sizeof(struct sockaddr_storage));
  socklen_t sock_len = 0;
  sock_len = tor_addr_to_sockaddr(addr, port, &sock_addr, sizeof(struct sockaddr_storage));

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

  return NULL;
}
