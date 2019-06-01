#include "../common/common.c"

#include "json/json.h"

unsigned char *gRequest; // request buffer
int gRequestMax = 4096;      // maximum buffer size
int gRequestSize;       // current buffer size
char *token;

char *gServerIP;

unsigned char *gContents;
int gContents_len;

unsigned char *gTitle;
int gTitle_len;

json_object *gObj;

void generate_token()
{
  struct sockaddr_in sin;
  int len;

  len = sizeof(struct sockaddr_in);
  if(getpeername(0, (void *)&sin, &len) == -1)
      err(EXIT_FAILURE, "Unable to getpeername(0, ...): ");

  srand((getpid() << 16) ^ (getppid() + (time(NULL) ^
      sin.sin_addr.s_addr) + sin.sin_port));

  asprintf(&token, "// %s:%d-%d-%d-%d-%d", inet_ntoa(sin.sin_addr),
      ntohs(sin.sin_port), (int)time(NULL), rand(), rand(),
      rand());
}

void send_token()
{
  generate_token();

  printf("\"%s\"\n", token);
  fflush(stdout);
}

void read_request()
{
  int ret;

  gRequest = malloc(gRequestMax);
  if(!gRequest) errx(EXIT_FAILURE, "Failed to allocate %d bytes",
      gRequestMax);

  while(1) {
      ret = read(0, gRequest + gRequestSize, gRequestMax - gRequestSize);
      if(ret == -1) err(EXIT_FAILURE, "Failed to read %d bytes ... ",
          gRequestMax - gRequestSize);

      if(ret == 0) break;

      gRequestSize += ret;

      if(gRequestSize == gRequestMax) {
          gRequest = realloc(gRequest, gRequestMax * 2);
          if(gRequest == NULL) {
              errx(EXIT_FAILURE, "Failed to realloc from %d bytes "
              "to %d bytes ", gRequestMax, gRequestMax * 2);
          }
          gRequestMax *= 2;
      }
  }

  close(0); close(1); close(2);
}

#include <openssl/hmac.h>

void validate_request()
{
  unsigned char result[20];
  unsigned char invalid;
  int len;

  if(strncmp(gRequest, token, strlen(token)) != 0)
      errx(EXIT_FAILURE, "Token not found!");
      // XXX won't be seen by user

  len = sizeof(result);

  HMAC(EVP_sha1(), token, strlen(token), gRequest, gRequestSize, result,
      &len); // hashcash with added hmac goodness

  invalid = result[0] | result[1]; // Not too bad :>
  if(invalid)
      errx(EXIT_FAILURE, "Checksum failed! (got %02x%02x%02x%02x...)",
      result[0], result[1], result[2], result[3]);
      // XXX won't be seen by user.
}

void parse_request()
{
  json_object *new_obj;
  new_obj = json_tokener_parse(gRequest);
  if(is_error(new_obj)) errx(EXIT_FAILURE, "Unable to parse request");
  gObj = new_obj;
}

void decode_string(const char *src, unsigned char *dest, int *dest_len)
{
  char swap[5], *p;
  int what;
  unsigned char *start, *end;

  swap[4] = 0;
  start = dest;
  // make sure we don't over the end of the allocated space.
  end = dest + *dest_len;

  while(*src && dest != end) {
      // printf("*src = %02x, dest = %p, end = %p\n", (unsigned char)
      // *src, dest, end);

      if(*src == '\\') {
          *src++;
          // printf("-> in src == '\\', next byte is %02x\n", *src);

          switch(*src) {
              case '"':
              case '\\':
              case '/':
                  *dest++ = *src++;
                  break;
              case 'b': *dest++ = '\b'; src++; break;
              case 'f': *dest++ = '\f'; src++; break;
              case 'n': *dest++ = '\n'; src++; break;
              case 'r': *dest++ = '\r'; src++; break;
              case 't': *dest++ = '\t'; src++; break;
              case 'u':
                  src++;

                  // printf("--> in \\u handling. got %.4s\n",
                  // src);

                  memcpy(swap, src, 4);
                  p = NULL;
                  what = strtol(swap, &p, 16);

                  // printf("--> and in hex, %08x\n", what);

                  *dest++ = (what >> 8) & 0xff;
                  *dest++ = (what & 0xff);
                  src += 4;
                  break;
              default:
                  errx(EXIT_FAILURE, "Unhandled encoding found");
                  break;
          }
      } else {
          *dest++ = *src++;
      }
  }

  // and record the actual space taken up
  *dest_len = (unsigned int)(dest) - (unsigned int)(start);
  // printf("and the length of the function is ... %d bytes", *dest_len);

}

void handle_request()
{
  unsigned char title[128];
  char *tags[16];
  unsigned char contents[1024];

  int tag_cnt = 0;
  int i;
  int len;

  memset(title, 0, sizeof(title));
  memset(contents, 0, sizeof(contents));

  json_object_object_foreach(gObj, key, val) {
      if(strcmp(key, "tags") == 0) {
          for(i=0; i < json_object_array_length(val); i++) {
              json_object *obj = json_object_array_get_idx(val, i);
              tags[tag_cnt + i] = json_object_get_string(obj);
          }
          tag_cnt += i;
      } else if(strcmp(key, "title") == 0) {
          len = sizeof(title);
          decode_string(json_object_get_string(val), title, &len);

          gTitle = calloc(len+1, 1);
          gTitle_len = len;
          memcpy(gTitle, title, len);

      } else if(strcmp(key, "contents") == 0) {
          len = sizeof(contents);
          decode_string(json_object_get_string(val), contents, &len);

          gContents = calloc(len+1, 1);
          gContents_len = len;
          memcpy(gContents, contents, len);

      } else if(strcmp(key, "serverip") == 0) {
          gServerIP = json_object_get_string(val);
      }
  }
  printf("and done!\n");
}

void post_blog_article()
{
  char *port = "80", *p;
  struct sockaddr_in sin;
  int fd;
  int len, cl;

  unsigned char *post, *data;

  // We can't post if there is no information available
  if(! gServerIP || !gContents || !gTitle) return;

  post = calloc(128 * 1024, 1);
  cl = gTitle_len + gContents_len + strlen("\r\n\r\n");

  len = sprintf(post, "POST /blog/post HTTP/1.1\r\n");
  len += sprintf(post + len, "Connection: close\r\n");
  len += sprintf(post + len, "Host: %s\r\n", gServerIP);
  len += sprintf(post + len, "Content-Length: %d\r\n", cl);
  len += sprintf(post + len, "\r\n");

  memcpy(post + len, gTitle, gTitle_len);
  len += gTitle_len;
  len += sprintf(post + len, "\r\n");
  memcpy(post + len, gContents, gContents_len);
  len += gContents_len;

  p = strchr(gServerIP, ':');
  if(p) {
      *p++ = 0;
      port = p;
  }

  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr(gServerIP);
  sin.sin_port = htons(atoi(port));

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd == -1) err(EXIT_FAILURE, "socket(): ");
  if(connect(fd, (void *)&sin, sizeof(struct sockaddr_in)) == -1)
      err(EXIT_FAILURE, "connect(): ");
  nwrite(fd, post, len);
  close(fd);
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *p;

  signal(SIGPIPE, SIG_IGN);

  background_process(NAME, UID, GID);
  fd = serve_forever(PORT);
  set_io(fd);

  send_token();
  read_request();
  validate_request();
  parse_request();
  handle_request();
  post_blog_article();
}