/*
 * This code is copyright 2001 by Craig Hughes
 * Conversion to a thread-safe shared library copyright 2002 Liam Widdowson
 * Portions copyright 2002 by Brad Jorsch
 * It is licensed under the same license as Perl itself.  The text of this
 * license is included in the SpamAssassin distribution in the file named
 * "License".
 */
#ifndef LIBSPAMC_H
#define LIBSPAMC_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>

#define EX_ISSPAM       1
#define EX_NOTSPAM      0
#define EX_TOOBIG     866

/* Aug 14, 2002 bj: Bitflags instead of lots of bool parameters */
#define SPAMC_MODE_MASK      1
#define SPAMC_RAW_MODE       0
#define SPAMC_BSMTP_MODE     1

#define SPAMC_USE_SSL	     1<<27
#define SPAMC_SAFE_FALLBACK  1<<28
#define SPAMC_CHECK_ONLY     1<<29

/* Aug 14, 2002 bj: A struct for storing a message-in-progress */
typedef enum {
    MESSAGE_NONE,
    MESSAGE_ERROR,
    MESSAGE_RAW,
    MESSAGE_BSMTP,
    MAX_MESSAGE_TYPE
} message_type_t;

struct message {
    /* Set before passing the struct on! */
    int max_len;  /* messages larger than this will return EX_TOOBIG */
    int timeout;  /* timeout for read() system calls */

    /* Filled in by message_read */
    message_type_t type;
    char *raw; int raw_len;   /* Raw message buffer */
    char *pre; int pre_len;   /* Pre-message data (e.g. SMTP commands) */
    char *msg; int msg_len;   /* The message */
    char *post; int post_len; /* Post-message data (e.g. SMTP commands) */

    /* Filled in by filter_message */
    int is_spam;              /* EX_ISSPAM if the message is spam, EX_NOTSPAM
                                 if not, EX_TOOBIG if a filtered message is
                                 returned in out below. */
    float score, threshold;   /* score and threshold */
    char *out; int out_len;   /* Output from spamd. Either the filtered
                                 message, or the check-only response. Or else,
                                 a pointer to msg above. */
};

/* Aug 14, 2002 bj: New interface functions */

/* Read in a message from the fd, with the mode specified in the flags.
 * Returns EX_OK on success, EX_otherwise on failure. On failure, m may be
 * either MESSAGE_NONE or MESSAGE_ERROR. */
int message_read(int in_fd, int flags, struct message *m);

/* Write out a message to the fd, as specified by m->type. Note that
 * MESSAGE_NONE messages have nothing to write. Also note that if you ran the
 * message through message_filter with SPAMC_CHECK_ONLY, it will only output
 * the "score/threshold" line. */
long message_write(int out_fd, struct message *m);

/* Pass the message through spamd (at addr) as the specified user, with the
 * given flags. Returns EX_OK on success, or various errors on error. If it was
 * successful, message_write will print either the CHECK_ONLY output, or the
 * filtered message in the appropriate output format. */
int message_filter(const struct sockaddr *addr, char *username, int flags, struct message *m);

/* Convert the host/port into a struct sockaddr. Returns EX_OK on success, or
 * else an error EX. */
int lookup_host(const char *hostname, int port, struct sockaddr *a);

/* Pass the message through one of a set of spamd's. This variant will handle
 * multiple spamd machines; if a connect failure occurs, it will fail-over to
 * the next one in the struct hostent. Otherwise identical to message_filter().
 */
int message_filter_with_failover (const struct hostent *hent, int port, char
    *username, int flags, struct message *m);

/* Convert the host into a struct hostent, for use with
 * message_filter_with_failover() above. Returns EX_OK on success, or else an
 * error EX.  Note that the data filled into hent is from gethostbyname()'s
 * static storage, so any call to gethostbyname() between
 * lookup_host_for_failover() and message_filter_with_failover() will overwrite
 * this.  Take a copy, and use that instead, if you think a call may occur in
 * your code, or library code that you use (such as syslog()). */
int lookup_host_for_failover(const char *hostname, struct hostent *hent);

/* Dump the message. If there is any data in the message (typically, m->type
 * will be MESSAGE_ERROR) it will be message_writed. Then, fd_in will be piped
 * to fd_out intol EOF. This is particularly useful if you get back an
 * EX_TOOBIG. */
void message_dump(int in_fd, int out_fd, struct message *m);

/* Do a message_read->message_filter->message_write sequence, handling errors
 * appropriately with dump_message or appropriate CHECK_ONLY output. Returns
 * EX_OK or EX_ISSPAM/EX_NOTSPAM on success, some error EX on error. */
int message_process(const char *hostname, int port, char *username, int max_size, int in_fd, int out_fd, const int flags);

/* Cleanup the resources we allocated for storing the message. Call after
 * you're done processing. */
void message_cleanup(struct message *m);

/* Aug 14, 2002 bj: This is now legacy, don't use it. */
int process_message(const char *hostname, int port, char *username, 
                    int max_size, int in_fd, int out_fd,
                    const int check_only, const int safe_fallback);

#endif

