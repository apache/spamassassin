#!/usr/bin/env python

# spamcheck.py: spam tagging support for Postfix/Cyrus
#
# Copyright (C) 2002 James Henstridge
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

#
# Spam Assassin filter to fit in between postfix (or other MTA) and
# Cyrus IMAP (or other MDA).  To hook it up, simply add a line like
# the following to postfix's master.cf:
#
# spamcheck	unix	-	n	n	-	-	pipe
#     flags=R user=cyrus
#     argv=/usr/bin/spamcheck.py -s ${sender} -r ${user} -l unix:/...
#
# then in main.cf, set the mailbox_transport to spamcheck.  A copy of
# spamcheck will be started for each incomming message.  Spamcheck will
# contact the local spamd process to handle the message, then send the
# mail on to the LMTP socket.

import sys, string
import re, getopt
import smtplib, socket
import exceptions

# EX_TEMPFAIL is 75 on every Unix I've checked, but...
# check /usr/include/sysexits.h if you have odd problems.
USAGE = 64
DATAERR = 65
NOUSER = 67
TEMPFAIL = 75

# this class hacks smtplib's SMTP class into a shape where it will
# successfully pass a message off to Cyrus's LMTP daemon.
# Also adds support for connecting to a unix domain socket.
class LMTP(smtplib.SMTP):
    lhlo_resp = None
    def __init__(self, host=''):
        self.lmtp_features  = {}
        self.esmtp_features = self.lmtp_features

        if host:
            (code, msg) = self.connect(host)
            if code != 220:
                raise smtplib.SMTPConnectError(code, msg)

    def connect(self, host='localhost'):
        """Connect to a host on a given port.

        If the hostname starts with `unix:', the remainder of the string
        is assumed to be a unix domain socket.
        """

        if host[:5] == 'unix:':
            host = host[5:]
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if self.debuglevel > 0: print 'connect:', host
            try:
              self.sock.connect(host)
            except socket.error:
              sys.exit(TEMPFAIL)
        else:
            i = string.find(host, ':')
            if i >= 0:
                host, port = host[:i], host[i+1:]
                try: port = int(port)
                except string.atoi_error:
                    raise socket.error, "non numeric port"
            if not port: port = LMTP_PORT
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.debuglevel > 0: print 'connect:', (host, port)
            self.sock.connect((host, port))
        (code, msg) = self.getreply()
        if self.debuglevel > 0: print 'connect:', msg
        return (code, msg)

    def putcmd(self, cmd, args=""):
        """Send a command to the server."""
        if args:
            str = '%s %s%s' % (cmd, args, smtplib.CRLF)
        else:
            str = '%s%s' % (cmd, smtplib.CRLF)
        self.send(str)

    def lhlo(self, name='localhost'):
        """ LMTP 'lhlo' command.
        Hostname to send for this command defaults to localhost.
        """
        self.putcmd("lhlo",name)
        (code, msg) = self.getreply()
        if code == -1 and len(msg) == 0:
            raise smtplib.SMTPServerDisconnected("Server not connected")
        self.lhlo_resp = msg
        self.ehlo_resp = msg
        if code != 250:
            return (code, msg)
        self.does_esmtp = 1
        # parse the lhlo response
        resp = string.split(self.lhlo_resp, '\n')
        del resp[0]
        for each in resp:
            m = re.match(r'(?P<feature>[A-Za-z0-9][A-Za-z0-9\-]*)',each)
            if m:
                feature = string.lower(m.group("feature"))
                params = string.strip(m.string[m.end("feature"):])
                self.lmtp_features[feature] = params
        return (code, msg)

    # make sure bits of code that tries to EHLO actually LHLO instead
    ehlo = lhlo

    def mail(self, sender, options=[]):
        optionlist = ''
        if options and self.does_esmtp:
            optionlist = ' ' + string.join(options, ' ')
        self.putcmd('mail', 'FROM:%s%s' % (smtplib.quoteaddr(sender), optionlist))
        return self.getreply()
    def rcpt(self, recip, options=[]):
        optionlist = ''
        if options and self.does_esmtp:
            optionlist = ' ' + string.join(options, ' ')
        self.putcmd('rcpt', 'TO:%s%s' % (smtplib.quoteaddr(recip), optionlist))
        return self.getreply()

response_pat = re.compile(r'^SPAMD/([\d.]+)\s+(-?\d+)\s+(.*)')

def spamcheck(spamd_host, spamd_port, user, data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((spamd_host, spamd_port))

    PROTOCOL_VERSION = "SPAMC/1.2"

    header = 'PROCESS %s\r\nUser: %s\r\nContent-length: %s\r\n\r\n' % \
        (PROTOCOL_VERSION, user, len(data))

    sock.send(header)
    sock.send(data)
    sock.shutdown(1) # shut down the writing half of the socket

    fd = sock.makefile('rb')
    
    # read the response back from the spamd server
    header_read = 0
    header = fd.readline()
    match = response_pat.match(header)
    if not match:
        raise RuntimeError, "bad response header"
    if match.group(2) != '0':
        raise RuntimeError, "bad response code %s" % match.group(3)

    content_length = -1
    header = fd.readline()
    while header and header != '\r\n':
        if header[:15] == 'Content-length:':
            content_length = int(header[15:])
        header = fd.readline()

    if header != '\r\n':
        raise IOError, "expected blank line after headers"

    # return the spam checked message
    return fd.read()

def process_message(spamd_host, spamd_port, lmtp_host, sender, recipient):
    CHUNKSIZE = 256 * 1024
    # read in the first chunk of the message
    
    data = sys.stdin.read(CHUNKSIZE)

    # is the message smaller than the maximum size?
    if len(data) < CHUNKSIZE:
        try:
            checked_data = spamcheck(spamd_host, spamd_port, recipient, data)
            # get rid of From ... line if present
            if checked_data[:5] == 'From ':
                nl = string.find(checked_data, '\n')
                if nl >= 0: checked_data = checked_data[nl+1:]
        except:
            sys.stderr.write('%s: %s\n' % sys.exc_info()[:2])
            checked_data = data # fallback

        try:
            lmtp = LMTP(lmtp_host)
        except:
            sys.exit(TEMPFAIL)

        code, msg = lmtp.lhlo()
        if code != 250: sys.exit(TEMPFAIL)

        #lmtp.set_debuglevel(1)
        try:
            lmtp.sendmail(sender, recipient, checked_data)
        except smtplib.SMTPRecipientsRefused, e:
            if e.recipients.has_key(recipient):
                if e.recipients[recipient][0] == 550:
                    sys.exit(NOUSER)
                else:
                    sys.exit(TEMPFAIL)  # XXXX sort this out
        except smtplib.SMTPDataError, errors:
            if errors.smtp_code/100 == 4:
                sys.exit(TEMPFAIL)
            else:
                sys.exit(DATAERR)
    else:
        # too much data.  Just pass it through unchanged
        try:
            lmtp = LMTP(lmtp_host)
        except:
            sys.exit(TEMPAIL)
        code, msg = lmtp.lhlo()
        if code != 250: sys.exit(TEMPFAIL)
        #lmtp.set_debuglevel(1)

        code, msg = lmtp.mail(sender)
        if code != 250: sys.exit(TEMPFAIL)
        code, msg = lmtp.rcpt(recipient)
        if code == 550: sys.exit(NOUSER)
        if code != 250: sys.exit(TEMPFAIL)

        # send the data in chunks
        lmtp.putcmd("data")
        code, msg = lmtp.getreply()
        if code != 354: sys.exit(TEMPFAIL)
        lmtp.send(smtplib.quotedata(data))
        data = ''
        data = sys.stdin.read(CHUNKSIZE)
        while data != '':
            lmtp.send(smtplib.quotedata(data))
            data = ''
            data = sys.stdin.read(CHUNKSIZE)
        lmtp.send('\r\n.\r\n')
 
        code, msg = lmtp.getreply()
        if code/100 == 4:
            sys.exit(TEMPFAIL)
        elif code != 250:
            sys.exit(DATAERR)

def main(argv):
    spamd_host = 'localhost'
    spamd_port = 783
    lmtp_host = None
    sender = None
    recipient = None
    try:
        opts, args = getopt.getopt(argv[1:], 's:r:l:')
    except getopt.error, err:
        sys.stderr.write('%s: %s\n' % (argv[0], err))
        sys.exit(USAGE)
    for opt, arg in opts:
        if opt == '-s': sender = arg
        elif opt == '-r': recipient = string.lower(arg)
        elif opt == '-l': lmtp_host = arg
        else:
            sys.stderr.write('unexpected argument\n')
            sys.exit(USAGE)
    if args:
        sys.stderr.write('unexpected argument\n')
        sys.exit(USAGE)
    if not lmtp_host or not sender or not recipient:
        sys.stderr.write('required argument missing\n')
        sys.exit(USAGE)

    try:
        process_message(spamd_host, spamd_port, lmtp_host, sender, recipient)
    except SystemExit, status:
        raise SystemExit, status
    except:
        sys.stderr.write('%s: %s\n' % sys.exc_info()[:2])
        sys.exit(TEMPFAIL)

if __name__ == '__main__':
    main(sys.argv)

