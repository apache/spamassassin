#!/usr/bin/env python

# spamcheck.py: spam tagging support for Postfix/Cyrus
#
# Copyright (C) 2002, 2003 James Henstridge
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

# Spam Assassin filter to fit in between postfix (or other MTA) and
# Cyrus IMAP (or other MDA).  To hook it up, simply copy the
# spamcheck.py and spamd.py files to postfix's libexec directory and
# add a line like the following to postfix's master.cf:
#
# spamcheck	unix	-	n	n	-	-	pipe
#     flags=R user=cyrus
#     argv=/usr/libexec/postfix/spamcheck.py -s ${sender} -r ${user} -l unix:/...
#
# then in main.cf, set the mailbox_transport to spamcheck.  A copy of
# spamcheck will be started for each incomming message.  The spamcheck
# script will contact the IMAP server's LMTP socket to check whether
# the user exists, get spamd to process the message and then pass the
# message to the IMAP server.

import sys
import re, getopt
import smtplib, socket
import spamd

# exit statuses taken from <sysexits.h>
EX_OK       = 0
EX_USAGE    = 64
EX_DATAERR  = 65
EX_NOUSER   = 67
EX_TEMPFAIL = 75

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
            self.sock.connect(host)
        else:
            port = LMTP_PORT
            if ':' in host:
                hose, port = host.split(':', 1)
                port = int(port)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.debuglevel > 0: print 'connect:', (host, port)
            self.sock.connect((host, port))
        (code, msg) = self.getreply()
        if self.debuglevel > 0: print 'connect:', msg
        return (code, msg)

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
        resp = self.lhlo_resp.split('\n')
        del resp[0]
        for each in resp:
            m = re.match(r'(?P<feature>[A-Za-z0-9][A-Za-z0-9\-]*)',each)
            if m:
                feature = m.group("feature").lower()
                params = m.string[m.end("feature"):].strip()
                self.lmtp_features[feature] = params
        return (code, msg)

    # make sure bits of code that tries to EHLO actually LHLO instead
    ehlo = lhlo

def process_message(spamd_host, lmtp_host, sender, recipient):
    try:
        lmtp = LMTP(lmtp_host)
    except:
        sys.exit(EX_TEMPFAIL)
    #lmtp.set_debuglevel(2)
    code, msg = lmtp.lhlo()
    if code != 250: sys.exit(EX_TEMPFAIL)

    # connect to the LMTP server
    code, msg = lmtp.mail(sender)
    if code != 250: sys.exit(1)
    code, msg = lmtp.rcpt(recipient)
    if code == 550: sys.exit(EX_NOUSER)
    if code != 250: sys.exit(EX_TEMPFAIL)

    # read in the first chunk of the message
    CHUNKSIZE = 256 * 1024
    data = sys.stdin.read(CHUNKSIZE)

    # if data is less than chunk size, check it
    if len(data) < CHUNKSIZE:
        connection = spamd.SpamdConnection(spamd_host)
        connection.addheader('User', recipient)
        try:
            connection.check(spamd.PROCESS, data)
            data = connection.response_message
        except spamd.error, e:
            sys.stderr.write('spamcheck: %s' % str(e))

    # send the data in chunks
    lmtp.putcmd("data")
    code, msg = lmtp.getreply()
    if code != 354: sys.exit(EX_TEMPFAIL)
    lmtp.send(smtplib.quotedata(data))
    
    data = sys.stdin.read(CHUNKSIZE)
    while data != '':
        lmtp.send(smtplib.quotedata(data))
        data = sys.stdin.read(CHUNKSIZE)
    lmtp.send('\r\n.\r\n')
 
    code, msg = lmtp.getreply()
    if code != 250: sys.exit(EX_TEMPFAIL)

def main(argv):
    spamd_host = ''
    lmtp_host = None
    sender = None
    recipient = None
    try:
        opts, args = getopt.getopt(argv[1:], 's:r:l:')
    except getopt.error, err:
        sys.stderr.write('%s: %s\n' % (argv[0], err))
        sys.exit(EX_USAGE)
    for opt, arg in opts:
        if opt == '-s': sender = arg
        elif opt == '-r': recipient = arg.lower()
        elif opt == '-l': lmtp_host = arg
        else:
            sys.stderr.write('unexpected argument\n')
            sys.exit(EX_USAGE)
    if args:
        sys.stderr.write('unexpected argument\n')
        sys.exit(EX_USAGE)
    if not lmtp_host or not sender or not recipient:
        sys.stderr.write('required argument missing\n')
        sys.exit(EX_USAGE)

    try:
        process_message(spamd_host, lmtp_host, sender, recipient)
    except SystemExit:
        raise # let SystemExit through ...
    except:
        sys.stderr.write('%s: %s\n' % sys.exc_info()[:2])
        sys.exit(1)

if __name__ == '__main__':
    main(sys.argv)

