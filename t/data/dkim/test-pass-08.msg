DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=
	sa-test.spamassassin.org; h=from:to:subject:message-id:date
	:mime-version:content-type; s=t0768; t=1244419200; bh=15pFrAvOGi
	+eHKJgB6psh6iIBCbvYSuhPj+wQn6C7Ss=; b=LOg+IyOPKmSkio7w57bKMSsLlE
	R2uatTzmrYlvo81oEhClmEE3sBza9nrkfaIfnGQFrFGGfRG8Lqu/XJCm4BIoZX5a
	2HK1EotKYyqXDTrJw44DqDS6SVPBFzeEMgI+Un
Subject: fake subject
MIME-Version: 2.0
Message-ID: <123@example.com>
To: SpamAssassin Test <test@sa-test.spamassassin.org>
From: SpamAssassin Test <test@sa-test.spamassassin.org>
To: undisclosed-recipients:;
Subject: test message 8
Message-ID: <4A294538.10002@spamassassin.org>
Date: Mon, 08 Jun 2009 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=iso-8859-1
Content-Type: text/plain; charset=utf8
Content-Type: text/plain; charset=us-ascii

testing
