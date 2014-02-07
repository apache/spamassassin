DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=
	sa-test.spamassassin.org; h=from:to:subject:message-id:date
	:mime-version:content-type; s=t1024a; bh=15pFrAvOGi+eHKJgB6psh6i
	IBCbvYSuhPj+wQn6C7Ss=; b=IAdlIs0kt/UsFvUEDoLToL45HAaB1IqXtJxATY2
	m3bYmDqF2G48cPc5BvQzaGB4cbjsuYEuLFnhnEgWGoLztjVAMlOlf8Fl7Qq0wXVp
	nWUxJPAGHJBXarvKwnrMrhXGS
From: SpamAssassin Test <test@sa-test.spamassassin.org>
To: undisclosed-recipients:;
Subject: test message (should fail) 8
Message-ID: <4A294538.10002@spamassassin.org>
Date: Mon, 08 Jun 2009 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii

testing
