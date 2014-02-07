DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=
	sa-test.spamassassin.org; h=from:to:subject:message-id:date
	:mime-version:content-type; s=t0768; t=1244419200; bh=15pFrAvOGi
	+eHKJgB6psh6iIBCbvYSuhPj+wQn6C7Ss=; b=mIrAui3j2XnmatMmIz4LaV02wt
	OY7v3zJAq+pIdOjyhqgSehCByD0/+DJWjOHXFjul0ZLSqMd+M+13ZQo/5Z0OValm
	FTva44EC7CPc1ZvZn7S9WpDyBW5pz7qGD4d8q3
From: SpamAssassin Test FAKE <test@sa-test.spamassassin.org>
To: undisclosed-recipients:;
Subject: test message (should fail) 2
Message-ID: <4A294538.10002@spamassassin.org>
Date: Mon, 08 Jun 2009 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii

testing
