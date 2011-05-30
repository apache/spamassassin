DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=
	sa-test.spamassassin.org; h=from:to:from:subject:message-id:date
	:mime-version:content-type; s=t0768; t=1244419200; bh=15pFrAvOGi
	+eHKJgB6psh6iIBCbvYSuhPj+wQn6C7Ss=; b=QpX3ST7TgW/mZLgCkHRpUzWkFu
	0t27yxMr780SFx4V6AouVaJ902fyVvHw9rXMEv9rSp+uIYwJvuekgxNgRNHT0Pg2
	Ve4ohhi/WNfaAzPFjMpeI7dLK8uPN20k5xxj2c
From: SpamAssassin Test <test@sa-test.spamassassin.org>
From: SpamAssassin Test <test@sa-test.spamassassin.org>
To: undisclosed-recipients:;
Subject: test message (should fail) 4
Message-ID: <4A294538.10002@spamassassin.org>
Date: Mon, 08 Jun 2009 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii

testing
