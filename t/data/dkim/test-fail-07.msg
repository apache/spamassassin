DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=
	sa-test.spamassassin.org; h=from:to:subject:message-id:date
	:mime-version:content-type; s=t0768; bh=15pFrAvOGi+eHKJgB6psh6iI
	BCbvYSuhPj+wQn6C7Ss=; b=eV6LkWhajlYSsITDKosr4TrlUi/+q+AVtdYQ3JdF
	pTwA0rJ/t7YbrRE6/U2e5bhEswrGymR8guzs2Xf0qlK0Ti2XX51LxP9UU/tROWq1
	Dd1paCom25LeMoUZ8JVxS6tywKmKKc8n1bhzXEnSNYO55YoVs/QehP3etQAnjsT2
	aKo=
From: SpamAssassin Test <test@sa-test.spamassassin.org>
To: undisclosed-recipients:;
Subject: test message (should fail) 7
Message-ID: <4A294538.10002@spamassassin.org>
Date: Mon, 08 Jun 2009 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii

testing
