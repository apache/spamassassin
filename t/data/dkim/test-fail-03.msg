DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=
	sa-test.spamassassin.org; h=from:to:subject:message-id:date
	:mime-version:content-type; s=t0768; t=1244419200; bh=15pFrAvOGi
	+eHKJgB6psh6iIBCbvYSuhPj+wQn6C7Ss=; b=EiCs7/1kFKbYl6hdaIR5N2Qjvz
	qxqoR0jI/vud0XWCxcmvbrCO7BCy7bfrewMndHMBdWHYOjlK7JwF7re8dfx2PKm1
	n/zyLE+irAIBAsKaA3sWIqdq8swlp04Rb/6CJn
From: SpamAssassin Test <test@sa-test.spamassassin.org>
To: undisclosed-recipients:;
Subject: test message (should fail) 3
Date: Mon, 08 Jun 2009 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii

testing
