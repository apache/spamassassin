DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=
	sa-test-nxd.spamassassin.org; h=from:to:subject:message-id:date
	:mime-version:content-type; s=txxxx; t=1244419200; bh=15pFrAvOGi
	+eHKJgB6psh6iIBCbvYSuhPj+wQn6C7Ss=; b=ew3dq85AwDg60ap6eG31FJfvvC
	XaYMYXKc6oepATDhzciHeXZQF7hPJNIS12sMrVjULEnBOK9rv3s9Zt2LWszfbnqP
	2r0wsYtZ9CX469vltG+n91BqT+qrfTl0curQ4o
From: SpamAssassin Test <test@sa-test-nxd.spamassassin.org>
To: undisclosed-recipients:;
Subject: test message (should fail) 9
Message-ID: <4A294538.10002@spamassassin.org>
Date: Mon, 08 Jun 2009 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii

testing
