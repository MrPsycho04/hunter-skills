# Corpus mining summary

Disclosed (valid) reports mined: 15259

Payment is an impact signal only; zero-bounty reports are valid evidence.

## xss — 2569 valid / 546 paid (21%) / median paid $500

**Top techniques from ALL valid writeups:** DOM / HTML source inspection(743), second-order / stored / blind delivery(413), encoding / double-encode / null byte(332), WAF / sanitizer / filter bypass(332), admin / privileged-role context(267), public source-code / repo review(208), file upload / filename / extension(207), HTTP method / verb tampering(183), two-account / cross-account replay(158), Content-Type / body-format switch(135), internal service / port / container(120), XML / SOAP / SAML / XXE(113)

**Tools:** browser(320), devtools(194), source-code-review(168), burp(63), curl(36), git(36), javascript-debugging(33), python(15), burp-repeater(8), beautifier(6)

**Bypasses:** bypass(261), content-type(203), blind(50), bypassed(44), open redirect(43), whitelist(39), %0d%0a(33), bypasses(26), unicode(22), bypassing(21), content type(14), %00(13)

**Top approach patterns:**
- (11) juliocesar was able to demonstrate this vulnerability by crafting a specially formatted url
- (9) description i discovered a cross site scripting xss vulnerability on specifically through the post method
- (5) and i can used this for ad jacking session hijacking bypassing csrf protection crypto mining
- (2) i found stored xss in concrete5
- (2) i want to report a reflected xss vulnerability that i found in www vimeo com website and which can affect the safety of your users
- (2) proof of concept i ve created an example malicious application associated with my partner account shopify whitehat bored engineer to demonstrate the issue
- (2) i discovered cross site scripting issue on the endpoint
- (2) report two weeks after the fix i ended up discovering what would soon become a head scratching mystery injecting a single in the payload would bypass the filter entirely and force the back end to somehow produce an unescaped along with the escaped one

## info-disclosure — 1827 valid / 339 paid (19%) / median paid $500

**Top techniques from ALL valid writeups:** public source-code / repo review(243), admin / privileged-role context(215), encoding / double-encode / null byte(162), internal service / port / container(159), file upload / filename / extension(154), header injection (Host / X-Forwarded / etc.)(142), Content-Type / body-format switch(128), cache / CDN / unkeyed header(125), subdomain / DNS / cert-transparency recon(106), error message / stack trace probing(99), XML / SOAP / SAML / XXE(92), public bucket / storage exposure(87)

**Tools:** source-code-review(205), browser(141), curl(140), devtools(76), burp(65), python(52), git(46), javascript-debugging(28), burp-repeater(16), burp-intruder(9)

**Bypasses:** content-type(218), bypass(103), whitelist(33), bypassed(23), bypasses(20), content type(20), host header(19), bypassing(18), blacklist(18), blind(15), url encoded(14), open redirect(11)

**Top approach patterns:**
- (2) hi i found an information disclosure vulnerability full path disclosure on your application
- (2) proof of concept sign in as a normal user i used my personal email address on the domain
- (2) i was able to fire this feature using gab2 subtitle chunks inside an avi file
- (2) even though tokens were immediately invalidated we decided to re engineer the process to eliminate any possibility of token leakage
- (2) reference impact the secure flag is an option that can be set by the application server when sending a new cookie to the user within an http response
- (2) description during poking around range looking for the cisco devices i came across which resolved to the while it s a not mil host it s likely related to the dod since it hosted in the dod controlled asn
- (2) at the following address i have found debug log file disclose the application full path on the server
- (2) i found that at least userid and password combination from that compromised db can still be used

## rce — 1399 valid / 338 paid (24%) / median paid $800

**Top techniques from ALL valid writeups:** public source-code / repo review(393), internal service / port / container(221), file upload / filename / extension(220), HTTP method / verb tampering(200), admin / privileged-role context(188), encoding / double-encode / null byte(159), WAF / sanitizer / filter bypass(153), race / concurrency / timing(130), Content-Type / body-format switch(119), cache / CDN / unkeyed header(100), header injection (Host / X-Forwarded / etc.)(95), error message / stack trace probing(92)

**Tools:** source-code-review(323), curl(155), git(111), browser(106), python(91), javascript-debugging(72), devtools(60), burp(59), burp-repeater(18), collaborator/oast(12)

**Bypasses:** content-type(199), bypass(145), %0d%0a(53), bypassed(40), whitelist(31), blacklist(25), bypassing(21), blind(19), bypasses(19), host header(19), unicode(14), null byte(11)

**Top approach patterns:**
- (4) this is achieved by simply sending a request that looks like below
- (3) worse yet by exposing kaspersky s internal processing to the web bugs in this processing code will turn into remote code execution vulnerabilities allowing websites to execute code with the privileges of the system user i haven t explored this possibility further
- (2) i was able to take control of this ip address and run my own ec2 instance
- (2) this vulnerability is in fact an cache poisoning in the ground which makes it possible to not harm the system in any way when testing
- (2) in the case of a popular streamer it opens them up to ddos attacks by just clicking on a safe tweet
- (2) i found that one of the targets belongs to dod vulnerable to cve where an attacker may be able to execute any malicious code like escalating remote code execution is also possible technical summary cve is a server side template injection vulnerability in the vmware workspace one access and identity manager
- (2) an unauthenticated attacker with network access could exploit this vulnerability by sending a specially crafted request to a vulnerable vmware workspace one or identity manager
- (2) using the dockerhub image the entire server is completely unavailable by repeatedly sending a small number of requests repeatedly

## authz-bypass — 1386 valid / 337 paid (24%) / median paid $500

**Top techniques from ALL valid writeups:** admin / privileged-role context(514), public source-code / repo review(230), Content-Type / body-format switch(165), encoding / double-encode / null byte(152), subdomain / DNS / cert-transparency recon(152), header injection (Host / X-Forwarded / etc.)(147), file upload / filename / extension(140), two-account / cross-account replay(137), HTTP method / verb tampering(125), internal service / port / container(110), employee / developer public info(99), cache / CDN / unkeyed header(98)

**Tools:** source-code-review(204), browser(141), burp(98), curl(75), devtools(69), python(33), git(32), burp-repeater(26), burp-collaborator(19), collaborator/oast(19)

**Bypasses:** bypass(357), content-type(314), bypassed(51), bypassing(47), whitelist(40), blind(25), open redirect(19), bypasses(18), %0d%0a(18), time-based(9), content type(8), host header(6)

**Top approach patterns:**
- (2) common access control vulnerabilities include bypassing access control checks by modifying the url internal application state or the html page or simply using a custom api attack tool
- (2) i created a folder named eicar on my system
- (2) steps to reproduce i created a dll file which when loaded spawns while giving information as to which application loaded the dll path from where the file was loaded and user privilege
- (2) so i was able to takeover the page and host the poc kubernetes version na component version na steps to reproduce
- (2) i haven t found any smart contract that has implemented this code
- (2) i have found smart contract that could be used for atomic swap between eth xmr but it hasn t got this vulnerability
- (2) we have found non production endpoints which exhibit this behavior
- (1) i just created the admin profile go check it out or see attached image

## other — 1226 valid / 246 paid (20%) / median paid $1000

**Top techniques from ALL valid writeups:** public source-code / repo review(189), encoding / double-encode / null byte(146), admin / privileged-role context(144), internal service / port / container(139), file upload / filename / extension(107), header injection (Host / X-Forwarded / etc.)(101), Content-Type / body-format switch(94), HTTP method / verb tampering(91), subdomain / DNS / cert-transparency recon(88), cache / CDN / unkeyed header(86), WAF / sanitizer / filter bypass(65), DOM / HTML source inspection(63)

**Tools:** source-code-review(171), curl(135), browser(99), python(61), devtools(57), burp(52), git(48), burp-intruder(19), javascript-debugging(15), ffuf(11)

**Bypasses:** content-type(209), bypass(194), unicode(69), content type(58), bypassing(40), bypassed(32), blind(30), bypasses(23), open redirect(21), whitelist(20), lowercase(19), %00(14)

**Top approach patterns:**
- (4) because of this endpoint we used we cannot see the request information which may degrade a defenders ability to track down an adversary
- (3) when megan is not working she enjoys competing in ctfs reading baking playing music geocaching and being with her family and friends
- (3) as a result of this an adversary can perform api calls using these endpoints and evade the logging of their ip address operating system information
- (2) i personally tried many times with wrong password even though no account lockout was detected
- (2) i just successfully created an account robots txt which results in a profile path of and results in an bugged account as accessing account settings etc is impossible
- (2) i only created it for testing purpose
- (2) i m because i hacker found bug because i report this bug i want to report a bug and because want some so please because you are telling me how much you pay money so i give you bug
- (2) as i understood injected content script could successfully emit events to background page only if popup was initiated earlier

## auth-bypass — 989 valid / 197 paid (20%) / median paid $500

**Top techniques from ALL valid writeups:** admin / privileged-role context(162), encoding / double-encode / null byte(107), Content-Type / body-format switch(98), header injection (Host / X-Forwarded / etc.)(86), two-account / cross-account replay(84), webhook / OAuth / SAML / integration abuse(78), cache / CDN / unkeyed header(75), HTTP method / verb tampering(73), public source-code / repo review(72),  HosT/absolute-URL reset poisoning(67), unauthenticated / removed-cookie test(63), internal service / port / container(63)

**Tools:** browser(86), source-code-review(62), curl(50), burp(45), devtools(40), python(24), burp-repeater(18), burp-intruder(16), javascript-debugging(11), git(10)

**Bypasses:** bypass(236), content-type(195), bypassed(34), bypassing(33), whitelist(19), race condition(18), open redirect(15), bypasses(15), unicode(14), %0d%0a(13), trailing dot(8), blacklist(4)

**Top approach patterns:**
- (2) i ve found a authorization issue in coinbase
- (1) however the authenticated session cookie used by a user before logging out is still active
- (1) i took a look at live install of phabricator and noticed that the user gets automatically logged in after clicking the password recovery link this link is sent to the user s mail
- (1) hi i ve found a way to circumvent redirect uri restrictions imposed by the web application using domain suffix subdomain technique
- (1) i created an oauth application under that has oauth redirect uri configured to so technically allowed request shall be denied request shall be surprisingly if i point the redirect uri to see mx suffix the endpoint will be accepted infact endpoint like will be accepted too
- (1) step scrape s3 i wrote a rough poc that scrapes s3 and shows the found exports not something i d use just something i wrote for demonstration purposes feel free to use the team id and name i mentioned before to check it out
- (1) i should also mention that i haven t looked through all the files but any sensitive file with the protection class set to anything other than nsfileprotectioncomplete would be extractable from the iphone without requiring the passcode
- (1) hi i found a brute forcing attacking on your website

## logic-and-design — 931 valid / 134 paid (14%) / median paid $500

**Top techniques from ALL valid writeups:** encoding / double-encode / null byte(132), public source-code / repo review(96), Content-Type / body-format switch(95), header injection (Host / X-Forwarded / etc.)(91), intercept & replay request in Burp(83), admin / privileged-role context(83), subdomain / DNS / cert-transparency recon(77), HTTP method / verb tampering(74), file upload / filename / extension(73), cache / CDN / unkeyed header(73), two-account / cross-account replay(61),  HosT/absolute-URL reset poisoning(52)

**Tools:** browser(106), source-code-review(76), curl(65), burp(64), devtools(52), burp-intruder(41), javascript-debugging(24), python(16), burp-repeater(10), git(10)

**Bypasses:** content-type(157), bypass(118), crlf(28), bypassing(27), bypassed(26), race condition(24), %00(14), content type(14), unicode(13), host header(12), blind(11), open redirect(11)

**Top approach patterns:**
- (2) e g by modifying etc hosts en wikipedia org
- (2) i noticed when we hit the reset password request endpoint too many times via some proxy for e g burp there is no rate limit on that endpoint and you can spam the email with s of requests and resend even more password reset emails to the users as there is no rate limiting on that
- (2) i was able to take control of this bucket and put my own content onto it
- (1) i used some other penetration tester s email address to create an account on hackerone and i choosed the username to be something erotic i know that users account will not be created untill they click on the confirmation key
- (1) you are right google is indexing browsers cache for search results after i reported the bug to facebook they added noindex and nofollow tags to all sensitive pages
- (1) i tried to change my email address on hackerone com and when i tried adding null bytes it was being accepted by hackerone com
- (1) i am registered wth and i tried to change my email address to and guess what this address was granted as an email address
- (1) i was able to upload an executable and i got a message saying it was successfully uploaded

## memory-corruption — 892 valid / 291 paid (33%) / median paid $750

**Top techniques from ALL valid writeups:** public source-code / repo review(232), WAF / sanitizer / filter bypass(209), race / concurrency / timing(201), HTTP method / verb tampering(150), encoding / double-encode / null byte(138), internal service / port / container(106), third-party data / paste / breach reuse(95), error message / stack trace probing(88), file upload / filename / extension(81), OAST / DNS / HTTP callback proof(56), fuzzing / wordlist brute force(55), admin / privileged-role context(51)

**Tools:** source-code-review(207), curl(165), python(96), git(91), javascript-debugging(37), browser(16), devtools(10), burp(3), burp-intruder(2), shodan(1)

**Bypasses:** unicode(81), bypass(55), content-type(24), null byte(20), crlf(17), bypasses(12), bypass_demo(11), type confusion(9), race condition(9), chunked(9), bypassing(7), normalize(6)

**Top approach patterns:**
- (2) the fix for this bug has been committed description i have found some vulnerable code at function
- (2) remote code execution rce by carefully crafting the payload in the data packet an attacker could overwrite critical heap metadata or function pointers potentially leading to arbitrary code execution on the victim s machine with the privileges of the curl process
- (2) description summary i discovered a heap buffer over read vulnerability in libcurl s smb protocol implementation
- (1) by carefully crafting the string to expand and choosing the tabsize you can limit the extent of the memory corruption to chosen objects
- (1) hello i found a bug on your registration sign up process
- (1) this bug is actually quite strange found by visiting some random page that loads that poc as a frame p i tried to reduce the poc unfortunately it became unstable
- (1) i noticed that there isn t any size check when someone tries to upload a flie through the upload picture option this could generate a memory leak or also a kind of dos and is deangerous with bigger and bigger files
- (1) after parsing a malformed mp4 file flash will keep on accessing a block of memory for timing

## crypto-and-secrets — 562 valid / 83 paid (15%) / median paid $500

**Top techniques from ALL valid writeups:** public source-code / repo review(154), internal service / port / container(87), JWT / token / base64 decode(55), subdomain / DNS / cert-transparency recon(54), race / concurrency / timing(51), admin / privileged-role context(50), cache / CDN / unkeyed header(50), file upload / filename / extension(49), encoding / double-encode / null byte(49), HTTP method / verb tampering(44), second-order / stored / blind delivery(33), webhook / OAuth / SAML / integration abuse(32)

**Tools:** source-code-review(144), curl(109), python(29), git(27), browser(25), nmap(14), burp(12), devtools(11), javascript-debugging(9), burp-intruder(4)

**Bypasses:** bypass(83), content-type(45), %00(33), bypassed(25), trailing dot(24), crlf(17), lowercase(16), bypassing(14), bypasses(7), whitelist(4), blind(3), unicode(2)

**Top approach patterns:**
- (3) ai disclosure i used an ai assistant claude for code review test setup and drafting
- (2) i was unable to use the found password as the api appears to be currently non functional but since the repo is active i would expect the server to be worked upon and the api to be functional in the future
- (2) for this reason i ve decided to make you aware of the issue
- (2) summary when i searched github for sensitive information i found some privet key in github repository
- (1) i have identified approximately android applications and some ipad that fail to validate ssl certificates either failing to validate valid certificate authorities correct hostnames or both
- (1) based on the available source code i see that proguard is not being used
- (1) by mx receiving tld with esmtps id e3si1568039obp for recipient domain tld version tlsv1 cipher ecdhe rsa rc4 sha bits tue apr pdt the perhaps slightly obvious fix seems to be to support esmtps by allowing starttls to be negotiated by the sending system s
- (1) as a possible fix you can replace captcha check with a honeypot trap or a simple task or skill testing question

## csrf — 541 valid / 93 paid (17%) / median paid $300

**Top techniques from ALL valid writeups:** encoding / double-encode / null byte(83), Content-Type / body-format switch(78), header injection (Host / X-Forwarded / etc.)(73), intercept & replay request in Burp(56), two-account / cross-account replay(52), XML / SOAP / SAML / XXE(50), HTTP method / verb tampering(49), DOM / HTML source inspection(46), admin / privileged-role context(44), file upload / filename / extension(41), cache / CDN / unkeyed header(36), webhook / OAuth / SAML / integration abuse(32)

**Tools:** browser(86), burp(52), devtools(42), source-code-review(20), burp-repeater(6), curl(5), burp-intruder(3), javascript-debugging(3), python(2), beautifier(1)

**Bypasses:** content-type(132), bypass(45), open redirect(13), bypassing(12), bypassed(8), same-site(7), content type(4), url encoded(4), %00(2), bypasses(2), double slash(2), blind(2)

**Top approach patterns:**
- (5) with a little help of social engineering like sending a link via email chat an attacker may trick the users of a web application into executing actions of the attacker s choosing
- (2) korprit was able to demonstrate this vulnerability by crafting a specially formatted webpage
- (2) description during my search in this domain i found it vulnerable to csrf so i tried to escalate it account takeover and i succeed impact account takeover via csrf system host s affected product s and version s cve numbers steps to reproduce vulnerable domain and endpoint
- (1) hi i have found a flash content type sniff vulnerability could allow attackers get user s team auth2 tokens
- (1) link while approving and reviewing a phrase you are able to send set a message
- (1) an attacker would need to guess the order id by sending some a lot of requests
- (1) i am security researcher and i pen test your website and i found there is click jacking attack and csrf attack can be done
- (1) to achieve the same session token is not verified while changing account setting s which result in account takeover description i have found that while changing setting session token is not verified so an attacker can basically plot a csrf attack which would change the default email of the user and this would led to account takeover

## idor — 382 valid / 88 paid (23%) / median paid $500

**Top techniques from ALL valid writeups:** two-account / cross-account replay(102), admin / privileged-role context(74), encoding / double-encode / null byte(56), header injection (Host / X-Forwarded / etc.)(52), Content-Type / body-format switch(49), intercept & replay request in Burp(45), swap object ID / parameter value(40), HTTP method / verb tampering(36), file upload / filename / extension(35), public source-code / repo review(32), employee / developer public info(23), parameter pollution / duplicate keys(16)

**Tools:** browser(52), burp(41), source-code-review(24), burp-repeater(17), devtools(13), burp-intruder(8), curl(7), python(4), git(3), burp-collaborator(2)

**Bypasses:** content-type(70), bypass(25), whitelist(9), bypassed(8), same-site(5), bypasses(2), bypassing(2), blind(2), null byte(1), race condition(1), normalized(1)

**Top approach patterns:**
- (2) psychomantis was able to demonstrate this vulnerability by crafting a specially formatted url
- (2) i have tested retrieving following ids
- (2) i l victim is able see the association to the attacker s child epic and may trust navigate to the attacker s group when clicking on it
- (1) i haven t tried this but i think this can be done
- (1) see screenshot where i was able to remove certain folks without inviting them
- (1) i apologize for the emails that were sent out to two different hackerone researchers accidentally
- (1) when i change identified user id to other user s id then request of add friend is send to other user without any token and secession validation
- (1) description while creating a product i noticed there is a call to which returns json details about the product

## open-redirect — 360 valid / 74 paid (21%) / median paid $300

**Top techniques from ALL valid writeups:** redirect chain / Location header(161), encoding / double-encode / null byte(44), webhook / OAuth / SAML / integration abuse(36), header injection (Host / X-Forwarded / etc.)(35), subdomain / DNS / cert-transparency recon(25), Content-Type / body-format switch(22), admin / privileged-role context(22), public source-code / repo review(21), DOM / HTML source inspection(20), WAF / sanitizer / filter bypass(19), cache / CDN / unkeyed header(18), XML / SOAP / SAML / XXE(18)

**Tools:** browser(33), source-code-review(19), devtools(14), burp(12), curl(8), burp-repeater(6), burp-intruder(2), dnsdump(1), postman(1), waybackurls(1)

**Bypasses:** open redirect(219), bypass(49), host header(36), content-type(33), whitelist(14), bypassed(11), trailing slash(6), url-encode(6), %00(5), bypassing(4), unicode(3), header injection(3)

**Top approach patterns:**
- (2) notice that you are redirected to and you re requested to complete oauth after logging in
- (1) hi i found that an attacker is able to steal access tokens of facebook users via phabricator app
- (1) hi i noticed that your facebook application used in the import photo can be used to take over the facebook account of the user being attacked
- (1) hi i found a bypass in the redirects won t work
- (1) proof steps click the link after clicking click the screen and you will be redirected to
- (1) for the second way i verified that the password reset functionality on the irc cloud website does not retrieve the host header when sending emails
- (1) here is the video of the poc the link i used in the video to report reporter user id reporter s id please fix this fastly thanks good day
- (1) for example works doesn t work i will investigate it further and get back with details if i find something more

## ssrf — 337 valid / 105 paid (31%) / median paid $700

**Top techniques from ALL valid writeups:** internal service / port / container(131), public source-code / repo review(66), header injection (Host / X-Forwarded / etc.)(60), encoding / double-encode / null byte(60), Content-Type / body-format switch(48), subdomain / DNS / cert-transparency recon(45), cloud metadata / IAM abuse(42), second-order / stored / blind delivery(40), admin / privileged-role context(39), WAF / sanitizer / filter bypass(39), OAST / DNS / HTTP callback proof(34), file upload / filename / extension(33)

**Tools:** source-code-review(62), browser(42), curl(31), burp(27), collaborator/oast(17), burp-collaborator(16), python(15), devtools(14), git(13), burp-repeater(7)

**Bypasses:** content-type(95), bypass(76), blind(68), whitelist(22), blacklist(19), bypassing(19), bypassed(14), host header(14), %0d%0a(14), bypasses(11), crlf(8), content type(7)

**Top approach patterns:**
- (2) resource exhaustion by sending excessively large responses in particular using gzip encoding
- (1) to check port we used as post value and the following response was received we received an error because the port of localhost was blocked
- (1) korprit was able to demonstrate this vulnerability by crafting specially formatted urls
- (1) summary server side request forgery ssrf vulnerability in the description by sending a specially crafted http request i can forcibly send a url request from ssi server
- (1) when sending the following http request access from the ssi server was logged on my server
- (1) hi i ve found ssrf vulnerability at description server side request forgery ssrf is a vulnerability that appears when an attacker has the ability to create requests from the vulnerable server
- (1) i found an issue which seems to be regression of the following issue
- (1) when modifying the http request that is sent an attacker can do server side request forgery

## sqli — 331 valid / 84 paid (25%) / median paid $1350

**Top techniques from ALL valid writeups:** second-order / stored / blind delivery(68), encoding / double-encode / null byte(61), header injection (Host / X-Forwarded / etc.)(52), admin / privileged-role context(51), WAF / sanitizer / filter bypass(40), Content-Type / body-format switch(37), XML / SOAP / SAML / XXE(33), public source-code / repo review(27), third-party data / paste / breach reuse(20), HTTP method / verb tampering(20), internal service / port / container(19), cache / CDN / unkeyed header(18)

**Tools:** browser(50), sqlmap(41), devtools(24), source-code-review(20), burp(15), curl(13), python(11), javascript-debugging(9), burp-repeater(3), burp-collaborator(1)

**Bypasses:** blind(113), time-based(47), content-type(42), bypass(27), backslash(17), time based(15), bypasses(6), bypassed(5), content type(3), normalization(3), second order(2), url encoded(2)

**Top approach patterns:**
- (3) korprit was able to demonstrate this vulnerability by crafting a specially formatted url
- (2) so i decided to sure that this endpoint vulnerable to sql injection or not i using sqlmap as you can see in my poc video
- (1) motivation i found a sql injection bug in drupal
- (1) i found sql injection in conc index php ccm system search users submit poc is below when user login as administrator the user open this link and update user s email address
- (1) and i think i can do various things i tested to work concrete5 on apache using ammps windows8
- (1) hi i noticed you are using a critically vulnerable version of wmpl by accessing attacker could find out is running wmpl version which is vulnerable to
- (1) however due to our previously vague bug bounty rules we decided to reward the maximum of since we were not previously clear that these were maximums
- (1) i haven t managed to inject something but i just want to make sure that this input is filtered

## path-traversal — 300 valid / 52 paid (17%) / median paid $1000

**Top techniques from ALL valid writeups:** public source-code / repo review(113), internal service / port / container(85), file upload / filename / extension(68), admin / privileged-role context(65), HTTP method / verb tampering(62), WAF / sanitizer / filter bypass(59), unauthenticated / removed-cookie test(43), encoding / double-encode / null byte(40), Content-Type / body-format switch(35), header injection (Host / X-Forwarded / etc.)(34), cache / CDN / unkeyed header(29), parser confusion / normalization(24)

**Tools:** curl(112), source-code-review(81), browser(35), git(16), devtools(13), python(13), burp(13), javascript-debugging(11), burp-repeater(4), zap(1)

**Bypasses:** content-type(61), bypass(45), url-encoded(17), normalization(15), normalize(14), transfer-encoding(11), chunked(8), normalized(8), allowlist(8), backslash(6), bypasses(6), bypassed(6)

**Top approach patterns:**
- (5) i used the burp to make a raw url and send it to server
- (5) an attacker could exploit this vulnerability by sending a crafted http request containing directory traversal character sequences to an affected device
- (4) description i discovered previously unidentified instance in network vulnerable to the cve poc we can disclose user sessions by quering sessions suggested fix updating to the latest version should fix the issue
- (3) supporting material references configuration i ve used to find this vulnerability kali linux nodejs v8 npm burpsuite wrap up i contacted the maintainer to let them know n i opened an issue in the related repository n impact this vulnerability allows malicious user to list file in the folder
- (3) summary i discovered a vulnerability read only path traversal cve at description a vulnerability in the web services interface of cisco adaptive security appliance asa software and cisco firepower threat defense ftd software could allow an unauthenticated remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system
- (2) i have tried to reproduce from within firefox and internet explorer without much luck however if you need it i will try to come up with a work around
- (2) i found out that was vulnerable to cve the ip has a ssl certificate pointing to curl kv output impact anyone can read any file present on the server
- (1) hey after reading egix s report and seeing your fix at i think the fixes are insufficient to stop lfi

## mfa-and-passwords — 159 valid / 29 paid (18%) / median paid $500

**Top techniques from ALL valid writeups:** fuzzing / wordlist brute force(51), intercept & replay request in Burp(31), admin / privileged-role context(21), encoding / double-encode / null byte(19), Content-Type / body-format switch(18), public source-code / repo review(15), header injection (Host / X-Forwarded / etc.)(14), two-account / cross-account replay(9), cache / CDN / unkeyed header(9), HTTP method / verb tampering(8), XML / SOAP / SAML / XXE(6), third-party data / paste / breach reuse(5)

**Tools:** burp-intruder(25), burp(24), source-code-review(15), browser(12), curl(6), python(6), devtools(4), sqlmap(2), beautifier(1), burp-repeater(1)

**Bypasses:** bypass(39), content-type(25), bypassed(14), blacklist(4), content type(3), bypassing(2), second order(2), out-of-band(1), transfer-encoding(1), chunked(1), blind(1), polyglot(1)

**Top approach patterns:**
- (2) by sending a very long password characters usually this problem is caused by a vulnerable password hashing implementation
- (1) it was enabled for over hours since i was told it didn t exist but i stumbled upon the link and then saw all my sms messages on a web page
- (1) i saw two authentication code text messages on my phone for the two fraudulent bitcoin purchases of and to max out the daily limit
- (1) i have found similar easy way to bruteforce invite codes but in different manner
- (1) invited you to make money with your car h1 another devastating thing i have found here is invite codes are already public in google which if an attacker uses he can ride with uber always for free with invites codes new account
- (1) i didn t used any of the invite codes
- (1) i also took a quick look at and noticed there is no reference to this coming up
- (1) description 2fa in short testing out your 2fa implementation i noticed that there is limited protection against brute forcing

## clickjacking — 153 valid / 11 paid (7%) / median paid $500

**Top techniques from ALL valid writeups:** HTTP method / verb tampering(14), DOM / HTML source inspection(13), XML / SOAP / SAML / XXE(12), public source-code / repo review(9), webhook / OAuth / SAML / integration abuse(6), two-account / cross-account replay(6), admin / privileged-role context(5), file upload / filename / extension(5), encoding / double-encode / null byte(4), subdomain / DNS / cert-transparency recon(3), cache / CDN / unkeyed header(2), JWT / token / base64 decode(2)

**Tools:** browser(10), source-code-review(9), devtools(7), javascript-debugging(2), curl(1), git(1)

**Bypasses:** unicode(4), bypasses(3), content-type(2), bypass(2), bypassed(1), blacklist(1)

**Top approach patterns:**
- (10) clickjacking user interface redress attack ui redress attack ui redressing is a malicious technique of tricking a web user into clicking on something different from what the user perceives they are clicking on thus potentially revealing confidential information or taking control of their computer while clicking on seemingly innocuous web pages
- (1) hi i found your site is vulnerable to clickjacking
- (1) i have set up a user agent switcher and tried to support my claim with regards to the mobile website
- (1) after clicking the victim will automatically post a tweet with content pwn3d
- (1) this isn t quite as bad as the previous vulnerability i found since it requires an additional step favoriting a tweet to exploit
- (1) i found that there is a form for submitting user information for applying for beta program
- (1) information like name email company following is html code i used to test it
- (1) i have found clickjacking vulnerability in your website you should set the frames to fix the issue

## crlf-injection — 115 valid / 19 paid (17%) / median paid $250

**Top techniques from ALL valid writeups:** internal service / port / container(31), encoding / double-encode / null byte(30), header injection (Host / X-Forwarded / etc.)(26), WAF / sanitizer / filter bypass(23), Content-Type / body-format switch(18), file upload / filename / extension(14), parser confusion / normalization(14), cache / CDN / unkeyed header(13), public source-code / repo review(13), admin / privileged-role context(11), HTTP method / verb tampering(10), subdomain / DNS / cert-transparency recon(8)

**Tools:** curl(32), browser(18), python(15), source-code-review(11), devtools(7), burp(4), git(4), javascript-debugging(3), burp-repeater(1), burp-intruder(1)

**Bypasses:** crlf(274), %0d%0a(116), bypass(34), host header(30), content-type(28), desync(15), header injection(11), bypassing(6), bypassed(5), transfer-encoding(5), whitelist(5), blind(5)

**Top approach patterns:**
- (2) limitations the test server is a minimal synthetic model built to isolate and prove the session tracking by resource behavior pattern we have not tested against and are not claiming to have compromised any specific real ip camera nvr or other rtsp server product
- (1) sp1d3rs was able to demonstrate this vulnerability by crafting a specially formatted url
- (1) poc i sent this post request to a test email post body the resulting response the referrer attritube is encoded and sent to the victims email
- (1) hey guys i found that the site is vulnerable to a crlf injection
- (1) in this case this is could be done by modifying an http request directed to the adding for example the following payload 0d 0aset cookie test2 test domain with the preceding payload an attacker is going to set on the victim s browser that is visiting the malicious url a new cookie with an arbitrary value
- (1) i recently discovered that we can add arbitery value in reset pass token and compromise the life time unlimitedly
- (1) okay so i decoded the value and changed year to instead of and it s all done miracle i got this page with different warning
- (1) the agent application was vulnerable to a response splitting attack when parsing line feed characters in a given url

## session — 112 valid / 18 paid (16%) / median paid $150

**Top techniques from ALL valid writeups:** unauthenticated / removed-cookie test(14), admin / privileged-role context(14),  HosT/absolute-URL reset poisoning(13), cache / CDN / unkeyed header(11), encoding / double-encode / null byte(10), second-order / stored / blind delivery(9), header injection (Host / X-Forwarded / etc.)(9), HTTP method / verb tampering(9), race / concurrency / timing(9), public source-code / repo review(8), two-account / cross-account replay(8), intercept & replay request in Burp(7)

**Tools:** browser(19), devtools(16), burp(9), source-code-review(7), curl(7), burp-repeater(3), python(3), zap(1), javascript-debugging(1), burp-intruder(1)

**Bypasses:** bypass(13), content-type(10), bypassing(4), bypasses(3), bypassed(2), whitelist(1)

**Top approach patterns:**
- (2) summary while conducting my researching i discovered that the application failure to invalidate session after password
- (1) hackerone fails to expire the session cookie from the server side even when the user logs off upon clicking sign out from the application
- (1) to reproduce this vulnerability open chrome and download edit this cookie ad don now open and log in now goto edit this cookie addon and click export all cookies by clicking this we get the cookie copied in clipboard
- (1) an attacker could exploit this issue by for example tricking a user into clicking on a link to a page with the following html code img src when the user visits the page the browser will send a request to www irccloud com over an unencrypted connection note the http instead of https containing the session cookie
- (1) as a result of this report we rethought how we handled password changes and we decided to invalidate all sessions on a password change reset to protect from this possible problem
- (1) hey i ve found a session management in help nextcloud com which can lead to session takeover
- (1) hi i don t know is it a valid vulnerability under your program but i found it
- (1) i have found a way to change the value of the cookie this error can be used to leave off the application to a particular user to log on again the attacker would have to cause the victim to visit a particular link

## request-smuggling — 97 valid / 30 paid (31%) / median paid $1800

**Top techniques from ALL valid writeups:** parser confusion / normalization(61), encoding / double-encode / null byte(46), cache / CDN / unkeyed header(39), JS bundle / source-map inspection(39), internal service / port / container(36), header injection (Host / X-Forwarded / etc.)(28), Content-Type / body-format switch(21), public source-code / repo review(17), parameter pollution / duplicate keys(17), intercept & replay request in Burp(15), race / concurrency / timing(11), subdomain / DNS / cert-transparency recon(11)

**Tools:** curl(19), browser(14), source-code-review(14), burp(12), burp-intruder(10), devtools(9), javascript-debugging(8), python(7), burp-collaborator(5), collaborator/oast(5)

**Bypasses:** chunked(163), transfer-encoding(151), desync(57), content-type(42), bypass(31), crlf(24), host header(15), %0d%0a(14), bypassing(11), header injection(8), transfer encoding(3), bypassed(3)

**Top approach patterns:**
- (2) in this poc i was able to massive redirect users to a domain under my control but other scenarios are also possible like the ones described here
- (1) so i found a http response splitting issue in your website
- (1) poc firefox after sending the request through firefox this query is saved in cache and using a small trick can be made to work it in another browser
- (1) these defects represent a security concern when httpd is participating in any chain of proxies or interacting with back end application servers either through mod proxy or using conventional cgi mechanisms
- (1) after adding to cart step there is no checking step
- (1) in starting from these past studies i studied apache nginx varnish source code i discovered that a lot of smuggling problems were still present found new ones based on overflows for the size attributes previous works were mostly based on doubling length information and expanded my works on golang nodejs pound haproxy jetty tomcat apache traffic server
- (1) if you ask my opinion this is one of the most problematic issue i found on these years
- (1) cve httpd apache http request parsing whitespace defects problems with cr ff vtab and others strange characeters in parsing http messages especially the space before colon problem

## subdomain-takeover — 72 valid / 12 paid (17%) / median paid $500

**Top techniques from ALL valid writeups:** subdomain / DNS / cert-transparency recon(56), cache / CDN / unkeyed header(7), public source-code / repo review(6), webhook / OAuth / SAML / integration abuse(4), admin / privileged-role context(3), two-account / cross-account replay(3), API docs / Swagger / introspection(3), file upload / filename / extension(3), OAST / DNS / HTTP callback proof(2), header injection (Host / X-Forwarded / etc.)(2), DOM / HTML source inspection(1), cloud metadata / IAM abuse(1)

**Tools:** source-code-review(4), curl(2), browser(2), shodan(1), burp(1)

**Bypasses:** host header(8), bypass(7), trailing dot(4), content-type(3)

**Top approach patterns:**
- (1) the researcher found a dns entry pointing to an unused ip address
- (1) hi i noticed that the following domain api legalrobot com was returning the following information f102881 from modulus io
- (1) in this case what i did was to create a new account on modulus and saw the following setup when i created my own application f102879 i tried adding the specific domain but it said it was already added somewhere
- (1) the problem was that i then tried with the wildcard legalrobot com and that actually worked f102878 which also made the page resolve my app f102877 you should not point subdomains to services you do not use yet
- (1) hey team i ve found a snapchat cdn domain here which had a test instance of fastly setup but did not remove the dns record when the service was cancelled
- (1) the researcher found a subdomain takeover on ws bimedb com
- (1) we removed the record because it was not needed any longer
- (1) but due to some problem the main domain help cloudup com see screenshot below png is showing ssl error maybe due to expired certificate i m not sure as i m just a started still have to learn many things

## deserialization — 69 valid / 20 paid (29%) / median paid $1500

**Top techniques from ALL valid writeups:** deserialization / gadget chain(34), public source-code / repo review(25), internal service / port / container(14), file upload / filename / extension(11), JWT / token / base64 decode(8), cache / CDN / unkeyed header(8), admin / privileged-role context(8), Content-Type / body-format switch(6), error message / stack trace probing(6), third-party data / paste / breach reuse(6), encoding / double-encode / null byte(6), HTTP method / verb tampering(6)

**Tools:** source-code-review(24), curl(12), python(7), git(4), burp-collaborator(2), collaborator/oast(2), browser(1), burp(1)

**Bypasses:** content-type(9), bypass(3), bypassing(2), type confusion(1)

**Top approach patterns:**
- (3) attached is a video detailing the poc generating the payload for generate the payload i used the tool ysoserial
- (2) sending the payload to a vulnerable server curl data binary payload k after sending the payload to the dod server the code was successfully executed and i received the dns query on my bind server as can be seen in the log record below
- (1) when parsing a gem posted to the api v1 gems endpoint the rubygems org application immediately calls gem package new body spec inside app models pusher rb
- (1) however yaml load is called directly when parsing the gem s checksum file in gem package read checksums
- (1) using classes accessible within the application i was able to turn this into a call to marshal load on attacker controlled data
- (1) from there i was able to use known marshal exploitation techniques to achieve code execution on the server i m omitting some details here for brevity so that i can submit this report right away
- (1) in this case as far as i have seen it is used for notifications
- (1) as far as i have seen the deserializer is only used to render notifications in render notifications as seen here the render notifications function is then used on the notifications template page as seen here there is no other place where the deserializer is used as far as i have seen

## dos — 66 valid / 18 paid (27%) / median paid $450

**Top techniques from ALL valid writeups:** internal service / port / container(14), public source-code / repo review(14), HTTP method / verb tampering(10), file upload / filename / extension(10), parameter pollution / duplicate keys(10), admin / privileged-role context(10), encoding / double-encode / null byte(9), Content-Type / body-format switch(8), header injection (Host / X-Forwarded / etc.)(6), WAF / sanitizer / filter bypass(6), second-order / stored / blind delivery(6), OAST / DNS / HTTP callback proof(5)

**Tools:** source-code-review(13), curl(7), browser(6), python(4), devtools(3), burp(2), burp-intruder(2), git(2), javascript-debugging(2), zap(2)

**Bypasses:** content-type(9), blind(5), backslash(4), unicode(2), chunked(2), crlf(2), blacklist(1), url encoded(1), bypass(1), transfer-encoding(1), lowercase(1), bypasses(1)

**Top approach patterns:**
- (1) steps to reproduce i ve created a script that can be run here against any rack based application by default it generates a request body with parts which in my testing was enough to cause github api to take between seconds to service the request once the request transfer had completed
- (1) f838206 but the api token can be added to that group through f838209 clicking on manage groups is possible to add this api token to the previously created group
- (1) so in my test i changed from testing to aaabc2
- (1) istead of the above setting i tested the app locally
- (1) as mentioned in another project to simulate a ldap server for users authentication i used a test server provided by the same author you can find attached
- (1) summary hello team while testing it was observed that on 3d cs money a dos is possible via specially crafted request using only single request from single machine on search bar
- (1) filed publicly my first gut reaction was that this had to be a problem with curl fnmatch as that has caused us grief in the past and on most platforms we use the native fnmatch now but not on windows iirc and this is a reported to happen on windows but i then built a test program and i made it crash in what seems like potential stack overflow due to recursive calls to wc statemach from within itself
- (1) i discovered this issue in the ftp functionality of the curl project as described in curl uses epsv mode as the default ftp file transfer method

## race-condition — 65 valid / 14 paid (22%) / median paid $520

**Top techniques from ALL valid writeups:** race / concurrency / timing(43), intercept & replay request in Burp(17), encoding / double-encode / null byte(14), public source-code / repo review(14), cache / CDN / unkeyed header(12), internal service / port / container(11), Content-Type / body-format switch(10), header injection (Host / X-Forwarded / etc.)(10), two-account / cross-account replay(7), admin / privileged-role context(7), subdomain / DNS / cert-transparency recon(6), file upload / filename / extension(6)

**Tools:** curl(16), burp(12), source-code-review(12), browser(10), burp-intruder(10), devtools(7), python(3), burp-collaborator(1), collaborator/oast(1), burp-repeater(1)

**Bypasses:** race condition(68), content-type(14), bypassing(7), bypass(5), bypassed(3), url-encode(1), blind(1)

**Top approach patterns:**
- (1) the researcher was able to find a misconfiguration in the captcha mechanism which allowed him to reuse any captcha and bypass the uniquness of the same
- (1) i tested it tonight and was able to authenticate two accounts on one invite for my test company test22 simply by clicking the accept button quickly in two separate browsers with two separately logged in users
- (1) for example i found the code dallas20
- (1) hi i want to report an issue that i have found on when a user wants to up vote or down vote a term he simply presses on the up or down button
- (1) each user can up vote or down vote a term only once but i have found that if a parallel threads do the process of up voting then multiple requests will be accepted
- (1) i discovered that the federalist api doesn t have rate limiting in place and executes any amount of request to the endpoint in parallel mode
- (1) this is possible because i found a way to confirm arbitrary emails
- (1) i tested that functionality and confirmed how it works

## account-takeover — 64 valid / 10 paid (16%) / median paid $1500

**Top techniques from ALL valid writeups:** subdomain / DNS / cert-transparency recon(9), admin / privileged-role context(9),  HosT/absolute-URL reset poisoning(7), employee / developer public info(7), Content-Type / body-format switch(6), encoding / double-encode / null byte(6), webhook / OAuth / SAML / integration abuse(5), file upload / filename / extension(5), XML / SOAP / SAML / XXE(5), header injection (Host / X-Forwarded / etc.)(4), HTTP method / verb tampering(4), two-account / cross-account replay(4)

**Tools:** browser(5), source-code-review(3), curl(3), devtools(2), burp(2), python(1), javascript-debugging(1), burp-collaborator(1), ffuf(1), collaborator/oast(1)

**Bypasses:** content-type(13), bypass(12), bypassing(2), whitelist(2), parameter pollution(2), blind(2), %00(1), blacklist(1), header injection(1)

**Top approach patterns:**
- (1) so i was able to claim the domain for my own host and thus can place content on this url
- (1) description i have noticed that there is no security check at changing password
- (1) hi summary i have found a design issue on the e mail change functionality offered by the accounts profile handler
- (1) i changed my email1 to email2 through profile
- (1) it was failed and when i used email2 its working
- (1) the researcher was able to pass verification to another account by finding confirmation data in response from the server
- (1) i was able to claim dmc support zendesk com
- (1) also attached is the apk of the malicious app i used as poc and for the video

## file-upload — 55 valid / 12 paid (22%) / median paid $750

**Top techniques from ALL valid writeups:** file upload / filename / extension(43), second-order / stored / blind delivery(10), JWT / token / base64 decode(6), HTTP method / verb tampering(6), WAF / sanitizer / filter bypass(6), Content-Type / body-format switch(6), internal service / port / container(6), encoding / double-encode / null byte(5), cloud metadata / IAM abuse(4), public source-code / repo review(4), header injection (Host / X-Forwarded / etc.)(4), two-account / cross-account replay(4)

**Tools:** browser(5), source-code-review(4), devtools(3), curl(3), decompiler(1), python(1), burp(1)

**Bypasses:** content-type(11), bypass(6), bypassed(4), open redirect(2), whitelist(2), bypassing(1)

**Top approach patterns:**
- (2) description i was able to identify unsafe upload endpoint on the poc go to the upload some test file
- (1) hi when a new driver is registering on uber they have to upload a variety of files proof of insurance id etc
- (1) i was able to access your account data f297519 f297520 those keys give me ability to not only access the files but also replace and delete them change different their settings
- (1) this is the first report we identified ourselves where we re expanding retesting to the community
- (1) when we identified this vulnerability we filed a ticket to our own bug bounty program instead of filing an internal ticket
- (1) this was possible by sending a specially crafted request to the attachments endpoint
- (1) i found an unrestricted file upload on which let me upload anything
- (1) i tested by uploading an executable visual studio community installer and a php file

## mobile — 49 valid / 14 paid (29%) / median paid $1000

**Top techniques from ALL valid writeups:** admin / privileged-role context(8), file upload / filename / extension(7), XML / SOAP / SAML / XXE(5), two-account / cross-account replay(4), webhook / OAuth / SAML / integration abuse(4), cache / CDN / unkeyed header(3), encoding / double-encode / null byte(3), unauthenticated / removed-cookie test(2), HTTP method / verb tampering(2), fuzzing / wordlist brute force(2), DOM / HTML source inspection(2), public source-code / repo review(2)

**Tools:** browser(5), devtools(2), source-code-review(2), javascript-debugging(1), zap(1)

**Bypasses:** bypass(5), bypassed(4), content-type(1), trailing dot(1), bypassing(1), normalization(1), normalized(1), unicode(1)

**Top approach patterns:**
- (1) i have already tried to logout from my twitter apps including from built in twitter apps for ios and then i already reboot the idevice too
- (1) so when testing i entered the random mobile number and twitter says that verification code sent to the mobile number and asking for the verification code i cant provide the code coz i entered the random number
- (1) hello i have recently found several critical vulnerabilities in odnoklassniki android application which is one of your projects thus i am reporting it here
- (1) you have been tricked u putextra conversation id u putextra mediatopic id u putextra dsc id user photo getactivity sendbroadcast u another vulnerability that i have found is unauthorized intent receipt in this certain case it is unauthorized notification message receipt
- (1) when logging in to an account on the website a user s account gets locked out after tries to prevent an attacker from brute forcing access to the account
- (1) these same restrictions do not apply to the mobile sign in endpoint a post request to which allows an attacker to brute force login of any user s account i have attempted logging into my account times with no restrictions
- (1) as an example i found a list of the most common passwords and added my own password somewhere in the list
- (1) products affected in ios affected is the latest version in android affected in brave latest version steps to reproduce i created a html code which would spoof address bar of brave browser bravespoof html in the attachments

## xxe — 42 valid / 9 paid (21%) / median paid $1000

**Top techniques from ALL valid writeups:** XML / SOAP / SAML / XXE(22), encoding / double-encode / null byte(12), Content-Type / body-format switch(8), file upload / filename / extension(8), header injection (Host / X-Forwarded / etc.)(8), admin / privileged-role context(6), internal service / port / container(6), second-order / stored / blind delivery(6), subdomain / DNS / cert-transparency recon(5), parser confusion / normalization(5), public source-code / repo review(5), JWT / token / base64 decode(4)

**Tools:** browser(7), source-code-review(5), python(4), devtools(4), burp(4), burp-collaborator(3), collaborator/oast(3), git(2), dnsdump(1), curl(1)

**Bypasses:** content-type(13), blind(10), bypass(8), out-of-band(2), bypassed(1), time-based(1)

**Top approach patterns:**
- (2) i was able to extract text files from the server and http responses by rendering them on my crew emblem
- (1) hi sir i am new hacker in hackerone platform i am glad to join paragonie bounty program i want to report a very critical bug that is i found dmarc missing for your domain paragonie com add dmarc record as soon as possible
- (1) many senders have a complex email environment with many systems sending email often including 3rd party service providers
- (1) dawgyg was able to exploit this vulnerability by crafting an xml request that revealed sensitive local system information
- (1) version i tested this against the latest stable source available a couple fo days ago may running weblate dev steps to reproduce i have included a live exploit testproject testcomponent en gb xlf that works with the hello data backing the demo website log in as a user that has permission to upload translation files
- (1) i ve identified an xxe vulnerability in the cloudhopper sxmp servlet on sms be vip twitter com which discloses local files to an external attacker and allows web requests to be sent
- (1) summary the project site audit function is vulnerable to xxe when parsing sitemap xml files
- (1) about one year after i started messing with the emblem editor i finally found a full ssrf and lfi

## oauth-oidc — 40 valid / 8 paid (20%) / median paid $900

**Top techniques from ALL valid writeups:** webhook / OAuth / SAML / integration abuse(15), admin / privileged-role context(11), internal service / port / container(9), public source-code / repo review(7), two-account / cross-account replay(6), redirect chain / Location header(5), second-order / stored / blind delivery(4), HTTP method / verb tampering(3), file upload / filename / extension(3), git history / exposed .git(3), WAF / sanitizer / filter bypass(3),  HosT/absolute-URL reset poisoning(3)

**Tools:** curl(9), source-code-review(7), python(4), git(3), browser(2), devtools(1)

**Bypasses:** bypass(10), bypasses(6), bypassing(4), blind(3), open redirect(2), content-type(2), bypassed(2), allowlist(2), %0d%0a(1)

**Top approach patterns:**
- (1) hi i noticed that the redirect uri used to redirect users to any location on the page passes in all data into a header location without any validation
- (1) hi i found that you are using a weak password policy
- (1) done ps the same occurs when you intercept no photo option ps2 i could not execute code through this but i thought it was a valid report because i tried to upload txt files in upload photo options and it was not allowed
- (1) i found a way to confirm arbitrary emails and after confirming arbitrary email in myshopify com user is able to integrate with other shopify store that shares the same email address by setting a master password for all of the stores if the owner hasn t integrated before effectively taking over every shopify stores by knowing just the owner s email address
- (1) what happened in was i was too excited and didn t take a step further to try to takeover merchant s account even they have sso setup and after reading the comment an important mitigating factor was that this bug only affected user accounts which had not yet adopted our single login system
- (1) users sso provider accounts remain secure and after that cache period of up to hour any user attempting to sign in with sso will be required to reauthorize courier s oauth application before logging in successfully again
- (1) there is nothing stopping a rogue application from hijacking your deep link by also registering to the same scheme and then obtaining access to the data your link contains
- (1) i created a malicious android app which is able to intercept the authorization code see poc

## web-cache — 30 valid / 9 paid (30%) / median paid $500

**Top techniques from ALL valid writeups:** cache / CDN / unkeyed header(21), header injection (Host / X-Forwarded / etc.)(13), encoding / double-encode / null byte(11), JS bundle / source-map inspection(6), XML / SOAP / SAML / XXE(6), intercept & replay request in Burp(4), subdomain / DNS / cert-transparency recon(4), Content-Type / body-format switch(4), two-account / cross-account replay(4), second-order / stored / blind delivery(3), HTTP method / verb tampering(3), redirect chain / Location header(2)

**Tools:** browser(7), devtools(5), burp(3), curl(3), source-code-review(2), burp-repeater(2), python(1), burp-intruder(1)

**Bypasses:** %00(6091), content-type(9), backslash(4), host header(3), transfer-encoding(3), chunked(3), null byte(3), open redirect(2), bypass(2), url-encoded(1), content type(1)

**Top approach patterns:**
- (2) i was able to impact the core functionality by using a custom http
- (1) i noticed if i made a request to your website intercepted the request and added the header
- (1) well after that i tried going to hackerone com and i was instantly redirected to evil com
- (1) i discovered an issue when by using single specially crafted url it was possible to cause service inaccessibility for all users who will visit the site as result of infinite redirect loop
- (1) to ensure that problem exists and site inaccessible not only for me i checked it from the different ip addresses proxies tor
- (1) we can see that the value of the applicationuri url prefix is bytes long which is close to the maximum number of bytes in the url i was able to send to the board greenhouse io server before receiving err connection closed
- (1) as an example try to visit the following url where i added token onto the applicationuri above i have omitted the proof of concept that this exploit bricks a live job board from start to finish since it has already been proven in the previous report that we can cause a denial of service by changing the applicationuri in the js file
- (1) in the above request i have added x forwarded host header

## prototype-pollution — 14 valid / 0 paid (0%) / median paid $0

**Top techniques from ALL valid writeups:** public source-code / repo review(9), HTTP method / verb tampering(2), deserialization / gadget chain(1), third-party data / paste / breach reuse(1), file upload / filename / extension(1), mass assignment / extra request fields(1)

**Tools:** javascript-debugging(12), source-code-review(3)

**Bypasses:** bypass(1), bypassed(1)

**Top approach patterns:**
- (1) module stats weekly downloads vulnerability vulnerability description i tested the deepcopy and deepextend functions

## graphql — 13 valid / 2 paid (15%) / median paid $25000

**Top techniques from ALL valid writeups:** API docs / Swagger / introspection(4), public source-code / repo review(3), admin / privileged-role context(3), race / concurrency / timing(3), unauthenticated / removed-cookie test(2), HTTP method / verb tampering(2), mass assignment / extra request fields(1), internal service / port / container(1), third-party data / paste / breach reuse(1), employee / developer public info(1), intercept & replay request in Burp(1), Content-Type / body-format switch(1)

**Tools:** source-code-review(1), python(1), burp(1), burp-repeater(1), browser(1)

**Bypasses:** race condition(2), bypass(1), bypassing(1), content-type(1), time based(1)

**Top approach patterns:**
- (1) when clicking on change password after supplying values for current password password and confirm password user is directed to sign in page to log in again with changed password
- (1) i ve found a misconfiguration in your graphql api on the endpoint in which an attacker is able to run a graphql interospection query to fetch schemas types fields available query operations after running interospection query on the graphql api endpoint an attacker is able to list all type of available api calls so he ll be able to perform unauthorised api calls due to this misconfiguration
- (1) impact an attacker can exploit this vulnerability to cause a denial of service dos by sending a single graphql request with multiple aliases of the expensive mutation

## ssti — 7 valid / 1 paid (14%) / median paid $2300

**Top techniques from ALL valid writeups:** admin / privileged-role context(1), internal service / port / container(1), template injection (SSTI)(1)

**Tools:** 

**Bypasses:** 

**Top approach patterns:**
- (1) the researcher found a local file inclusion vulnerability this could be exploited by using twig templates available on the system
- (1) i found template injection in via the mail input

## llm-ai — 5 valid / 0 paid (0%) / median paid $0

**Top techniques from ALL valid writeups:** parser confusion / normalization(3), public source-code / repo review(3), encoding / double-encode / null byte(2), two-account / cross-account replay(1), HTTP method / verb tampering(1), OAST / DNS / HTTP callback proof(1), cache / CDN / unkeyed header(1), WAF / sanitizer / filter bypass(1), API docs / Swagger / introspection(1), public bucket / storage exposure(1), intercept & replay request in Burp(1), subdomain / DNS / cert-transparency recon(1)

**Tools:** source-code-review(2), python(1), curl(1), burp(1)

**Bypasses:** normalization(5), unicode(2), normalized(2), normalizes(1), bypass(1)

**Top approach patterns:**
- (1) i have identified a vulnerability in the hai ai chat system following an invitation by hackerone for a spot check
- (1) specifically i found that by encoding a message into ascii format and then asking hai to decode and respond the ai could be manipulated into parroting the exact content of the decoded message irrespective of its appropriateness or alignment with its normal behavior
- (1) you can paste the report above into a website like this to see the hidden payload or we used the prompt injection payload times just to make sure it was effective
- (1) verify that the arjunc77 htmlstreamparser repository is no longer active or has been deleted as i was able to register the username arjunc77
