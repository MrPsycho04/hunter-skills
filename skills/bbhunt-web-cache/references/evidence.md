# Evidence appendix — Web Cache Poisoning and Deception

Mined from all **30 valid disclosed reports** for this class (9 paid, 30% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| cache / CDN / unkeyed header | 21 |
| header injection (Host / X-Forwarded / etc.) | 13 |
| encoding / double-encode / null byte | 11 |
| JS bundle / source-map inspection | 6 |
| XML / SOAP / SAML / XXE | 6 |
| intercept & replay request in Burp | 4 |
| subdomain / DNS / cert-transparency recon | 4 |
| Content-Type / body-format switch | 4 |
| two-account / cross-account replay | 4 |
| second-order / stored / blind delivery | 3 |
| HTTP method / verb tampering | 3 |
| redirect chain / Location header | 2 |
| webhook / OAuth / SAML / integration abuse | 2 |
| internal service / port / container | 2 |
| public source-code / repo review | 2 |
| error message / stack trace probing | 2 |
| response diff / status / length comparison | 2 |
| DOM / HTML source inspection | 1 |
| JWT / token / base64 decode | 1 |
| OAST / DNS / HTTP callback proof | 1 |
| admin / privileged-role context | 1 |
| file upload / filename / extension | 1 |
| replay / modify a captured request | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 7 |
| devtools | 5 |
| burp | 3 |
| curl | 3 |
| source-code-review | 2 |
| burp-repeater | 2 |
| python | 1 |
| burp-intruder | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| %00 | 6091 |
| content-type | 9 |
| backslash | 4 |
| host header | 3 |
| transfer-encoding | 3 |
| chunked | 3 |
| null byte | 3 |
| open redirect | 2 |
| bypass | 2 |
| url-encoded | 1 |
| content type | 1 |

## Impact language

| Item | Count |
|---|---:|
| token | 12 |
| localhost | 2 |
| sensitive information | 2 |
| admin | 1 |
| unauthorized | 1 |
| api key | 1 |
| financial | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| token | 1 |
| xyzxyz | 1 |
| yeettest | 1 |
| postrequesttriggeredfirewall.png | 1 |
| cachebuster | 1 |
| dontpoisoneveryone | 1 |

## Recurring approach patterns

- **2×** i was able to impact the core functionality by using a custom http
  - e.g. I was able to impact the core functionality by using a custom HTTP.
- **1×** i noticed if i made a request to your website intercepted the request and added the header
  - e.g. I noticed if I made a request to your website, intercepted the request, and added the header...
- **1×** well after that i tried going to hackerone com and i was instantly redirected to evil com
  - e.g. Well, after that, I tried going to hackerone.com and I was instantly redirected to evil.com.
- **1×** i discovered an issue when by using single specially crafted url it was possible to cause service inaccessibility for all users who will visit the site as result of infinite redirect loop
  - e.g. I discovered an issue, when by using single specially crafted URL, it was possible to cause service inaccessibility for all users who will visit the site, as result of infinite redirect loop.
- **1×** to ensure that problem exists and site inaccessible not only for me i checked it from the different ip addresses proxies tor
  - e.g. To ensure that problem exists, and site inaccessible not only for me, i checked it from the different IP addresses/proxies/Tor.
- **1×** we can see that the value of the applicationuri url prefix is bytes long which is close to the maximum number of bytes in the url i was able to send to the board greenhouse io server before receiving err connection closed
  - e.g. We can see that the value of the `applicationURI` URL prefix is 6155 bytes long, which is close to the maximum number of bytes in the URL I was able to send to the `board.greenhouse.io` server, before receiving `ERR_CONNECTION_CLOSED`.
- **1×** as an example try to visit the following url where i added token onto the applicationuri above i have omitted the proof of concept that this exploit bricks a live job board from start to finish since it has already been proven in the previous report that we can cause a denial of service by changing the applicationuri in the js file
  - e.g. As an example, try to visit the following URL, where I added `&token=1234567` onto the `applicationURI` above: I have omitted the proof of concept that this exploit bricks a live job board from start to finish, since it has already been proven in the previous report that we can cause a denial of ser
- **1×** in the above request i have added x forwarded host header
  - e.g. In the above request I have added X-Forwarded-Host header.
- **1×** below is what i added to my config
  - e.g. Below is what I added to my config.
- **1×** summary i found the problem of cache poisoning in www acronis com
  - e.g. ## Summary I found the problem of cache poisoning in www.acronis.com.
- **1×** in this report the researcher discovered that there was a cache poisoning weakness on updates rockstargames com due to an unkeyed header trailer
  - e.g. In this report, the researcher discovered that there was a cache poisoning weakness on `updates.rockstargames.com` due to an unkeyed header, `trailer`.
- **1×** by sending this header an attacker could cause the cache to save a malformed response with status code
  - e.g. By sending this header, an attacker could cause the cache to save a malformed response with status code 400.
- **1×** i am testing websites for possible web cache deception vulnerabilities you can find more about it here and i discovered that shopify com is vulnerable
  - e.g. <█████████> <████> I am testing websites for possible Web Cache Deception vulnerabilities (you can find more about it [here]( and I discovered that `shopify.com` is vulnerable.
- **1×** i discovered that by applying path confusion followed by a random file name and css it is possible for an attacker to leak authenticated user s personal information
  - e.g. I discovered that by applying path confusion followed by a random file name and `.css` it is possible for an attacker to leak authenticated user's personal information.
- **1×** not implemented at i was able to impact core functionality by using an invalid custom http header to replace the javascript file from with message not implemented
  - e.g. 501 Not Implemented** At I was able to impact core functionality by using an invalid custom HTTP header to replace the JavaScript file from with message '501 Not Implemented'.
- **1×** response supporting material references f1744429 crash501notimplemented png f1744430 firewalltriggeredwithcachepoison png f1744431 postrequesttriggeredfirewall png note i ve added in the user agent header to help with problem tracking
  - e.g. : Response : ## Supporting Material/References: - F1744429: Crash501NotImplemented.png - F1744430: FirewallTriggeredWithCachePoison.png - F1744431: PostRequestTriggeredFirewall.png ==Note: I've added in the User-Agent header to help with problem tracking.
- **1×** also before doing any testing you have to add a cache buster query parameter to the end of the url to prevent dos on all users using the website
  - e.g. Also, before doing any testing, you have to add a cache buster query parameter to the end of the URL to prevent DoS on all users using the website.
- **1×** i believe the regex used to parse the url is the cause
  - e.g. I believe the regex used to parse the url is the cause.
- **1×** i haven t used them and luckily they won t be in the cache yet
  - e.g. I haven't used them and luckily they won't be in the cache yet.
- **1×** impact an attacker is able to manipulate the caching system to its avantage by sending a crafted link which can trick victims to unintentionally link a spoofed amazon product to their linkpop accounts
  - e.g. ## Impact An attacker is able to manipulate the caching system to its avantage by sending a crafted link which can trick victims to unintentionally link a spoofed Amazon product to their Linkpop accounts.
- **1×** however we noticed that the x http method override head header is honored in the same way
  - e.g. However, we noticed that the `X-HTTP-Method-Override: HEAD`header is honored in the same way.

## Case studies (full excerpts)

### 1695604 — DoS Vulnerability via Cache Poisoning on cdn.shopify.com and shopify-assets.shopifycdn.com
Shopify · $3800 · medium · https://hackerone.com/reports/1695604

## Summary: There's a web cache poisoning vulnerability on cdn.shopify.com that allows the attacker to block access to any file hosted on the website. This vulnerability exists as the cache server deals with the backslash as a frontslash. However, the original server returns a 404 error when a backslash exists in the URL So, according to the caching server, these two URLs are the same However, the second one will return 404 from the original server So, when an attacker sends a request with replacing the slashes with backslashes for a certain file, the server will return *404 Not Found* error page, and this error will be saved into the cache and any upcoming requests to this file will return *404 Not Found* error. This scenario could be exploited to cause DoS on nearly every Shopify website as all the javascript and static files used by Shopify websites are hosted on cdn.shopify.com. ## Steps To Reproduce: 1. Open any file hosted on cdn.shopify.com (ex: and intercept the request using Burp Suite. which will look like this: 2. In order to make this request return *404 Not Found*, we will replace the slashes in the url with backslashes 3. Also, before doing any testing, you have to add a cache buster query parameter to the end of the URL to prevent DoS on all users using the website. (i.e. Add ?cachebuster={random-value} to the end of the URL). Now the new request will be: 4. Send

### 977851 — Cache poisoning via X-Forwarded-Host in www.shopify.com/partners/blog
Shopify · $1000 · low · https://hackerone.com/reports/977851

Hello, run in loop requests with - after some time You will notice in response {F981839} now remove - there still be our url: {F981841} i've logged to my VPS to verify this bug and downloaded poisoned page ( , it's contains links to collabolator: {F981844} {F981845} Looks like there is no URL keys so i stopped testing cause i'm breaking site functionally, but it was be worth to check if we can poison or try use other headers, if i get permission i can try other vectors on a older article to prevent distributing users. ## Impact poisoning links, eg. FB share button:

### 1271944 — Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage
Shopify · $800 · low · https://hackerone.com/reports/1271944

# Shopify.com Web Cache Deception Vulnerability **Matteo Golinelli, July 21, 2021**. <█████████> <████> I am testing websites for possible Web Cache Deception vulnerabilities (you can find more about it [here]( and I discovered that `shopify.com` is vulnerable. Web cache deception (WCD) is an attack where an attacker tricks a caching proxy into erroneously storing private information transmitted over the Internet and subsequently gains unauthorized access to that cached data. This vulnerability allows a potential attacker to **steal personal** (and potentially *sensitive*) **information** of users of a website with a simple social engineering attack. The victim is only required to open a link in a browser on which they are authenticated on the given website to have their information mistakenly stored by the cache server and become accessible to the attacker. To confuse the cache server, I am using multiple path confusion techniques and by appending to the URL a random string followed by the extension *.css*. I discovered that by applying path confusion followed by a random file name and `.css` it is possible for an attacker to leak authenticated user's personal information. Using the slash character (`/`), the exploit URL can be formed as follows: - ` This URL will be interpreted as a CSS file from the cache server, resulting in the web page being cached (with the personal info

### 1848940 — URL Path Manipulation Enables Cache Poisoning of Amazon Affiliate Products in Shopify Linkpop
Shopify · $500 · low · https://hackerone.com/reports/1848940

# Summary The fix in report ████████ seems to prevent correctly an attacker from redirecting the request to another domain which was the main issue, however, there is still a way for that attacker to "poison" the cache usin the Amazon domain. I believe the regex used to parse the url is the cause. # Description If an attacker uses a crafted link such as anyone who will then try to use the "victim" product link will be shown the attacker controlled product. This way works even better because when you click the link button on the victim's page, it will even redirect to the attacker's product. # Steps to Reproduce 1. Have two Amazon products ID in hands (which haven't been cached yet) 1.1. Attacker Product ID: `██████` ( 1.2. Victim Product ID: `████` ( 2. In your attacker's Linkpop account, add a new Amazon product using the following crafted link ` and make sure to replace the placholders 2.1. Based on the ID's in step \#1, you could use the following link ` 3. Now, in the victim's Linkpop account, try to add the following product which is the "victim" product ID from step \#1. At that point you should be faced with the attacker's product (███) instead of the victim's product (███s). # Notes You can test the POC with the IDs I've provided. I haven't used them and luckily they won't be in the cache yet. If they are, you should notice it when adding the product as it will resolve 

### 1530066 — Web Cache Deception vulnerability on algolia.com leads to personal information leakage
Algolia · $400 · medium · https://hackerone.com/reports/1530066

A web cache deception(WCD) was found on our main website (algolia.com). An attacker could trick a caching proxy into storing private information transmitted over the internet from authenticated user. To do so, attacker would use simple social engineering where the victim is only required to open a link in a browser while being authenticated on the website. The attacker could then access the cached data, which can include personal and sensitive information of the victim. The exploit URL was formed by using a randomly named css file.

### 1219038 — Cache Poisoning DoS on updates.rockstargames.com
Rockstar Games · no bounty (valid finding) · medium · https://hackerone.com/reports/1219038

In this report, the researcher discovered that there was a cache poisoning weakness on `updates.rockstargames.com` due to an unkeyed header, `trailer`. By sending this header, an attacker could cause the cache to save a malformed response with status code 400. An example of such a request, as provided by the researcher: To resolve this issue, our team worked together with our CDN provider. The host no longer returns/saves a 400-code response when this header is sent in a request, and legitimate users can no longer be denied access to this content. For more details about the vulnerability, check out:

### 1976449 — DOS via cache poisoning on [developer.mozilla.org]
Mozilla · no bounty (valid finding) · low · https://hackerone.com/reports/1976449

## Summary: Hello, after some research it appears that it is possible for an attacker to perform a DOS attack on the page for an indefinite period. This is possible by adding an header and a value causing an error on the back-end side (error 404), the bad configuration of the cache makes it possible to save the response there and to serve it to users visiting the page, making the page completely inaccessible for an indefinite period. No information about the caching period is available in the response, but it is anyway possible to reinterpret the manipulation indefinitely. For obvious reasons I performed my tests using a cache-buster - adding a URL parameter as we will see in the POC - so as not to affect the user experience. ## Steps To Reproduce: 1. Pass your HTTP requests through your preferred proxy 2. Go to : then - in your proxy - send the request to your repeater 3. Add the parameter of your choice to the URL, it will serve as a cache-buster and will not "poison" the site visited by users. In other words, the DOS will only be effective on the URL containing your parameter, you probably know this but let me clarify: this is very important in order not to damage the services. 4. Add the following header : The request ready to send ( ) being my cache-buster : {F2339007} Once the request has been sent, the response will - as expected - contain a 404 error. Open another brows

## Field playbook (unedited)

### quick

- Identify cache layers, keys, and TTLs from headers and behavior.
- Find unkeyed inputs: X-Forwarded-Host, X-Host, X-Original-URL, cookies, headers reflected in responses.
- Test cache deception with static extensions on authenticated routes.
- Check normalization mismatches between cache and origin.

### payloads

- `X-Forwarded-Host: evil.com` `X-Host: evil.com` `X-Forwarded-Scheme: http`
- `/account/profile.css` `/account/profile%2ecss` `/account/profile;.css`
- Cache buster -> `?cb=123` then poison the canonical URL

### bypass

- Use unkeyed headers that the origin reflects into redirects or HTML.
- Exploit path normalization: `/x/..%2faccount`.
- Poison only your own cache key, then request the victim URL.

### surface

- any CDN/proxy path
- static extensions
- X-Forwarded-*
- Host
- cookies

### tools

- Burp
- Web Cache Vulnerability Scanner
- Param Miner

### chain

- Cache poisoning -> stored XSS.
- Cache deception -> PII theft.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class web-cache
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class web-cache --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
