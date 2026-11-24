# Recon command recipes

All commands assume written authorization and the program's rate limit. Run passive sources first.

```sh
# Passive: archives and certificate transparency
subfinder -d target.com -o recon/subdomains.txt
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
waybackurls target.com | sort -u > recon/wayback.txt
gau target.com | sort -u >> recon/wayback.txt

# Liveness + soft-404 control
httpx -l recon/subdomains.txt -status-code -content-length -title -o recon/live.txt
for H in $(cat recon/live-hosts.txt); do
  for P in /zzz-nope-12345 /qqq-other-98765; do
    curl -sk -m 12 -o /tmp/b -w "$H $P %{http_code} %{size_download} " "https://$H$P"
    shasum /tmp/b | cut -c1-12
  done
done

# JS collection and analysis
katana -u https://target -jc -o recon/js_urls.txt
grep -aoE 'https?://[^"\' ]+' bundle.js | sort -u
# sourcemap: check for sourceMappingURL, then extract sourcesContent

# Fingerprint (headers AND body, follow redirects)
curl -sSL -m 12 -D - -o /tmp/body https://target | tr -d '\r'
grep -aoE '__NEXT_DATA__|/_next/|VIEWSTATE|rO0[AB]|laravel_session|Ignition|Telescope|/actuator|swagger|\.js\.map' /tmp/body | sort -u
```

## Field notes (from authorized sessions)

- A 738-host passive list collapsed to 6 meaningful live hosts. **Prune before probing.**
- Third-party hosted pages on in-scope hostnames are out of scope until confirmed.
- Staging/k8s host families often share a single misconfiguration — record the family, not just the host.
- A full 403 header/path/method pass that stays 403 is a logged negative. Record the matrix and move on.
- GraphQL introspection may be disabled while the schema is still reconstructable from validation errors (`__typename` often works).
- Two test accounts unlock entire classes; without them mark IDOR/authz units blocked.
