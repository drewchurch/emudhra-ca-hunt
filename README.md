# Hunting the eMudhra Intermediate CA Compromise in Splunk

Searches, an IOC lookup and test data for finding certificates from the eight compromised eMudhra intermediate CAs in your Splunk network data. These are the companion notes to my blog post on the subject.

> **Disclaimer:** This is a personal project, shared as-is. It isn't an official Splunk or Cisco product, it comes with no warranty or support, and the views here are my own. Test everything on a non-production instance before you rely on it.

On 17 October 2026, a researcher who signs their work as Wayne reported that the private keys of eight eMudhra intermediate CAs (`EM {DV,OV,EV} TLS CA - G3B/G3C` and `EM OV CS CA - G3B/G3C`) could be recovered from the certificates themselves. [Dennis Jackson](https://dennis-jackson.uk/) of Mozilla confirmed it independently, opened [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449), and published the details at [we-have-a-problem.com](https://we-have-a-problem.com). Thanks to both of them. Three facts from that bug drive everything here:

- The keys were weak from the day they were made, in a key ceremony on 30 April 2025. Hunt back that far if you can.
- eMudhra says these intermediates never issued a customer certificate, so there's no legitimate traffic to filter out. (`EM DV TLS CA - G3C` may be the exception.)
- A forger picks the certificate's issue date, so an old date doesn't make a hit safe.

## What's in Here

| Path | What it is | Where it goes |
|---|---|---|
| [`emudhra_hunt/`](emudhra_hunt/) | A tiny Splunk app with the IOC lookup ([`emudhra_compromised_ca.csv`](emudhra_hunt/lookups/emudhra_compromised_ca.csv)) and its lookup definition | Any search head. Copy it to `$SPLUNK_HOME/etc/apps/`, or just upload the CSV as a lookup with a definition of the same name. |
| [`test-data/*.json`](test-data/) | Sample events in four formats: Corelight `ssl` and `x509`, Splunk Stream `stream:tcp`, and OCSF Network Activity | A **test** instance, to prove the searches fire before you trust a zero |
| [`test-data/emudhra_hunt_testdata/`](test-data/emudhra_hunt_testdata/) | Parsing, tags and field aliases for the sample events | A **test** instance only. It reuses the Corelight and Stream sourcetype names, so don't install it alongside those add-ons. |

The searches need the CIM add-on (`Splunk_SA_CIM`), with your certificate data in the Certificates data model.

## The Main Search

This finds every certificate issued by one of the eight CAs in the Certificates data model. Every such certificate has to name the CA as its issuer, or it won't chain, so matching the issuer is all it takes:

```spl
| tstats summariesonly=false fillnull_value="unknown" count min(_time) as firstTime max(_time) as lastTime values(All_Certificates.src) as src
  from datamodel=Certificates.All_Certificates
  where All_Certificates.SSL.ssl_issuer IN ("*EM DV TLS CA - G3*", "*EM OV TLS CA - G3*", "*EM EV TLS CA - G3*", "*EM OV CS CA - G3*")
  by All_Certificates.dest All_Certificates.SSL.ssl_subject_common_name All_Certificates.SSL.ssl_issuer All_Certificates.SSL.ssl_start_time sourcetype
| rename All_Certificates.SSL.* as *, All_Certificates.* as *
| rex field=ssl_issuer "CN\s*=\s*(?<issuer_cn>EM (DV|OV|EV) TLS CA - G3[BC]|EM OV CS CA - G3[BC])\s*(,|$)"
| where isnotnull(issuer_cn)
| eval cert_issued=coalesce(tonumber(ssl_start_time), strptime(ssl_start_time, "%b %d %H:%M:%S %Y %Z")),
       verdict=if(match(ssl_subject_common_name, "we-have-a-problem\.com$"), "test site", "investigate")
| eval firstTime=strftime(firstTime, "%F %T"), lastTime=strftime(lastTime, "%F %T"), cert_issued=strftime(cert_issued, "%F")
| table verdict ssl_subject_common_name issuer_cn cert_issued dest src count firstTime lastTime sourcetype
```

Every hit that isn't the test site (`*.we-have-a-problem.com`) is worth investigating, whatever its date. Keep `fillnull_value`: without it, `tstats` drops rows with an empty `by` field, and Zeek leaves some empty. On an accelerated data model, switch to `summariesonly=true`; on an unaccelerated one, run it a month at a time.

### Without `tstats` or CIM

If you'd rather skip `tstats` and the data model, and you have Splunk Stream, there's a simpler route. Every Stream TLS event already carries the issuer, the subject, the validity dates and both IP addresses, so a plain search does the job. No data model required:

```spl
index=<your_stream_index> sourcetype="stream:tcp" ("EM DV TLS CA" OR "EM OV TLS CA" OR "EM EV TLS CA" OR "EM OV CS CA")
| rex field=ssl_issuer "CN\s*=\s*(?<issuer_cn>EM (DV|OV|EV) TLS CA - G3[BC]|EM OV CS CA - G3[BC])\s*(,|$)"
| where isnotnull(issuer_cn)
| eval verdict=if(match(ssl_subject, "we-have-a-problem\.com$"), "test site", "investigate")
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as clients values(ssl_server_name) as sni
        by verdict ssl_subject issuer_cn ssl_validity_start dest_ip
| convert ctime(firstTime) ctime(lastTime)
```

Swap in the index your Stream data lives in. The quoted phrases let Splunk skip every event that doesn't mention one of these CAs before it does any real work, so it's cheap to run over a long time range. It's slower than `tstats` on an accelerated data model, but you can read it top to bottom.

To find every client that talked to a server that presented one of these certs, add `| outputlookup emudhra_cert_hits.csv` to the search above and then run:

```spl
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports
  from datamodel=Network_Traffic.All_Traffic
  where [| inputlookup emudhra_cert_hits.csv | where dest!="unknown" | dedup dest | fields dest | rename dest as All_Traffic.dest | format]
  by All_Traffic.src All_Traffic.dest
| `drop_dm_object_name("All_Traffic")`
```

Treat that as a list to check, not a list of victims. An on-path attacker may keep the real server's address.

## Which Data Sources Can See It?

Rows marked ✅ I checked against known-good sample events. The rest are from vendor docs.

| Source | Sourcetype | Issuer / subject | Chain or hashes | Serial | Gotchas |
|---|---|---|---|---|---|
| ✅ Zeek / Corelight `ssl.log` | `corelight_ssl`, `bro:ssl:json` | `issuer`, `subject` (`CN=..,O=..,C=..`) | `cert_chain_fps` (SHA-256) on Zeek 4.2+; `cert_chain_fuids` before that | — | Zeek 4.2+ leaves `subject`/`issuer` out of ssl.log; `redef SSL::log_include_server_certificate_subject_issuer = T;` brings them back. `established=true` means the handshake finished: the client trusted the chain *or isn't checking*. |
| ✅ Zeek / Corelight `x509.log` | `corelight_x509` | `certificate.issuer`, `certificate.subject` | Every cert in the chain, `fingerprint` (SHA-256 by default) | hex | The best single source. `basic_constraints.ca` separates CAs from leaves. Each cert is logged once a day, so don't count on it for volume. |
| ✅ Splunk Stream | `stream:tcp` (`app=ssl`) | `ssl_issuer`, `ssl_subject` | **Leaf only**: `ssl_cert_sha1/sha256/md5` | **decimal** `ssl_serialnumber` | Intermediate hashes will never match here, so match on the issuer. Validity is a string like `Oct 20 02:22:41 2026 GMT`. |
| Suricata EVE | `suricata` (`event_type=tls`) | `tls.issuerdn`, `tls.subject` | `tls.fingerprint` (leaf SHA-1, colon hex); `tls.chain` is base64 certificates, not hashes | colon hex | `fingerprint` and `serial` need extended TLS logging, and `chain` must be added as a custom field. Strip colons before matching. |
| Palo Alto decryption log | `pan:decryption` | `issuer_cn`, `root_cn`, chain status | Cert fingerprint and serial | hex | PAN-OS 10.0+. It logs No Decrypt sessions too, but only failed handshakes by default; turn on successful-handshake logging. Undecrypted TLS 1.3 has no cert details. |
| Cisco Secure Firewall | `cisco:sfw:estreamer` (Cisco Security Cloud app) | — | `SSL_CertFingerprint` (leaf SHA-1, lowercase) | — | ESCU's *Cisco Secure Firewall - Blacklisted SSL Certificate Fingerprint* already matches this field against a lookup. Older eNcore installs use `cisco:estreamer:data`. |
| Zscaler ZIA web | `zscalernss-web` | No issuer field | No | — | You get the proxy's own verdicts instead: `srvocspresult`, `srvcertchainvalpass`, `is_ssluntrustedca`. The proxy's trust store decides for everyone behind it, so test the proxy itself. |
| ✅ OCSF Network / HTTP Activity | `4001` / `4002`, any producer | `tls.certificate.issuer`, `.subject` | `tls.certificate.fingerprints{}`; `tls.certificate_chain{}` holds the issuers' **serial numbers** | string | `tls` is optional. AWS Security Lake 4001 events come from VPC Flow Logs and have no `tls` object at all. Times are in milliseconds. |

That boils down to two rules:

1. **Match the leaf's issuer name.** It works everywhere, and it's reliable: a leaf from `EM DV TLS CA - G3B` has to name it as the issuer, or it won't chain.
2. **Match the intermediates by hash or serial where the chain is logged** (Zeek x509, `cert_chain_fps`, OCSF `certificate_chain`). It's a good second signal, and it shows you which path the client took (the emSign root or the Sectigo cross-sign).

## Normalization Traps

- **DN formats.** Zeek writes `CN=R3,O=Let's Encrypt,C=US`. Stream writes either `C = US, O = Amazon, ..., CN = Amazon` (spaces around `=`) or `C=US,O="VeriSign, Inc.",...` (reversed order, quoted commas). `CN\s*=\s*` handles all three.
- **Serials.** Zeek and OCSF use hex. Suricata uses colon-separated hex. Stream uses decimal, and these CAs' serials are 36–39 digits, far too long for SPL to convert to hex without losing precision. The lookup carries both `serial_norm` (hex, leading zeros stripped) and `serial_dec`.
- **Hash case.** Stream is uppercase, Zeek is lowercase, Suricata uses colons. Search terms and `tstats` don't care about case, but `lookup` does, so `upper()` before you look anything up.

## Getting Data Into the Certificates Data Model

Check what's there with `| tstats count from datamodel=Certificates.All_Certificates by sourcetype`. Events need `tag=certificate` plus `tag=ssl` (or `tls`), and the searches use `ssl_issuer`, `ssl_subject_common_name`, `ssl_serial`, `ssl_hash`, `ssl_start_time` and `dest`. Your add-on should handle this. If it doesn't, this is the minimum I needed on a bare Splunk instance (Zeek x509 shown; `ssl.log` and Stream are the same idea, and the full set is in [`test-data/emudhra_hunt_testdata`](test-data/emudhra_hunt_testdata/default/props.conf)):

```ini
# props.conf
[corelight_x509]
KV_MODE = json
FIELDALIAS-cim = "certificate.issuer" AS ssl_issuer "certificate.subject" AS ssl_subject "certificate.serial" AS ssl_serial fingerprint AS ssl_hash "certificate.not_valid_before" AS ssl_start_time "certificate.not_valid_after" AS ssl_end_time
EVAL-ssl_subject_common_name = trim(replace('certificate.subject', "^(?:.*[,/]\s*)?CN\s*=\s*([^,/]+).*$", "\1"))

# eventtypes.conf / tags.conf
[certs_for_cim]
search = sourcetype IN (corelight_ssl, corelight_x509, "stream:tcp")
[eventtype=certs_for_cim]
certificate = enabled
ssl = enabled
```

Two things the data model does that will bite you:

- It fills missing `ssl_issuer`, `ssl_issuer_common_name`, `ssl_subject`, `ssl_subject_common_name` and `ssl_hash` with the word `unknown`. That's why the searches pull the CN out of `ssl_issuer` with `rex` instead of trusting `ssl_issuer_common_name`.
- `tstats` drops any row where a `by` field is empty. `ssl.log` has no serial or dates and `x509.log` has no `dest`, so always set `fillnull_value`.

For the pivots you also need your connection logs tagged `network` + `communicate` (Network_Traffic), and your DNS logs tagged `network` + `resolution` + `dns` (Network_Resolution).

## Extra Searches

All of these need the IOC lookup from [`emudhra_hunt/`](emudhra_hunt/). It has 16 rows (the eight CAs plus their Sectigo cross-signs), with SHA-256, SHA-1, hex and decimal serials, SPKI and SKI. I checked every row against the PEMs in the [we-have-a-problem.com repo](https://github.com/galadran/we-have-a-problem.com).

### Which compromised intermediates did my sensors see?

The main search finds the leaves. This one finds the intermediate certificates themselves, which tells you which trust path your clients were handed. `chains_via` is the issuer of the intermediate: the emSign G3 root, or Sectigo's `AAA Certificate Services`.

```spl
| tstats summariesonly=false fillnull_value="unknown" count min(_time) as firstTime max(_time) as lastTime values(All_Certificates.src) as src
  from datamodel=Certificates.All_Certificates
  where [| inputlookup emudhra_compromised_ca | eval h=mvappend(sha256, sha1) | mvexpand h | rename h as All_Certificates.SSL.ssl_hash | fields All_Certificates.SSL.ssl_hash | format]
  by All_Certificates.SSL.ssl_hash sourcetype
| rename All_Certificates.SSL.* as *
| eval ssl_hash=upper(ssl_hash)
| lookup emudhra_compromised_ca sha256 as ssl_hash OUTPUT ca_name chains_via
| lookup emudhra_compromised_ca sha1 as ssl_hash OUTPUTNEW ca_name chains_via
| eval firstTime=strftime(firstTime, "%F %T"), lastTime=strftime(lastTime, "%F %T")
| table ca_name chains_via ssl_hash count firstTime lastTime sourcetype
```

Only sources that log the whole chain will return anything here; in practice that's Zeek `x509.log`.

### What if my data is in OCSF?

The same leaf-issuer match, plus a chain match on serial numbers:

```spl
index=<ocsf_index> class_uid IN (4001, 4002) tls.certificate.issuer=*
| rex field=tls.certificate.issuer "CN\s*=\s*(?<issuer_cn>EM (DV|OV|EV) TLS CA - G3[BC]|EM OV CS CA - G3[BC])\s*(,|$)"
| eval chain=mvmap('tls.certificate_chain{}', ltrim(upper(replace('tls.certificate_chain{}', ":", "")), "0"))
| lookup emudhra_compromised_ca serial_norm as chain OUTPUT ca_name as chain_hit
| where isnotnull(issuer_cn) OR isnotnull(chain_hit)
| eval cert_issued=strftime('tls.certificate.created_time'/1000, "%F")
| fillnull value="none" issuer_cn chain_hit cert_issued
| stats count min(_time) as firstTime max(_time) as lastTime values(src_endpoint.ip) as src
        by dst_endpoint.ip tls.sni issuer_cn chain_hit cert_issued disposition
```

Watch the braces. Splunk names JSON arrays with `{}`, so it's `'tls.certificate_chain{}'`; without them the field is empty and the chain match never fires. The `fillnull` matters for the same reason as before: `stats` drops rows with an empty `by` field.

### Where does my certificate data live?

What's mapped into CIM:

```spl
| tstats count from datamodel=Certificates.All_Certificates by sourcetype index
```

And a keyword sweep for anything that isn't mapped. Put every index that might hold network, proxy or firewall data in place of `<your_network_indexes>`. It's cheap, because these terms are rare:

```spl
index=<your_network_indexes> earliest=-30d ("EM DV TLS CA" OR "EM OV TLS CA" OR "EM EV TLS CA" OR "EM OV CS CA" OR eMudhra OR emSign)
| stats count min(_time) as first max(_time) as last by index sourcetype
| convert ctime(first) ctime(last)
```

If the sweep comes back empty, make sure you log certificates at all before you celebrate: run the first search and look for Let's Encrypt and DigiCert issuers.

### Is there a hash or serial anywhere in raw data?

A subsearch that returns a field called `search` becomes raw search terms. End it with `| format`. Without it, Splunk only uses the first row, and you'll sweep for one value out of 48 without knowing.

```spl
index=<your_network_indexes> earliest=-30d
    [| inputlookup emudhra_compromised_ca | eval search=mvappend(sha256, sha1, serial_norm) | mvexpand search | fields search | format]
| stats count by index sourcetype
```

Use the same index list as the keyword sweep. This catches chain-logging sources (Zeek x509, `cert_chain_fps`, OCSF `certificate_chain`) whether or not they're in CIM. It won't match Suricata's colon-separated values, but the keyword sweep catches those by name.

### Who looked these servers up?

For clients behind NAT or a CDN, pivot on the hostname instead of the IP. This uses the `emudhra_cert_hits.csv` you saved from the main search:

```spl
| tstats summariesonly=false count values(DNS.src) as clients
  from datamodel=Network_Resolution.DNS
  where [| inputlookup emudhra_cert_hits.csv | where ssl_subject_common_name!="unknown" | dedup ssl_subject_common_name | fields ssl_subject_common_name | rename ssl_subject_common_name as DNS.query | format]
  by DNS.query DNS.answer
```

If the `DNS.answer` for a hit doesn't match where that name normally resolves, you may have found the hijack.

## Triage

| What you see | What it probably is | What to do |
|---|---|---|
| `*.we-have-a-problem.com` | Someone testing, maybe you | Nothing. It's free proof that your pipeline works. |
| Any other hit, whatever the date | A forged certificate | Look it up in CT ([Censys](https://search.censys.io/) or [Cert Spotter](https://sslmate.com/certspotter/)). If it's not there, it's an incident: pull the cert, work out where the attacker was on-path, and rotate whatever the client sent. |
| An `EM DV TLS CA - G3C` hit that *is* in CT | Possibly one of the few real G3C certs | Talk to the site owner before you escalate. |
| `established=true` on a hit (Zeek) | The client accepted it, or doesn't check | Put the client on the patch list and find out which app made the call. |
| An intermediate seen via `AAA Certificate Services` | The client was handed the Sectigo cross-sign path | Expect Apple and Windows machines, and old CA bundles, to trust it. |

## Testing It Yourself

A hunt that returns nothing only means something if you know it would have found something. You have two options.

**Live.** From a host behind your sensor (tell your SOC first!), run `curl --tls-max 1.2 https://dv-g3b-emudhra.we-have-a-problem.com/`. The server sends its chain before curl refuses it, so you'll get an event either way.

**Sample data.** On a test instance with the CIM add-on:

1. Create an index, for example `emudhra_test`.
2. Install `emudhra_hunt/` and `test-data/emudhra_hunt_testdata/`, then restart Splunk.
3. Load each file with its sourcetype. Settings > Add Data > Upload works, or from the CLI:

   ```bash
   splunk add oneshot test-data/corelight_ssl.json -index emudhra_test -sourcetype corelight_ssl
   splunk add oneshot test-data/corelight_x509.json -index emudhra_test -sourcetype corelight_x509
   splunk add oneshot test-data/stream_tcp.json -index emudhra_test -sourcetype stream:tcp
   splunk add oneshot test-data/ocsf_network_activity.json -index emudhra_test -sourcetype ocsf:network_activity
   ```

4. Run the searches over 13–20 October 2026 (or "All time"). Use `index=emudhra_test` for the OCSF search.

The events are synthetic logs generated from known-good data samples. The certificates for the test site come from the real chains in the [we-have-a-problem.com repo](https://github.com/galadran/we-have-a-problem.com). There are three groups of hosts:

- **The test site:** 12 sites, visited by 3 internal hosts.
- **A backdated forgery:** `portal.fabrikam.co.in`, on `EM OV TLS CA - G3C` and dated July 2026, used by 5 hosts. It should come back as "investigate".
- **A near-miss:** `mail.tailspintoys.co.in`, on an uncompromised emSign issuer. It should only show up in the keyword sweep.

Fabrikam and Tailspin Toys are fictional, and all server addresses are from documentation ranges. You should get:

| Search | Result |
|---|---|
| Main search | 12 "test site" rows in each of `corelight_ssl`, `corelight_x509` and `stream:tcp`, plus `portal.fabrikam.co.in` as "investigate" in all three. |
| Stream search (no CIM) | 12 "test site" rows plus `portal.fabrikam.co.in` as "investigate" (22 events). |
| Pivot | 8 client/server pairs: 3 to the test site, 5 to the forgery. |
| Intermediates | 12 compromised intermediates in `corelight_x509`: 6 via the emSign root, 6 via the Sectigo cross-sign. |
| OCSF | 13 rows (12 test site, 1 forgery), all with a chain hit. |
| Data model inventory | `corelight_ssl` 43, `corelight_x509` 49, `stream:tcp` 43. |
| Keyword sweep | 43 events in each of `corelight_ssl`, `stream:tcp` and OCSF, and 49 in `corelight_x509`. That includes the near-miss, which is what a discovery sweep is for. |
| Hash and serial sweep | `corelight_ssl` 12, `corelight_x509` 17, OCSF 34, Stream 0. |
| DNS pivot | Nothing; there's no DNS data in the samples. |

When I ran these searches, the same events were buried in a week of synthetic background traffic (about 13.5k events), and nothing in the background came back.

## Appendix: The Eight Compromised CAs

Each one appears twice: issued by its emSign G3 root, and cross-signed by `AAA Certificate Services`. The TLS CAs allow both server and client authentication. Full SHA-256, SHA-1, serial and SPKI values are in the lookup.

| CA | Usage | SKI (same for both copies) |
|---|---|---|
| EM DV TLS CA - G3B | TLS | `E21E2FE71C19390E554B62C120245735248A2514` |
| EM OV TLS CA - G3B | TLS | `9BD86551AFE7E72C37AD08EE6919D9BF3784AE0A` |
| EM EV TLS CA - G3B | TLS | `3EDC20D9894698877B873FD88147B25C15D84706` |
| EM DV TLS CA - G3C | TLS | `AE7E105C3C2996C1A847270559F1E03DD4E50AF3` |
| EM OV TLS CA - G3C | TLS | `34EAEA0CEBC90ADAF9D0C5E2ED9B78C9879E1B6C` |
| EM EV TLS CA - G3C | TLS | `A6255E80A94DB7F3967C1BC791DF92BCEE4BEB5F` |
| EM OV CS CA - G3B | Code signing | `79FAE8ECCFDB0D758DA458D69FB6EDDC7C49DEE6` |
| EM OV CS CA - G3C | Code signing | `EE6F73298D6FBFA7B31BC39534F61556447866B7` |

*Sources: [galadran/we-have-a-problem.com](https://github.com/galadran/we-have-a-problem.com) (commit `87b66fe`) and [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449).*
