---
layout: post
title: "[CVE-2022-35933] Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in prestashop/productcomments"
categories: module
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,productcomments"
severity: "medium (6.1)"
---

Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in prestashop/productcomments

## Summary

* **CVE ID**: [CVE-2022-35933](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-35933)
* **Published at**: 2022-11-01
* **Advisory source**: [github](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-35933/poc.txt)
* **Vendor**: PrestaShop
* **Product**: productcomments
* **Impacted release**: 5.0.1
* **Product author**: 
* **Weakness**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* **Severity**: medium (6.1)

## Description

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: required
* **Scope**: changed
* **Confidentiality**: low
* **Integrity**: low
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

## Possible malicious usage

* Bypass Protection Mechanism
* Read Application Data
* Execute Unauthorized Code or Commands

## Patch

The issue is fixed in 5.0.2
https://github.com/PrestaShop/productcomments/commit/314456d739155aa71f0b235827e8e0f24b97c26b

## Other recommendations

* Upgrade the module to the most recent version
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Systematically escape characters ' " < and > by replacing them with HTML entities and applying strip_tags
* Limit to the strict minimum the length's value in database - a database field which allow 10 characters (varchar(10)) is far less dangerous than a field which allow 40+ characters (use cases which can exploit fragmented XSS payloads are very rare)
* Configure CSP headers (content security policies) by listing externals domains allowed to load assets (such as js files) or being called in XHR transactions (Ajax).
* If applicable: check against all your frontoffice's uploaders, uploading files which will be served by your server with mime type application/javascript (like every .js natively) must be strictly forbidden as it must be considered as dangerous as PHP files.
* Activate OWASP 941's rules on your WAF (Web application firewall) - be warn that you will probably break your backoffice and you will need to preconfigure some bypasses against these set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 01-11-2022 | GitHub Poc |

## Links

* [Source of this CVE](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-35933/poc.txt)
* [National Vulnerability Database CVE-2022-35933](https://nvd.nist.gov/vuln/detail/CVE-2022-35933)
