# reports factors to factordb
import os
import re
import urllib3
import logging

http = urllib3.PoolManager()

logger = logging.getLogger("global_logger")


def send2fdb(composite, factors):
    factors = map(str, factors)
    payload = {"report": f"{str(composite)}=" + "*".join(factors)}
    url = "https://factordb.com/report.php"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
        # Attribute reported factors to a FactorDB account; override with
        # the FDB_COOKIE env var to report under your own account.
        "Cookie": os.environ.get(
            "FDB_COOKIE", "fdbuser=c777863e3e92987fd320986b5fb72e94"
        ),
    }
    response = http.request(
        "POST",
        url,
        encode_multipart=False,
        headers=headers,
        fields=payload,
        timeout=30,
    )
    webpage = str(response.data.decode("utf-8"))

    matches = re.findall(r"Found [0-9] factors and [0-9] ECM", webpage)
    if not matches:
        logger.info("[!] Factordb response did not mention any factor counts")
    elif matches[0] == "Found 0 factors and 0 ECM":
        logger.info("[!] All the factors we found are already known to factordb")
    else:
        logger.info(f"[+] Factordb: {matches[0]}")
