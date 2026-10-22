import logging
import os
import subprocess

NECA_BIN = os.environ.get("NECA_BIN", "neca")


def neca_factor_driver(n, timeout=None):
    logging.getLogger("global_logger").info("[*] Factoring %d with neca..." % n)
    necaresult = subprocess.check_output(
        [NECA_BIN, f"{n}"], timeout=timeout, stderr=subprocess.DEVNULL
    )
    if b"FAIL" in necaresult or b"*" not in necaresult:
        return None
    necaresult_l = necaresult.decode("utf8", errors="replace").split("\n")
    for line in necaresult_l:
        r0 = line.find("N = ")
        r1 = line.find(" * ")
        if r0 > -1 and r1 > -1:
            return list(map(int, line.split("=")[1].split("*")))
    return None



