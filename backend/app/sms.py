"""SMS dispatch seam — fverify OWNS the OTP (owner ruling 2026-08-31): the
code is minted and verified in this service; only DELIVERY rides this seam.
Dev stub today (nothing is sent, the masked hint comes back); a provider or
the Agentys SMS workflow slots in later — the signature is the contract.

The raw code must NEVER be logged anywhere.
"""


def mask_mobile(mobile: str) -> str:
    digits = "".join(ch for ch in mobile if ch.isdigit())
    return f"*** *** {digits[-3:]}" if len(digits) >= 3 else "***"


async def send_otp_sms(mobile: str, code: str) -> str:
    """Dispatch the code to the (T24-registered) mobile. Returns the masked
    channel hint for the API response. Dev stub: no provider wired — nothing
    is sent and nothing is logged; the dev code is known to the lane."""
    del code  # the raw code is never logged, never echoed
    return mask_mobile(mobile)
