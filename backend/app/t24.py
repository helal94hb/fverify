"""T24 (core banking) seam — the enrollment's identity anchor (owner ruling
2026-08-31): a national id resolves through the CORE to the real customer id +
the REGISTERED mobile. The customer never self-asserts the phone number.

Stub by default (the fixture serves the demo customer); the live path rides
`FV_T24_LIVE=true` + `FV_T24_BASE_URL` + `FV_T24_API_KEY` (env-only, never
hardcoded). Live upstream errors fail closed with a client-safe AdapterError
— an enrolment must never proceed on an unresolved anchor.
"""

import httpx

from .config import get_settings
from .errors import ProblemError

#: the demo anchor (mirrors the banking platform's demo customer for the PoC)
STUB_CUSTOMERS: dict[str, dict[str, str]] = {
    "12345678901234": {"customer_id": "cust-000123", "mobile": "01000000000"},
}


class T24UnavailableError(ProblemError):
    def __init__(self) -> None:
        super().__init__(
            502,
            "t24-unavailable",
            "Core banking is temporarily unavailable",
            "Please try again in a moment.",
        )


async def resolve_customer(national_id: str) -> dict[str, str] | None:
    """national id → {customer_id, mobile} (the REGISTERED mobile), or None
    when the id is not a bank customer (a face cannot be enrolled for one)."""
    settings = get_settings()
    if not settings.t24_live:
        return STUB_CUSTOMERS.get(national_id)

    try:
        async with httpx.AsyncClient(base_url=settings.t24_base_url, timeout=10.0) as http:
            res = await http.get(
                f"/customers/by-national-id/{national_id}",
                headers={"X-Api-Key": settings.t24_api_key},
            )
    except httpx.HTTPError as exc:
        raise T24UnavailableError() from exc

    if res.status_code == 404:
        return None
    if res.status_code >= 400:
        raise T24UnavailableError()
    body = res.json()
    customer_id = body.get("customer_id")
    mobile = body.get("mobile")
    if not customer_id or not mobile:
        # An anchor without a registered mobile cannot carry the OTP — treat
        # it as unresolved rather than enrol against a guessed number.
        return None
    return {"customer_id": str(customer_id), "mobile": str(mobile)}
