"""RFC 7807 problem+json error surface. Fail-closed, client-safe details only.

Problem titles are diagnostic, never customer copy. No embeddings, PII, or
internals are ever placed in a problem body.
"""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

PROBLEM_MEDIA_TYPE = "application/problem+json"

_TYPE_BASE = "urn:face-verify:problem:"


class ProblemError(Exception):
    """Raised by handlers to produce a designed problem+json response."""

    def __init__(self, status: int, slug: str, title: str, detail: str) -> None:
        self.status = status
        self.slug = slug
        self.title = title
        self.detail = detail
        super().__init__(title)


def problem_response(status: int, slug: str, title: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        media_type=PROBLEM_MEDIA_TYPE,
        content={
            "type": f"{_TYPE_BASE}{slug}",
            "title": title,
            "status": status,
            "detail": detail,
        },
    )


def invalid_embedding(detail: str) -> ProblemError:
    return ProblemError(422, "invalid-embedding", "Invalid embedding payload", detail)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def on_problem(_request: Request, exc: ProblemError) -> JSONResponse:
        return problem_response(exc.status, exc.slug, exc.title, exc.detail)

    @app.exception_handler(RequestValidationError)
    async def on_validation(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Fail-closed: extra fields (e.g. anything image-like) are rejected here.
        return problem_response(
            422,
            "invalid-request",
            "Invalid request",
            "Request body failed validation; unknown or missing fields are not accepted.",
        )

    @app.exception_handler(Exception)
    async def on_unexpected(_request: Request, exc: Exception) -> JSONResponse:
        # Never leak internals.
        return problem_response(
            500, "internal-error", "Internal error", "An unexpected error occurred."
        )
