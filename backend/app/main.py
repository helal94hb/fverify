"""App factory for the standalone face-verification backend.

Fully decoupled from the digital-banking platform: own DB, own keys, own app.
Run with:  uv run uvicorn app.main:app --reload
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import api, db
from .config import get_settings
from .errors import register_exception_handlers

logger = logging.getLogger("face_verify")


def _load_seal_private_key(pem: str | None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if pem:
        return serialization.load_pem_private_key(pem.replace("\\n", "\n").encode(), password=None)
    logger.warning(
        "FV_SEAL_PRIVATE_KEY_PEM is unset: generating an EPHEMERAL dev-only RSA key. "
        "Embeddings sealed to this key become unreadable after restart."
    )
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = db.make_engine(settings)
        await db.init_db(engine)
        app.state.session_factory = db.make_session_factory(engine)
        app.state.seal_private_key = _load_seal_private_key(settings.seal_private_key_pem)
        yield
        await engine.dispose()

    app = FastAPI(title="Face Verification (standalone)", version="0.1.0", lifespan=lifespan)
    register_exception_handlers(app)
    app.include_router(api.router)
    return app


app = create_app()
