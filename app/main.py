"""FastAPI local static host and strict CSP security-headers server."""

import mimetypes
from typing import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
import uvicorn

from app.config import Settings, load_settings
from app.schemas import HealthResponse

# Ensure Windows registries with non-standard static mappings serve assets properly.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/svg+xml", ".svg")
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("image/png", ".png")
mimetypes.add_type("application/manifest+json", ".webmanifest")
mimetypes.add_type("application/xml", ".xml")
mimetypes.add_type("text/plain", ".txt")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the PromptVeil FastAPI static host."""
    resolved_settings = settings if settings is not None else load_settings()

    application = FastAPI(
        title="PromptVeil",
        version=resolved_settings.app_version,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.settings = resolved_settings

    @application.middleware("http")
    async def add_security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = resolved_settings.csp_policy
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        return response

    @application.api_route(
        "/health",
        methods=["GET", "HEAD"],
        response_model=HealthResponse,
        tags=["health"],
    )
    async def health_check() -> HealthResponse:
        return HealthResponse(version=resolved_settings.app_version)

    # Mount static bundle at '/' AFTER '/health' so relative paths (./styles.css, ./js/*.js)
    # resolve identically on FastAPI and Netlify (publish = "app/static").
    # Zero /api/sanitize or /api/rehydrate routes exist.
    application.mount(
        "/",
        StaticFiles(
            directory=str(resolved_settings.static_dir),
            html=True,
            check_dir=False,
        ),
        name="static",
    )

    return application


app: FastAPI = create_app()


if __name__ == "__main__":
    runtime_settings = load_settings()
    uvicorn.run(
        "app.main:app",
        host=runtime_settings.app_host,
        port=runtime_settings.app_port,
        log_level=runtime_settings.log_level,
    )
