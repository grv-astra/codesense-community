"""Stamp X-CodeSense-Edition on every response -- cheap support/observability.
Never raises: a resolution failure just omits the header rather than 500ing."""
from licenses.services import entitlements


class EditionHeaderMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        try:
            response["X-CodeSense-Edition"] = entitlements.get().edition
        except Exception:
            pass
        return response
