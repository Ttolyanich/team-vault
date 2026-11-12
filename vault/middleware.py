import ipaddress
from django.conf import settings


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        peer = request.META.get("REMOTE_ADDR", "")
        request.client_ip = peer
        if peer in settings.TRUSTED_PROXY_IPS:
            try:
                # Nginx must overwrite this header with $remote_addr, never append client input.
                request.client_ip = str(ipaddress.ip_address(request.META.get("HTTP_X_FORWARDED_FOR", "")))
            except ValueError:
                pass
        response = self.get_response(request)
        response["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
        response["Referrer-Policy"] = "same-origin"
        response["Cache-Control"] = "no-store"
        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response
