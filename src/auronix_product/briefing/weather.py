"""Weather helper with profile city lookup and short timeout caching."""

from __future__ import annotations

import json
import time
from pathlib import Path
import httpx

from ..actions.handlers import DEFAULT_CITY

_WEATHER_CACHE: dict[str, tuple[float, dict]] = {}

_WEATHER_CODES = {
    0: "clear sky",
    1: "mostly clear",
    2: "partly cloudy",
    3: "overcast",
    45: "foggy",
    51: "light drizzle",
    61: "slight rain",
    63: "moderate rain",
    65: "heavy rain",
    71: "slight snow",
    80: "rain showers",
    95: "thunderstorm",
}


def _resolve_city(city: str | None) -> str:
    if city and city.strip():
        return city.strip()
    profile_path = Path.home() / ".auronix" / "profile.json"
    if profile_path.exists():
        try:
            prof = json.loads(profile_path.read_text(encoding="utf-8"))
            if isinstance(prof, dict) and str(prof.get("city", "")).strip():
                return str(prof["city"]).strip()
        except Exception:
            pass
    return DEFAULT_CITY


def get_weather(city: str | None = None, ttl: float = 60.0) -> dict:
    """Fetch current weather for city with a 60-second cache and 4s timeout."""
    target_city = _resolve_city(city)
    cache_key = target_city.lower()
    now = time.monotonic()
    cached = _WEATHER_CACHE.get(cache_key)
    if cached is not None and (now - cached[0]) < ttl:
        return dict(cached[1])

    try:
        geo = httpx.get(
            "https://geocoding-api.open-meteo.com/v1/search",
            params={"name": target_city, "count": 1, "language": "en"},
            timeout=4.0,
        ).json()
        if not geo.get("results"):
            data = {
                "city": target_city,
                "temp_c": None,
                "condition": "unknown",
                "summary": f"I couldn't find weather data for {target_city}.",
            }
            _WEATHER_CACHE[cache_key] = (now, data)
            return dict(data)

        loc = geo["results"][0]
        w = httpx.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude": loc["latitude"],
                "longitude": loc["longitude"],
                "current": "temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m",
                "timezone": "auto",
            },
            timeout=4.0,
        ).json()
        cur = w["current"]
        temp_c = cur.get("temperature_2m")
        cond = _WEATHER_CODES.get(cur.get("weather_code"), "mixed")
        place = f"{loc.get('name', target_city)}, {loc.get('country', '')}".strip(", ")
        summary = (
            f"In {place}, it's {temp_c}°C and {cond}, "
            f"humidity {cur.get('relative_humidity_2m')}%, wind {cur.get('wind_speed_10m')} km/h."
        )
        data = {
            "city": loc.get("name", target_city),
            "temp_c": temp_c,
            "condition": cond,
            "summary": summary,
        }
        _WEATHER_CACHE[cache_key] = (now, data)
        return dict(data)
    except Exception as e:
        return {
            "city": target_city,
            "temp_c": None,
            "condition": "unavailable",
            "summary": f"Weather unavailable for {target_city}: {e}",
        }

