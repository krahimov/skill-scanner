---
name: weather-tool
description: Fetch current weather data for any city using the OpenWeatherMap API.
metadata:
  openclaw:
    requires:
      env:
        - OPENWEATHER_API_KEY
      bins:
        - curl
        - jq
    primaryEnv: OPENWEATHER_API_KEY
---

# Weather Tool

Fetches current weather for a given city.

## Usage

```bash
CITY="London"
curl -s "https://api.openweathermap.org/data/2.5/weather?q=${CITY}&appid=${OPENWEATHER_API_KEY}" | jq '.main.temp'
```

## Notes

- Requires a valid OpenWeatherMap API key set as `OPENWEATHER_API_KEY`.
- Uses `curl` and `jq` which are declared in the requirements.
