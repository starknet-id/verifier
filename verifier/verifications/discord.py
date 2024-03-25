import aiohttp
from .common import WrongRequestException


async def start_discord(conf, code):

    async with aiohttp.ClientSession() as session:
        resp = await session.post(
            conf.discord_api_endpoint + "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": conf.discord_client_id,
                "client_secret": conf.discord_client_secret,
                "redirect_uri": conf.discord_redirect_uri,
                "scope": "identify",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status != 200:
            error_content = await resp.text()
            print(f"Error: {error_content}")
            raise WrongRequestException()

        content = await resp.json()
        token_type = content["token_type"]
        token = content["access_token"]

        resp = await session.get(
            "https://discordapp.com/api/users/@me",
            headers={"Authorization": f"{token_type} {token}"},
        )
        if resp.status != 200:
            raise WrongRequestException()
        content = await resp.json()
        print(content)
        user_id = content["id"]
        username = content["username"]
        discriminator = content["discriminator"]

        return user_id, username, discriminator
