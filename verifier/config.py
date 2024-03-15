import os
import toml
import shutil


class Config:
    def get_path(self, name):
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.realpath(__file__))), name
        )

    def extract_config(self, file_name, template_name):
        config_file = self.get_path(file_name)
        if not os.path.isfile(config_file):
            print(f"config {file_name} doesn't exist, copying template!")
            shutil.copyfile(self.get_path(template_name), config_file)
        return config_file


class TomlConfig(Config):
    def __init__(self, file_name, template_name):
        config_file = self.extract_config(file_name, template_name)
        self.load_config(config_file)

    def load_config(self, config_file):
        config = toml.load(config_file)

        server = config["server"]
        self.server_port = server["port"]

        starknet = config["starknet"]
        self.identity_contract = starknet["identity_contract"]
        self.verifier_contract = starknet["verifier_contract"]
        self.verifier_key = starknet["verifier_key"]

        discord = config["discord"]
        self.discord_api_endpoint = discord["api_endpoint"]
        self.discord_client_id = discord["client_id"]
        self.discord_client_secret = discord["client_secret"]
        self.discord_redirect_uri = discord["redirect_uri"]

        twitter = config["twitter"]
        self.twitter_api_endpoint = twitter["api_endpoint"]
        self.twitter_client_id = twitter["client_id"]
        self.twitter_redirect_uri = twitter["redirect_uri"]

        github = config["github"]
        self.github_api_endpoint = github["api_endpoint"]
        self.github_client_id = github["client_id"]
        self.github_client_secret = github["client_secret"]
        self.github_redirect_uri = github["redirect_uri"]
