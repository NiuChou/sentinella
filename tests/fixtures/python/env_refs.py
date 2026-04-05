import os

# Direct access (no default)
database_url = os.environ["DATABASE_URL"]

# With default via os.environ.get
port = os.environ.get("PORT", "5432")

# With default via os.getenv
host = os.getenv("HOST", "localhost")

# No default via os.getenv
api_key = os.getenv("API_KEY")

# Direct bracket access
secret = os.environ["SECRET_KEY"]
