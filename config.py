# configuration file for Flask app (keys, database URLs ...)
from dotenv import load_dotenv
import datetime

import os

load_dotenv()

class Config:
  SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
  JWT_SECRET_KEY = os.environ.get('SECRET_KEY')
  SQLALCHEMY_TRACK_MODIFICATIONS = False
  JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=3600)


