import os
import openai
from dotenv import load_dotenv

load_dotenv(".env")

# Standard OpenAI API
standard_key = os.environ.get("OPENAI_API_KEY")

# Iterative count bound
iterative_count_bound = 3
