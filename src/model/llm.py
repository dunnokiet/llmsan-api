from openai import *
import sys
import tiktoken
from typing import Tuple
from model.utils import *
import time
import threading
from pathlib import Path
import replicate
import google.generativeai as genai


class LLM:
    """
    An online inference model using ChatGPT
    """

    def __init__(self, online_model_name: str, openai_key: str, temperature: float) -> None:
        """
        Initialize the LLM with model name, OpenAI key, and temperature.
        :param online_model_name: Name of the online model to use
        :param openai_key: API key for OpenAI
        :param temperature: Temperature setting for the model
        """
        self.online_model_name = online_model_name
        self.encoding = tiktoken.encoding_for_model("gpt-3.5-turbo-0125")
        self.openai_key = openai_key
        self.temperature = temperature
        self.systemRole = "You are an experienced Java programmer and good at understanding Java programs."

    # Main Inference Function
    def infer(self, message: str, is_measure_cost: bool = False) -> Tuple[str, int, int]:
        """
        Perform inference using the specified online model.
        :param message: The input message for the model
        :param is_measure_cost: Flag to measure token cost
        :return: Tuple containing the output, input token cost, and output token cost
        """
        output = ""
        if "gpt" in self.online_model_name:
            output = self.infer_with_openai_model(message)

        input_token_cost = 0 if not is_measure_cost else len(self.encoding.encode(self.systemRole)) + len(self.encoding.encode(message))
        output_token_cost = 0 if not is_measure_cost else len(self.encoding.encode(output))
        return output, input_token_cost, output_token_cost

    # Inference with OpenAI Model
    def infer_with_openai_model(self, message: str) -> str:
        """
        Perform inference using the OpenAI model.
        :param message: The input message for the model
        :return: The output from the model
        """
        model_input = [
            {"role": "system", "content": self.systemRole},
            {"role": "user", "content": message},
        ]

        received = False
        tryCnt = 0
        output = ""

        def run_with_timeout(timeout, func, *args):
            result = [None]
            exception = [None]

            def target():
                try:
                    result[0] = func(*args)
                except Exception as e:
                    exception[0] = e

            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout)
            
            if thread.is_alive():
                # Timeout occurred
                return None, TimeoutError("ChatCompletion timeout")
            if exception[0] is not None:
                raise exception[0]
            return result[0], None

        while not received:
            tryCnt += 1
            time.sleep(2)
            try:
                # OpenAI version: 24.0
                # Use OpenAI official APIs
                def call_openai():
                    client = OpenAI(api_key=self.openai_key)
                    response = client.chat.completions.create(
                        model=self.online_model_name, messages=model_input, temperature=self.temperature
                    )
                    return response.choices[0].message.content

                # Run with a 100-second timeout
                result, error = run_with_timeout(100, call_openai)
                
                if error:
                    if isinstance(error, TimeoutError):
                        received = False
                        raise KeyboardInterrupt("Simulating Ctrl+C")
                    raise error
                
                output = result
                received = True
                break
            except KeyboardInterrupt:
                output = ""
                break
            except Exception:
                received = False
            if tryCnt > 5:
                output = ""
                break
        return output