# LLMSAN: Bug Detection with Large Language Models and Data-Flow Sanitization

**LLMSAN** is a research-oriented tool designed for detecting and sanitizing software bugs using Large Language Models (LLMs) with minimal token overhead. It combines static analysis with prompt-based LLM reasoning to reduce false positives in bug reports.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/dunnokiet/llmsan-fork.git
    cd llmsan-fork
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Ensure you have the Tree-sitter library and language bindings installed:
    ```bash
    cd lib
    python build.py
    cd ..
    ```

4. Configure the keys:
   
   Create a `.env.local` file in your project root and add your OpenAI API Key.

    ```bash
    touch .env.local
    ```

   Edit the `.env.local` file:
    ```
    OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    ```

5. Run the LLMSAN FastAPI

   This will start a local backend service for analysis and sanitization.
    ```bash
    python src/index.py
    ```

Once the server is running, open your browser and go to:

http://localhost:8000/docs

(Interactive Swagger UI to test the API)

## API Endpoints

You can configure the analysis by specifying parameters in the API requests.

### `/api/analysis`
- **Method**: POST
- **Parameters**:
  - `file`: Source code file to analyze (UploadFile).
  - `bug_type`: Type of bug (`apt`, `ci`, `dbz`, `npd`, `xss`).
  - `model_name`: LLM model for detection (e.g., `gpt-3.5-turbo`).
- **Response**: Streaming response with analysis results.

### `/api/sanitize`
- **Method**: POST
- **Parameters**:
  - `file_name`: Name of the file to sanitize (string, e.g., `example.java`).
  - `bug_type`: Type of bug (default: `dbz`).
  - `model_name`: LLM model for sanitization (default: `gpt-4.1-mini`).
- **Response**: Sanitized code as plain text.

## More Programming Languages

LLMSAN is language-agnostic. To migrate the current implementations to other programming languages or extract more syntactic facts, please refer to the grammar files in the corresponding Tree-sitter libraries and refactor the code in `sanitizer/analyzer.py`. Basically, you only need to change the node types when invoking `find_nodes`.

Here are the links to grammar files in Tree-sitter libraries targeting mainstream programming languages:

- C: https://github.com/tree-sitter/tree-sitter-c/blob/master/src/grammar.json
- C++: https://github.com/tree-sitter/tree-sitter-cpp/blob/master/src/grammar.json
- Java: https://github.com/tree-sitter/tree-sitter-java/blob/master/src/grammar.json
- Python: https://github.com/tree-sitter/tree-sitter-python/blob/master/src/grammar.json
- JavaScript: https://github.com/tree-sitter/tree-sitter-javascript/blob/master/src/grammar.json

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
