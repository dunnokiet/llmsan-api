import json
from pathlib import Path
from fastapi import FastAPI, UploadFile
from fastapi.responses import PlainTextResponse, StreamingResponse
from model.llm import LLM
from pipeline import stream_llmsan
from model.utils import *
import uvicorn

app = FastAPI()


@app.post("/api/analysis")
async def analysis(file: UploadFile, model_name: str, bug_type: str):
    specs = ["dbz.json", "npd.json", "xss.json", "ci.json", "apt.json"]

    bug_type_id = {"dbz": 0, "npd": 1, "xss": 2, "ci": 3, "apt": 4}.get(bug_type, -1)

    source_code = (await file.read()).decode('utf-8')
    file_name = file.filename

    detection_key = standard_key
    anitization_key = standard_key

    spec = specs[bug_type_id]

    response = stream_llmsan(
        source_code=source_code,
        file_name=file_name,
        code_in_support_files={},
        detection_online_model_name=model_name,
        detection_key=detection_key,
        sanitization_online_model_name=model_name,
        sanitization_key=anitization_key,
        spec_file_name=spec,
        analysis_mode="eager",
        neural_sanitize_strategy={"functionality_sanitize": True, "reachability_sanitize": True},
        is_measure_token_cost=False 
    )

    return StreamingResponse(response)

@app.post("/api/sanitize")
async def sanitize_code(file_name: str, model_name: str = "gpt-4.1-mini", bug_type: str = "dbz"):
    log_dir = Path(__file__).resolve().parent.parent / "log" / "llmsan" / "sanitization" / model_name

    case_name = file_name.replace(".java", "")

    log_file = log_dir / f"{case_name}.json"

    with open(log_file, "r") as f:
        log_data = json.load(f)

    original_code = log_data.get("original code", "")
    trace_check_results = log_data.get("trace_check_results", [])

    llm = LLM(online_model_name=model_name, openai_key=standard_key, temperature=0.7)

    prompt_file = Path(__file__).resolve().parent / "prompt" / "santize.json"

    with open(prompt_file, "r") as f:
        prompt_data = json.load(f)
    
    meta_prompts = prompt_data.get("meta_prompts", [])

    prompt_template = meta_prompts[0]

    prompt = prompt_template.format(
        original_code=original_code,
        bug_type=bug_type,
        trace_check_results=json.dumps(trace_check_results, indent=2)
    )

    sanitized_code, _, _ = llm.infer(prompt)

    return PlainTextResponse(sanitized_code)


if __name__ == "__main__":
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)