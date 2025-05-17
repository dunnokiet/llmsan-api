import json
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import StreamingResponse
from pipeline import stream_llmsan
from model.utils import *

app = FastAPI()

@app.post("/api/analysis/")
async def upload_file(file: UploadFile = File(...)):
    source_code = (await file.read()).decode('utf-8')
    file_name = file.filename

    detection_key = standard_key
    anitization_key = standard_key

    response = stream_llmsan(
        source_code=source_code,
        file_name=file_name,
        code_in_support_files={},
        detection_online_model_name="gpt-4o-mini",
        detection_key=detection_key,
        sanitization_online_model_name="gpt-4o-mini",
        sanitization_key=anitization_key,
        spec_file_name="dbz.json",
        analysis_mode="eager",
        neural_sanitize_strategy={"functionality_sanitize": True, "reachability_sanitize": True},
        is_measure_token_cost=False
    )

    return StreamingResponse(response)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)