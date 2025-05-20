from data.transform import *
from sanitizer.analyzer import *
from sanitizer.passes import *
from parser.parser import *
from model.detector import *
import json
import os
from pathlib import Path
from typing import Dict

def stream_llmsan(
    source_code: str,
    file_name: str,
    code_in_support_files: Dict[str, str],
    detection_online_model_name: str,
    detection_key: str,
    sanitization_online_model_name: str,
    sanitization_key: str,
    spec_file_name: str,
    analysis_mode: str,
    neural_sanitize_strategy: Dict[str, bool],
    is_measure_token_cost: bool
):
    """
    Start the LLMsan process.
    :param source_code: Content of the Java file to analyze
    :param file_name: Name of the Java file (for case_name and logging)
    :param code_in_support_files: Dictionary of support files with their content
    :param detection_online_model_name: Name of the online model for detection
    :param detection_key: API key for the detection model
    :param sanitization_online_model_name: Name of the online model for sanitization
    :param sanitization_key: API key for the sanitization model
    :param spec_file_name: Name of the specification file
    :param analysis_mode: Analysis mode for the detection model
    :param neural_sanitize_strategy: Dictionary of neural check strategies
    :param is_measure_token_cost: Flag to measure token cost
    """
    cnt = 0
    case_name = file_name.replace(".java", "")
    yield json.dumps({"stage": "started", "message": f"Analyzing {case_name}"}) + "\n"

    is_detected = False
    log_dir_path = str(
        Path(__file__).resolve().parent.parent / ("log/llmsan/initial_detection/" + detection_online_model_name)
    )
    if not os.path.exists(log_dir_path):
        os.makedirs(log_dir_path)
    existing_json_file_names = set([])

    for root, dirs, files in os.walk(log_dir_path):
        for file in files:
            if case_name in file:
                is_detected = True
                cnt += 1
                json_file_name = root + "/" + file
                existing_json_file_names.add(json_file_name)

    if detection_online_model_name == sanitization_online_model_name:
        sanitization_log_file_dir = str(
            Path(__file__).resolve().parent.parent / ("log/llmsan/sanitization/" + detection_online_model_name)
        )
    else:
        sanitization_log_file_dir = str(
            Path(__file__).resolve().parent.parent / (
                "log/llmsan/sanitization/" + detection_online_model_name + "_" + sanitization_online_model_name)
        )

    if not os.path.exists(sanitization_log_file_dir):
        os.makedirs(sanitization_log_file_dir)

    new_code = obfuscate(source_code)
    lined_new_code = add_line_numbers(new_code)

    total_traces = []

    if not is_detected or analysis_mode == "eager":
        detector = Detector(detection_online_model_name, detection_key, spec_file_name)
        json_file_name = case_name

        iterative_cnt = 0
        while True:
            output = detector.start_detection(
                case_name,
                json_file_name,
                log_dir_path,
                source_code,
                lined_new_code,
                code_in_support_files,
                False,
                is_measure_token_cost
            )
            
            yield json.dumps({"stage": "detection", "output": parse_bug_report(output)}) + "\n"

            bug_num, traces, first_report = parse_bug_report(output)
            if len(traces) == bug_num:
                break
            iterative_cnt += 1
            if iterative_cnt > iterative_count_bound:  
                bug_num = 0
                traces = []
                break
        total_traces = traces

        existing_result = {
            "response": {
                "original code": source_code,
                "analyzed code": lined_new_code,
                "response": output,
                "input token": 0,
                "output token": 0,
                "program line": 0
            }
        }
        
        output_json_file_name = (Path(log_dir_path).parent.parent / "initial_detection"
                                 / detection_online_model_name / (case_name + ".json"))
        
        if os.path.exists(output_json_file_name):
            os.remove(output_json_file_name)
        with open(output_json_file_name, "w") as file:
            json.dump(existing_result, file, indent=4)

    else:
        for json_file_name in existing_json_file_names:
            with open(json_file_name) as existing_json_file:
                existing_result = json.load(existing_json_file)
                output = existing_result["response"]["response"]
                bug_num, traces, report = parse_bug_report(output)

                if bug_num != len(traces):
                    bug_num = 0
                    traces = []

                total_traces.extend(traces)

    ts_analyzer = TSAnalyzer(case_name, source_code, new_code, code_in_support_files)
    passes = Passes(sanitization_online_model_name, sanitization_key, spec_file_name)

    trace_cnt = 0
    cnt_dict = {
        "type_sanitize": 0,
        "functionality_sanitize": 0,
        "order_sanitize": 0,
        "reachability_sanitize": 0,
        "total": 0,
        "final": 0
    }
    trace_check_results = []
    history_trace_strs = set([])

    for trace in total_traces:
        cnt_dict_in_single_trace = {
            "type_sanitize": 0,
            "functionality_sanitize": 0,
            "order_sanitize": 0,
            "reachability_sanitize": 0,
            "total": 0,
            "final": 0
        }

        if str(trace) in history_trace_strs:
            continue
        history_trace_strs.add(str(trace))

        trace_cnt += 1
        cnt_dict["total"] += 1
        cnt_dict_in_single_trace["total"] += 1

        yield json.dumps({"stage": "analyzing_trace", "trace": trace}) + "\n"

        syntactic_check_result = passes.type_sanitize(ts_analyzer, trace)

        yield json.dumps({"stage": "type_sanitize", "result": syntactic_check_result}) + "\n"

        if syntactic_check_result:
            cnt_dict["type_sanitize"] += 1
            cnt_dict_in_single_trace["type_sanitize"] += 1

        functionality_sanitize_result, function_check_output_results = (
            passes.functionality_sanitize(ts_analyzer, trace, is_measure_token_cost)
            if neural_sanitize_strategy["functionality_sanitize"] else (True, {})
        )

        yield json.dumps({"stage": "functionality_sanitize", "result": functionality_sanitize_result, "reason": function_check_output_results}) + "\n"

        if functionality_sanitize_result:
            cnt_dict["functionality_sanitize"] += 1
            cnt_dict_in_single_trace["functionality_sanitize"] += 1

        with open(sanitization_log_file_dir + "/" + case_name + "_" + str(trace_cnt)
                + "_functionality_sanitize.json", "w") as file:
            json.dump(function_check_output_results, file, indent=4)

        order_sanitize_result = passes.order_sanitize(ts_analyzer, trace)
        if order_sanitize_result:
            cnt_dict["order_sanitize"] += 1
            cnt_dict_in_single_trace["order_sanitize"] += 1


        yield json.dumps({"stage": "order_sanitize", "result": order_sanitize_result}) + "\n"

        reachability_sanitize_result, reachability_sanitize_output_results = (
            passes.reachability_sanitize(ts_analyzer, trace, is_measure_token_cost)
            if neural_sanitize_strategy["reachability_sanitize"] else (True, {})
        )

        yield json.dumps({"stage": "reachability_sanitize", "result": reachability_sanitize_result, "reason": reachability_sanitize_output_results}) + "\n"

        if reachability_sanitize_result:
            cnt_dict["reachability_sanitize"] += 1
            cnt_dict_in_single_trace["reachability_sanitize"] += 1
        with open(sanitization_log_file_dir + "/" + case_name + "_" + str(trace_cnt)
                + "_reachability_sanitize.json", "w") as file:
            json.dump(reachability_sanitize_output_results, file, indent=4)

        if syntactic_check_result and functionality_sanitize_result and order_sanitize_result and reachability_sanitize_result:
            cnt_dict["final"] += 1
            cnt_dict_in_single_trace["final"] += 1
            
        trace_check_results.append({
            "trace": trace,
            "result": cnt_dict_in_single_trace
        })

        yield json.dumps({"stage": "trace_result", "result": cnt_dict_in_single_trace}) + "\n"

    output_results = {
        "original code": source_code,
        "analyzed code": lined_new_code,
        "trace_check_results": trace_check_results,
    }

    output_json_file_name = (Path(sanitization_log_file_dir) / (case_name + ".json"))
    with open(output_json_file_name, "w") as file:
        json.dump(output_results, file, indent=4)

    yield json.dumps({"stage": "completed", "final_result": cnt_dict}) + "\n"