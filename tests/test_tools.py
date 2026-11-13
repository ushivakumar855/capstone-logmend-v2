import json
from logmend.tools.log_parser import LogParser
from logmend.tools.context_retriever import ContextRetriever

def test_log_parser():
    print("\n" + "="*50)
    print("🛠️ TESTING LOG PARSER (T1)")
    print("="*50)
    parser = LogParser()
    
    # Mock DARPA JSON
    darpa_mock = '{"uuid": "1234-abcd", "type": "firefox", "cmdLine": "firefox -sh", "ppid": 100}'
    print("[*] Parsing DARPA mock...")
    print(json.dumps(parser.parse_record(darpa_mock), indent=2))
    
    # Mock BETH JSON
    beth_mock = '{"processId": 5555, "hostName": "ubuntu-host", "processName": "bash", "parentProcessId": 111, "sus": 1}'
    print("\n[*] Parsing BETH mock...")
    parsed_beth = parser.parse_record(beth_mock)
    print(json.dumps(parsed_beth, indent=2))
    
    return parsed_beth

def test_context_retriever(beth_identifier):
    print("\n" + "="*50)
    print("🕸️ TESTING CONTEXT RETRIEVER (T5)")
    print("="*50)
    retriever = ContextRetriever()
    
    # We know the BETH database is running from your previous test.
    # It will likely return "Graph context not found" because PID 5555 doesn't exist, 
    # but returning that safely without crashing proves the DB routing and 4-part key work!
    print(f"[*] Querying BETH DB for PID: {beth_identifier['pid']} on Host: {beth_identifier['hostName']}...")
    
    # Map the parsed JSON to the identifier dictionary the tool expects
    identifier = {
        "pid": beth_identifier["pid"],
        "host_name": beth_identifier["hostName"],
        "process_name": beth_identifier["processName"],
        "parent_pid": beth_identifier["parentPid"]
    }
    
    result = retriever.get_process_context(identifier, "beth")
    print(json.dumps(json.loads(result), indent=2))

if __name__ == "__main__":
    parsed_beth = test_log_parser()
    if parsed_beth:
        test_context_retriever(parsed_beth)