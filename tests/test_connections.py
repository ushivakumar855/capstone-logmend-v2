import os
from logmend.agent.ollama_router import OllamaRouter
from logmend.database.neo4j_router import db_router

def test_ollama():
    print("\n" + "="*50)
    print("🤖 TESTING OLLAMA CONNECTION")
    print("="*50)
    router = OllamaRouter()
    print(f"Target Model: {router.model}")
    
    try:
        reply = router.generate_response(
            system_prompt="You are a system diagnostic tool.",
            user_prompt="Say exactly: 'Ollama is online and Gemma4:26b is responding!'"
        )
        if reply:
            print(f"[Success] Agent replied: {reply}")
        else:
            print("[Failed] No response received from Ollama.")
    except Exception as e:
        print(f"[Failed] Connection error: {e}")

def test_neo4j():
    print("\n" + "="*50)
    print("🕸️  TESTING NEO4J DUAL-ROUTER")
    print("="*50)
    
    # 1. Test BETH (Expected to Succeed)
    print("[*] Pinging BETH instance...")
    try:
        result = db_router.query("beth", "RETURN 'BETH IS ALIVE' AS Status")
        if result:
            print(f"[Success] Database responded: {result[0]['Status']}")
    except Exception as e:
        print(f"[Error] BETH query failed: {e}")

    # 2. Test THEIA (Expected to Fail since it's stopped)
    print("\n[*] Pinging THEIA instance (Expected to fail right now)...")
    try:
        result = db_router.query("darpa", "RETURN 'THEIA IS ALIVE' AS Status")
        if result:
            print(f"[Unexpected] THEIA responded: {result[0]['Status']}")
    except Exception as e:
        print(f"[Expected Behavior] THEIA query blocked/failed: {e}")

if __name__ == "__main__":
    test_neo4j()
    test_ollama()
    print("\n[System] Diagnostics complete.\n")