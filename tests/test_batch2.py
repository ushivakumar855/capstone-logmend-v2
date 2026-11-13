import json
from logmend.tools.description_generator import DescriptionGenerator
from logmend.tools.rule_matcher import RuleMatcher
from logmend.tools.ttp_mapper import TTPMapper

def run_tests():
    # Our mock 4-part identifier for BETH
    beth_identifier = {
        "pid": 5555, 
        "host_name": "ubuntu-host", 
        "process_name": "bash", 
        "parent_pid": 111
    }

    print("\n" + "="*50)
    print("📝 TESTING DESCRIPTION GENERATOR (T3)")
    print("="*50)
    desc_gen = DescriptionGenerator()
    result1 = desc_gen.generate_description(beth_identifier, "beth")
    print(json.dumps(json.loads(result1), indent=2))

    print("\n" + "="*50)
    print("🛡️  TESTING RULE MATCHER (T2)")
    print("="*50)
    rule_matcher = RuleMatcher()
    result2 = rule_matcher.match_rules(beth_identifier, "beth")
    print(json.dumps(json.loads(result2), indent=2))

    print("\n" + "="*50)
    print("🧠 TESTING TTP MAPPER (T6)")
    print("="*50)
    ttp_mapper = TTPMapper()
    result3 = ttp_mapper.map_ttp(beth_identifier, "beth")
    print(json.dumps(json.loads(result3), indent=2))

if __name__ == "__main__":
    run_tests()