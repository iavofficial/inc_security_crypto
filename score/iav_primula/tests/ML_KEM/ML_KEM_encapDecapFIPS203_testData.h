// Generated from JSON file: ML-KEM-encapDecap-FIPS203\internalProjection.json
#include <string>
#include <vector>

// Test case struct
struct ML_KEM_encapDecap_TestCase {
    std::string c;
    bool deferred;
    std::string dk;
    std::string ek;
    std::string k;
    std::string m;
    std::string reason;
    int tcId;
    bool testPassed;
};

// Test group struct
struct ML_KEM_encapDecap_Testgroup {
    std::string function;
    std::string parameterSet;
    std::string testType;
    int tgId;
    std::vector<ML_KEM_encapDecap_TestCase> tests;
};

extern std::vector<ML_KEM_encapDecap_Testgroup> ML_KEM_encapDecap_testGroups;
