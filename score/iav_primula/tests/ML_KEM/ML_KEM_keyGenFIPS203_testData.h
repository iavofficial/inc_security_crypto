// Generated from JSON file: ML-KEM-keyGen-FIPS203\internalProjection.json
#include <string>
#include <vector>

// Test case struct
struct ML_KEM_keyGen_TestCase {
    std::string d;
    bool deferred;
    std::string dk;
    std::string ek;
    int tcId;
    std::string z;
};

// Test group struct
struct ML_KEM_keyGen_TestGroup {
    std::string parameterSet;
    std::string testType;
    int tgId;
    std::vector<ML_KEM_keyGen_TestCase> tests;
};

extern std::vector<ML_KEM_keyGen_TestGroup> ML_KEM_keyGen_testGroups;
