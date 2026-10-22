// Generated from JSON file: ML-DSA-keyGen-FIPS204\internalProjection.json
#include <string>
#include <vector>

// Test case struct
struct ML_DSA_keyGen_TestCase
{
  bool deferred;
  std::string pk;
  std::string seed;
  std::string sk;
  int tcId;
};

// Test group struct
struct ML_DSA_keyGen_TestGroup
{
  std::string parameterSet;
  std::string testType;
  int tgId;
  std::vector<ML_DSA_keyGen_TestCase> tests;
};

extern std::vector<ML_DSA_keyGen_TestGroup> ML_DSA_keyGen_testGroups;