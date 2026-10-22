// Generated from JSON file: ML-KEM-encapDecap-FIPS203-tr1\internalProjection.json
#include <string>
#include <vector>

// Test case struct
struct ML_KEM_encapDecap_tr1_TestCase
{

  std::string c;
  std::string d;
  bool deferred;
  std::string dk;
  std::string ek;
  std::string k;
  std::string m;
  std::string reason;
  int tcId;
  bool testPassed;
  std::string z;
};

// Test group struct
struct ML_KEM_encapDecap_tr1_Testgroup
{
  std::string function;
  std::string keyFormat;
  std::string parameterSet;
  std::string testType;
  int tgId;
  std::vector<ML_KEM_encapDecap_tr1_TestCase> tests;
};

extern std::vector<ML_KEM_encapDecap_tr1_Testgroup> ML_KEM_encapDecap_tr1_testGroups;
