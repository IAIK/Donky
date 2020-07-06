#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "pk.h"
#include "pk_debug.h"

#include "tinyxml2.h"
using namespace tinyxml2;

class XMLElementIsolate {
private:
    XMLElement* xml;
    int did_;
    Ecall<XMLElementIsolate, XMLElementIsolate*, const char*> ecall_first_child_element_;
    Ecall<XMLElementIsolate, const char*> ecall_get_text_;
public:
    XMLElementIsolate(int did, XMLElement* x) : xml(x),
        did_(did),
        ecall_first_child_element_(this, did_, &XMLElementIsolate::_FirstChildElement),
        ecall_get_text_(this, did_, &XMLElementIsolate::_GetText)  { 
    }

    const char* GetText() { return ecall_get_text_.InvokeDomainSwitch(); }
    XMLElementIsolate* FirstChildElement(const char* name) { return ecall_first_child_element_.InvokeDomainSwitch(name); }
    
private:
    const char* _GetText() {
      const char* text = xml->GetText();
      if (!text) {
        // Donky can handle c++ exceptions across ecalls
        // They will be masked to avoid information leakage
        throw "NULL exception";
      }
      return text;
    }
    XMLElementIsolate* _FirstChildElement(const char* name) { return new XMLElementIsolate(did_, xml->FirstChildElement(name)); }
};

class XMLDocumentIsolate {
private:
  int did_;
  Ecall<XMLDocumentIsolate, int, const char*> ecall_load_file_;
  Ecall<XMLDocumentIsolate, XMLElementIsolate*, const char*> ecall_first_child_element_;
  Ecall<XMLDocumentIsolate, int, const int*> ecall_malicious_;
  XMLDocument* doc;

public:
  XMLDocumentIsolate(int did) : 
    did_(did),
    ecall_load_file_(this, did_, &XMLDocumentIsolate::_LoadFile),
    ecall_first_child_element_(this, did_, &XMLDocumentIsolate::_FirstChildElement),
    ecall_malicious_(this, did_, &XMLDocumentIsolate::_Malicious) {
    doc = new XMLDocument();
  }
  XMLDocumentIsolate() : XMLDocumentIsolate(pk_domain_create(0)) {
  }

  ~XMLDocumentIsolate() { delete doc; }
  void LoadFile(const char *fname) { ecall_load_file_.InvokeDomainSwitch(fname); }
  XMLElementIsolate* FirstChildElement(const char* name) { return ecall_first_child_element_.InvokeDomainSwitch(name); }
  int Malicious(const int* ptr) { return ecall_malicious_.InvokeDomainSwitch(ptr); }
  
private:
  int _LoadFile(const char* fname) { doc->LoadFile(fname); return 0; }
  XMLElementIsolate* _FirstChildElement(const char* name) { return new XMLElementIsolate(did_, doc->FirstChildElement(name)); }
  int _Malicious(const int* ptr) { return *ptr; }
};

#if 0
  XMLDocument doc;
#else
  XMLDocumentIsolate doc;
#endif

int global = 1111;
int main(int argc, char* argv[]) {

  doc.LoadFile( "test.xml" );
  
  // Test normal XML parsing
  const char* title = doc.FirstChildElement( "Tests" )->FirstChildElement( "Test" )->FirstChildElement("Name")->GetText();
  printf( "Name of test (1): %s\n", title );

  // Test c++ exceptions
  try {
    printf( "Should not come here: %s\n", doc.FirstChildElement( "Tests" )->GetText() );
  } catch (...) {
    printf( "XML element text was NULL\n");
  }

  // Test allowed access. Our global variable is unprotected.
  printf( "Should succeed...\n");
  printf( "Unprotected global is: %d\n", doc.Malicious(&global));

  // Test malicious access. Our stack variable belongs to protected stack
  // of root domain. Only works for systems with MPK!!
  int secret = 1234;
  printf( "Should fail...\n");
  printf( "Secret is: %d\n", doc.Malicious(&secret));

  return 0;
}
