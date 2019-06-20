#include <unicorn/unicorn.h>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <iostream> //NEW LIBRARIES ADDED (THIS AND NEXT THREE) FOR FILEIO
#include <fstream>
#include <string>
#include "AflUnicornEngine.h"
#include "UnicornSimpleHeap.h"

const uint64_t start_address = 0xaaaaa4e8;
const uint64_t end_address = 0xaaaaa5bc;
/*const uint64_t _malloc = 0x8048320;
const uint64_t _free = 0x8048310;*/

UnicornSimpleHeap* uc_heap;

static void unicorn_hook_instruction(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){
    return;
}

int main(int argc, char* argv[]){
  if(argc < 5){
      std::cerr << "Usage : ./unicorn_loader CONTEXT_DIR INPUT_DIR ENABLE_TRACE(true|false) DEBUG_TRACE(true|false)" << std::endl;
      return 0;
  }
  const std::string context_dir = argv[1];
  bool enable_trace = strcmp(argv[3], "true")? false : true;
  bool debug_trace = strcmp(argv[4], "true")? false : true;

  AflUnicornEngine afl = AflUnicornEngine(context_dir, enable_trace, debug_trace);
  uc_heap = new UnicornSimpleHeap(afl.get_uc(), true);

  /*uc_hook trace;
  uc_hook_add(afl.get_uc(), &trace, UC_HOOK_CODE, reinterpret_cast<void*>(unicorn_hook_instruction), NULL, 1, 0);*/


  //Execute 1 instruction for fork???
  uc_emu_start(afl.get_uc(), start_address, end_address, 0, 1);


  printf("Loading input from %s\n", argv[2]);
  //ifstream input;
  //input.open ("example.bin", ios::in | ios::binary);
  //printf("hey");
  std::string line;
  std::string total;
  std::ifstream input(argv[2]);
  if(input.is_open()){
    while(getline(input, line)){
      total.append(line);
      total.append("\n");
    }
    input.close();
  }
  else{
    _error("Opening intput failed");
  }

  uint32_t buff_addr = uc_heap->malloc(total.length());
  uc_reg_write(afl.get_uc(), buff_addr, &total);
  uc_reg_write(afl.get_uc(), UC_ARM_REG_R1, &buff_addr);

  uint32_t len = total.length();
  uint32_t stack_ptr;
  uc_reg_read(afl.get_uc(), UC_ARM_REG_SP, &stack_ptr);
  uc_mem_write(afl.get_uc(), stack_ptr+8, &len, 4);
  uc_mem_write(afl.get_uc(), stack_ptr+16, &total, len);


  //std::cout << total;
  //std::string content( (std::istreambuf_iterator<char>(ifs) ),
  //                   (std::istreambuf_iterator<char>()    ) );
  //printf("%s", argv[2]);

  //try{
  //uc_emu_start(afl.get_uc(), start_address, end_address, 0, 0);
  /*}
  catch(int n){
    afl.dump_regs();
    afl.force_crash(err);
    return 0;
  }*/

  uint64_t eip = start_address;
     while(eip != end_address){
         uc_err err = uc_emu_start(afl.get_uc(), eip, end_address, 0, 0);
         if(err){
             afl.dump_regs();
             afl.force_crash(err);
             return 0;
         }
         uc_reg_read(afl.get_uc(), UC_ARM_REG_PC, &eip);
       }

  afl.dump_regs();
}
