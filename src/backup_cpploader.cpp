#include <unicorn/unicorn.h>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include "AflUnicornEngine.h"
#include "UnicornSimpleHeap.h"

const uint64_t start_address = 0xaaaaa4e8;
const uint64_t end_address = 0xaaaaa5bc;
/*const uint64_t _malloc = 0x8048320;
const uint64_t _free = 0x8048310;*/

UnicornSimpleHeap* uc_heap;

static void unicorn_hook_instruction(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){
  if(address == _malloc){ // printf
      uint32_t esp;
      uc_reg_read(uc, UC_X86_REG_ESP, &esp);

      uint32_t size, ret_addr;
      uc_mem_read(uc, esp+4, &size, sizeof(size));
      uc_mem_read(uc, esp, &ret_addr, sizeof(ret_addr));
      uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);

      uint32_t eax = uc_heap->malloc(size);
      uc_reg_write(uc, UC_X86_REG_EAX, &eax);

      esp += 4;
      uc_reg_write(uc, UC_X86_REG_ESP, &esp);
  }

  if(address == _free){ // printf
      uint32_t esp;
      uc_reg_read(uc, UC_X86_REG_ESP, &esp);

      uint32_t addr, ret_addr;
      uc_mem_read(uc, esp+4, &addr, sizeof(addr));
      uc_mem_read(uc, esp, &ret_addr, sizeof(ret_addr));
      uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);

      uint32_t eax = uc_heap->free(addr);
      uc_reg_write(uc, UC_X86_REG_EAX, &eax);

      esp += 4;
      uc_reg_write(uc, UC_X86_REG_ESP, &esp);
  }
}

int main(int argc, char* argv[]){
    if(argc < 4){
        std::cerr << "Usage : ./unicorn_loader CONTEXT_DIR INPUT_DIR ENABLE_TRACE(true|false) DEBUG_TRACE(true|false)" << std::endl;
        return 0;
    }
    const std::string context_dir = argv[1];
    //const std::string input_dir = argv[4];
    bool enable_trace = strcmp(argv[2], "true")? false : true;
    bool debug_trace = strcmp(argv[3], "true")? false : true;

    AflUnicornEngine afl = AflUnicornEngine(context_dir, enable_trace, debug_trace);
    uc_heap = new UnicornSimpleHeap(afl.get_uc(), true);

    /*uc_hook trace;
    uc_hook_add(afl.get_uc(), &trace, UC_HOOK_CODE, reinterpret_cast<void*>(unicorn_hook_instruction), NULL, 1, 0);*/

    //printf("hey");
    //std::ifstream ifs(input_dir);
    //std::string content( (std::istreambuf_iterator<char>(ifs) ),
    //                   (std::istreambuf_iterator<char>()    ) );
    //printf("%s", content);
    def is_int(x):
        try:
            int(X)
            return True
        except ValueError:
            return False



    //try{
    uc_err err = uc_emu_start(afl.get_uc(), start_address, end_address, 0, 0);
    /*}
    catch(int n){
      afl.dump_regs();
      afl.force_crash(err);
      return 0;
    }*/

    afl.dump_regs();
}
