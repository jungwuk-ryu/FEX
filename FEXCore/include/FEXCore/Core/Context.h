// SPDX-License-Identifier: MIT
#pragma once
#include <functional>
#include <stdint.h>

#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/Core/CPUID.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/IntervalList.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/Utils/WritePriorityMutex.h>

namespace FEXCore {
struct HostFeatures;
class ThunkHandler;
} // namespace FEXCore

namespace FEXCore::Core {
struct CPUState;
struct CpuStateFrame;
struct InternalThreadState;
} // namespace FEXCore::Core

namespace FEXCore::HLE {
class SyscallHandler;
} // namespace FEXCore::HLE

namespace FEXCore::IR {
class IREmitter;
} // namespace FEXCore::IR

namespace FEXCore::Context {

enum OperatingMode {
  MODE_32BIT,
  MODE_64BIT,
};

using CodeRangeInvalidationFn = std::function<void(uint64_t start, uint64_t Length)>;

using CustomIREntrypointHandler = std::function<void(uintptr_t Entrypoint, IR::IREmitter*)>;

using ExitHandler = std::function<void(Core::InternalThreadState* Thread)>;

// Private Darwin embedding entry: AAPCS register arguments with custom x18
// already active on both entry and return. Never call this as a Mach-O C API.
using CustomDispatchEntry = void (*)(Core::CpuStateFrame* Frame);

class Context {
public:
  virtual ~Context() = default;
  /**
   * @brief [[threadsafe]] Create a new FEXCore context object
   *
   * This is necessary to do when running threaded contexts
   *
   * @return a new context object
   */
  FEX_DEFAULT_VISIBILITY static fextl::unique_ptr<FEXCore::Context::Context> CreateNewContext(const FEXCore::HostFeatures& Features);

  /**
   * @brief Allows setting up in memory code and other things prior to launchign code execution
   *
   * @param CTX The context that we created
   * @param Loader The loader that will be doing all the code loading
   *
   * @return true if we loaded code
   */
  FEX_DEFAULT_VISIBILITY virtual bool InitCore() = 0;

  /**
   * @brief Configure a uniform low guest-address mapping before InitCore.
   *
   * Guest addresses below LowAddressLimit are backed at HostOffset + guest;
   * all other guest addresses remain identity mapped.  Passing two zeroes
   * disables the mapping. The Darwin embedding's generated transform requires
   * LowAddressLimit == 4 GiB; implementations reject other nonzero limits,
   * non-power-of-two host offsets and arithmetic overflow.
   */
  FEX_DEFAULT_VISIBILITY virtual bool SetGuestMemoryMapping(uint64_t LowAddressLimit, uint64_t HostOffset) = 0;

  /**
   * @brief Enable an embedding-owned execution-stop contract before InitCore.
   *
   * The optional transition bitmap contains one bit per guest page.  A set bit
   * makes the dispatcher return before decoding or executing that page.  Three
   * zero arguments enable syscall, guest-exception, and per-thread suspend
   * stops without a transition bitmap.
   */
  FEX_DEFAULT_VISIBILITY virtual bool SetExternalExecutionStops(
    const uint64_t* TransitionBitmap, uint64_t HighestUserAddress, uint32_t TransitionPageShift) = 0;

  /** Optional Darwin embedding contract, immutable after InitCore. The callback
   * selects custom/system x18 mode using the operating system, preserves the
   * normal host ABI, and must not throw or call other OS services in custom mode.
   * The embedding owns signal/nonlocal-exit handling and supplies each frame's
   * authenticated, nonzero CustomABIValue before execution, without concurrent
   * mutation. External stops must be configured;
   * ExecuteThread/HandleCallback reject an unset value without entering JIT and
   * report InvalidCustomABI through ExternalStop. A null callback retains
   * ordinary host mode. */
  FEX_DEFAULT_VISIBILITY virtual bool SetCustomABITransition(void (*Transition)(bool)) = 0;

  /** Prepare a resource-free generated entry for an already-custom caller.
   * Returns null unless the custom-ABI/external-stop contract is configured
   * and this thread has a nonzero embedding-authenticated CustomABIValue.
   * Call in system mode before dispatch. The caller must exclusively own the
   * thread and pin context, mappings and code until the generated entry returns
   * or its execution is explicitly consumed by fault reconstruction. No FEX
   * execute/compiler activation may survive on the private stack during a
   * native interval. Reacquire ownership and use this
   * immutable dispatcher entry, not a TB address, on every fresh execution. */
  FEX_DEFAULT_VISIBILITY virtual CustomDispatchEntry PrepareCustomDispatch(
    FEXCore::Core::InternalThreadState* Thread) = 0;

  /**
   * @brief Executes the supplied thread context on the current thread until a return is requested
   */
  FEX_DEFAULT_VISIBILITY virtual void ExecuteThread(FEXCore::Core::InternalThreadState* Thread) = 0;

  FEX_DEFAULT_VISIBILITY virtual bool CheckIfBlockIsCacheable(FEXCore::Core::InternalThreadState& Thread, uint64_t GuestRIP, uint64_t MaxInst) = 0;
  FEX_DEFAULT_VISIBILITY virtual void CompileRIP(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP) = 0;
  FEX_DEFAULT_VISIBILITY virtual void CompileRIPCount(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) = 0;

  FEX_DEFAULT_VISIBILITY virtual void HandleCallback(FEXCore::Core::InternalThreadState* Thread, uint64_t RIP) = 0;

  FEX_DEFAULT_VISIBILITY virtual bool IsAddressInCurrentBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) = 0;
  FEX_DEFAULT_VISIBILITY virtual bool IsHostAddressInCurrentBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) = 0;
  FEX_DEFAULT_VISIBILITY virtual bool IsCurrentBlockSingleInst(FEXCore::Core::InternalThreadState* Thread) = 0;
  FEX_DEFAULT_VISIBILITY virtual uint64_t GetGuestBlockEntry(FEXCore::Core::InternalThreadState* Thread) = 0;

  ///< State reconstruction helpers
  ///< Reconstructs the guest RIP from the passed in thread context and related Host PC.
  FEX_DEFAULT_VISIBILITY virtual uint64_t RestoreRIPFromHostPC(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC) = 0;
  /**
   * @brief Reconstructs a compacted EFLAGS from FEX's internal EFLAG representation.
   *
   * @param Thread The thread getting the state reconstructed
   * @param WasInJIT If the code was in the JIT at the time.
   * @param HostGPRs The host Arm64 GPRs at the point of state inside the JIT.
   * @param PSTATE The Arm64 PState value.
   *
   * If WasInJIT is false then HostGPRs and PSTATE is ignored, with the assumption that the FEX JIT has already stored all state in to the
   * ThreadState object.
   *
   * @return x86 EFLAGS reconstructed
   */
  FEX_DEFAULT_VISIBILITY virtual uint32_t
  ReconstructCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, bool WasInJIT, const uint64_t* HostGPRs, uint64_t PSTATE) = 0;
  ///< Sets FEX's internal EFLAGS representation to the passed in compacted form.
  FEX_DEFAULT_VISIBILITY virtual void SetFlagsFromCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, uint32_t EFLAGS) = 0;

  FEX_DEFAULT_VISIBILITY virtual void
  ReconstructXMMRegisters(const FEXCore::Core::InternalThreadState* Thread, __uint128_t* XMM_Low, __uint128_t* YMM_High) = 0;
  FEX_DEFAULT_VISIBILITY virtual void
  SetXMMRegistersFromState(FEXCore::Core::InternalThreadState* Thread, const __uint128_t* XMM_Low, const __uint128_t* YMM_High) = 0;

  /**
   * @brief Create a new thread object that doesn't inherit any state.
   * Used to create FEX thread objects in preparation for creating a true OS thread.
   *
   * @param NewThreadState The thread state to inherit from if not nullptr.
   *
   * @return A new InternalThreadState object for using with a new guest thread.
   */

  FEX_DEFAULT_VISIBILITY virtual FEXCore::Core::InternalThreadState* CreateThread(const FEXCore::Core::CPUState* NewThreadState = nullptr) = 0;

  FEX_DEFAULT_VISIBILITY virtual void DestroyThread(FEXCore::Core::InternalThreadState* Thread) = 0;
#ifndef _WIN32
  FEX_DEFAULT_VISIBILITY virtual void LockBeforeFork(FEXCore::Core::InternalThreadState* Thread) {}
  FEX_DEFAULT_VISIBILITY virtual void UnlockAfterFork(FEXCore::Core::InternalThreadState* Thread, bool Child) {}
#endif
  FEX_DEFAULT_VISIBILITY virtual void SetSignalDelegator(FEXCore::SignalDelegator* SignalDelegation) = 0;
  FEX_DEFAULT_VISIBILITY virtual void SetSyscallHandler(FEXCore::HLE::SyscallHandler* Handler) = 0;
  FEX_DEFAULT_VISIBILITY virtual void SetThunkHandler(FEXCore::ThunkHandler* Handler) = 0;

  FEX_DEFAULT_VISIBILITY virtual FEXCore::CPUID::FunctionResults RunCPUIDFunction(uint32_t Function, uint32_t Leaf) = 0;
  FEX_DEFAULT_VISIBILITY virtual FEXCore::CPUID::XCRResults RunXCRFunction(uint32_t Function) = 0;
  FEX_DEFAULT_VISIBILITY virtual FEXCore::CPUID::FunctionResults RunCPUIDFunctionName(uint32_t Function, uint32_t Leaf, uint32_t CPU) = 0;

  virtual void InitDiskCache() = 0;

  virtual AbstractCodeCache& GetCodeCache() = 0;
  virtual void SetCodeMapWriter(fextl::unique_ptr<CodeMapWriter>) = 0;
  virtual void FlushAndCloseCodeMap() = 0;

  FEX_DEFAULT_VISIBILITY virtual void ClearCodeCache(FEXCore::Core::InternalThreadState* Thread, bool NewCodeBuffer = true) = 0;
  FEX_DEFAULT_VISIBILITY virtual void InvalidateCodeBuffersCodeRange(uint64_t Start, uint64_t Length) = 0;
  FEX_DEFAULT_VISIBILITY virtual void
  InvalidateThreadCachedCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) = 0;
  FEX_DEFAULT_VISIBILITY virtual FEXCore::Utils::WritePriorityMutex::Mutex& GetCodeInvalidationMutex() = 0;

  FEX_DEFAULT_VISIBILITY virtual void
  ConfigureAOTGen(FEXCore::Core::InternalThreadState* Thread, fextl::set<uint64_t>* ExternalBranches, uint64_t SectionMaxAddress) = 0;

  /**
   * @brief Checks if a PC is inside any code buffer used by the thread's JIT.
   *
   * @param Thread Which thread's code buffers to check inside of.
   * @param Address The PC to check against.
   *
   * @return true if PC is inside the thread's code buffers.
   */
  FEX_DEFAULT_VISIBILITY virtual bool IsAddressInCodeBuffer(FEXCore::Core::InternalThreadState* Thread, uintptr_t Address) const = 0;

  /**
   * @brief Informs the context if hardware TSO is supported.
   * Once hardware TSO is enabled, then TSO emulation through atomics is disabled and relies on the hardware.
   *
   * @param HardwareTSOSupported If the hardware supports the TSO memory model or not.
   */
  FEX_DEFAULT_VISIBILITY virtual void SetHardwareTSOSupport(bool HardwareTSOSupported) = 0;

  /**
   * @brief Enable exiting the JIT when HLT is hit.
   *
   * This is to workaround a bug in Wine's longjump function which breaks our unittests.
   *
   */
  FEX_DEFAULT_VISIBILITY virtual void EnableExitOnHLT() = 0;

  /**
   * @brief Adds a new Thunk trampoline handler
   *
   * @param Entrypoint The guest PC that the custom thunk trampoline IR handler will be installed at.
   * @param GuestThunkEntrypoint The thunk entrypoint that the IR handler will redirect to.
   */
  FEX_DEFAULT_VISIBILITY virtual void AddThunkTrampolineIRHandler(uintptr_t Entrypoint, uintptr_t GuestThunkEntrypoint) = 0;

  /**
   * @brief Adds additional per-instruction granularity TSO enable/disable information for the given range.
   *
   * @param ValidRanges The set of address ranges covered by this information
   * @param Instructions The set of instruction addresses within the given ranges for which TSO should be enabled
   */
  FEX_DEFAULT_VISIBILITY virtual void AddForceTSOInformation(const IntervalList<uint64_t>& ValidRanges, fextl::set<uint64_t>&& Instructions) = 0;

  FEX_DEFAULT_VISIBILITY virtual void RemoveForceTSOInformation(uint64_t Address, uint64_t Size) = 0;

  FEX_DEFAULT_VISIBILITY virtual void MarkMonoDetected() = 0;

  FEX_DEFAULT_VISIBILITY virtual void MarkMonoBackpatcherBlock(uint64_t BlockEntry) = 0;
private:
};
} // namespace FEXCore::Context
