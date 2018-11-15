/*
 * Copyright (C) 2015 Cybernetica
 *
 * Research/Commercial License Usage
 * Licensees holding a valid Research License or Commercial License
 * for the Software may use this file according to the written
 * agreement between you and Cybernetica.
 *
 * GNU General Public License Usage
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl-3.0.html.
 *
 * For further information, please contact us at sharemind@cyber.ee.
 */

#include <cassert>
#include <LogHard/Logger.h>
#include <sharemind/ExecutionProfiler.h>
#include <sharemind/libemulator_protocols/Binary.h>
#include <sharemind/libemulator_protocols/Nullary.h>
#include <sharemind/libemulator_protocols/Ternary.h>
#include <sharemind/libemulator_protocols/Unary.h>
#include <sharemind/module-apis/api_0x1.h>
#include <sharemind/visibility.h>
#include "AbyModule.h"
#include "AbyPDPI.h"
#include "Syscalls/Common.h"
#include "Syscalls/CoreSyscalls.h"
#include "Syscalls/Meta.h"


namespace {

using namespace sharemind;

SHAREMIND_MODULE_API_0x1_SYSCALL(get_domain_name,
                                 args, num_args, refs, crefs,
                                 returnValue, c)
{
    if (!SyscallArgs<1u, true, 0u, 0u>::check(num_args, refs, crefs, returnValue))
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

    VMHandles handles;
    if (!handles.get(c, args))
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

    try {
        AbyPDPI * const pdpi = static_cast<AbyPDPI*>(handles.pdpiHandle);
        const std::string & pdName = pdpi->pdName();

        const uint64_t mem_size = pdName.size() + 1u;
        const uint64_t mem_hndl = (* c->publicAlloc)(c, mem_size);
        char * const mem_ptr = static_cast<char *>((* c->publicMemPtrData)(c, mem_hndl));
        strncpy(mem_ptr, pdName.c_str(), mem_size);
        returnValue[0u].uint64[0u] = mem_hndl;

        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (...) {
        return catchModuleApiErrors ();
    }
}

} // anonymous namespace


extern "C" {

SHAREMIND_MODULE_API_MODULE_INFO("aby",
                                 0x00010000,   /* Version 0.1.0.0 */
                                 0x1);         /* Support API version 1. */

SHAREMIND_MODULE_API_0x1_INITIALIZER(c) SHAREMIND_VISIBILITY_DEFAULT;
SHAREMIND_MODULE_API_0x1_INITIALIZER(c) {
    assert(c);

    const SharemindModuleApi0x1Facility * const flogger =
            c->getModuleFacility(c, "Logger");

    if (!flogger || !flogger->facility)
        return SHAREMIND_MODULE_API_0x1_MISSING_FACILITY;

    const SharemindModuleApi0x1Facility * const fprofiler =
            c->getModuleFacility(c, "Profiler");

    if (!fprofiler || !fprofiler->facility)
        return SHAREMIND_MODULE_API_0x1_MISSING_FACILITY;

    const LogHard::Logger & logger =
        *static_cast<LogHard::Logger *>(flogger->facility);

    sharemind::ExecutionProfiler & profiler =
        *static_cast<sharemind::ExecutionProfiler *>(fprofiler->facility);

    /*
     Initialize the module handle
    */
    try {
        c->moduleHandle = new sharemind::AbyModule(logger, profiler);
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (...) {
        return catchModuleApiErrors ();
    }
}

SHAREMIND_MODULE_API_0x1_DEINITIALIZER(c) SHAREMIND_VISIBILITY_DEFAULT;
SHAREMIND_MODULE_API_0x1_DEINITIALIZER(c) {
    assert(c);
    assert(c->moduleHandle);

    static_assert(std::is_nothrow_destructible<sharemind::AbyModule>::value,
                  "");
    delete static_cast<sharemind::AbyModule *>(c->moduleHandle);
    #ifndef NDEBUG
    c->moduleHandle = nullptr; // Not needed, but may help debugging.
    #endif
}


/*
 * Define wrappers for named syscalls
 */
NAMED_SYSCALL_WRAPPER(new_uint8_vec, new_vec<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(new_uint16_vec, new_vec<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(new_uint32_vec, new_vec<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(new_uint64_vec, new_vec<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(init_uint8_vec, init_vec<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(init_uint16_vec, init_vec<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(init_uint32_vec, init_vec<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(init_uint64_vec, init_vec<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(set_shares_uint8_vec, set_shares<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(set_shares_uint16_vec, set_shares<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(set_shares_uint32_vec, set_shares<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(set_shares_uint64_vec, set_shares<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(get_shares_uint8_vec, get_shares<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(get_shares_uint16_vec, get_shares<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(get_shares_uint32_vec, get_shares<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(get_shares_uint64_vec, get_shares<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(fill_uint8_vec, fill_vec<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(fill_uint16_vec, fill_vec<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(fill_uint32_vec, fill_vec<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(fill_uint64_vec, fill_vec<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(assign_uint8_vec, assign_vec<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(assign_uint16_vec, assign_vec<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(assign_uint32_vec, assign_vec<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(assign_uint64_vec, assign_vec<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(delete_uint8_vec, delete_vec<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(delete_uint16_vec, delete_vec<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(delete_uint32_vec, delete_vec<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(delete_uint64_vec, delete_vec<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(load_uint8_vec, load_vec<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(load_uint16_vec, load_vec<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(load_uint32_vec, load_vec<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(load_uint64_vec, load_vec<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(store_uint8_vec, store_vec<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(store_uint16_vec, store_vec<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(store_uint32_vec, store_vec<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(store_uint64_vec, store_vec<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(classify_uint8_vec, classify_vec<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(classify_uint16_vec, classify_vec<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(classify_uint32_vec, classify_vec<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(classify_uint64_vec, classify_vec<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(declassify_uint8_vec, declassify_vec<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(declassify_uint16_vec, declassify_vec<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(declassify_uint32_vec, declassify_vec<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(declassify_uint64_vec, declassify_vec<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(get_type_size_uint8, get_type_size<aby_uint8_t>)
NAMED_SYSCALL_WRAPPER(get_type_size_uint16, get_type_size<aby_uint16_t>)
NAMED_SYSCALL_WRAPPER(get_type_size_uint32, get_type_size<aby_uint32_t>)
NAMED_SYSCALL_WRAPPER(get_type_size_uint64, get_type_size<aby_uint64_t>)
NAMED_SYSCALL_WRAPPER(add_arith_uint8_vec, binary_arith_vec<aby_uint8_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_arith_uint16_vec, binary_arith_vec<aby_uint16_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_arith_uint32_vec, binary_arith_vec<aby_uint32_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_arith_uint64_vec, binary_arith_vec<aby_uint64_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_arith_uint8_vec, binary_arith_vec<aby_uint8_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_arith_uint16_vec, binary_arith_vec<aby_uint16_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_arith_uint32_vec, binary_arith_vec<aby_uint32_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_arith_uint64_vec, binary_arith_vec<aby_uint64_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_arith_uint8_vec, binary_arith_vec<aby_uint8_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_arith_uint16_vec, binary_arith_vec<aby_uint16_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_arith_uint32_vec, binary_arith_vec<aby_uint32_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_arith_uint64_vec, binary_arith_vec<aby_uint64_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_bool_uint8_vec, binary_arith_vec<aby_uint8_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_bool_uint16_vec, binary_arith_vec<aby_uint16_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_bool_uint32_vec, binary_arith_vec<aby_uint32_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_bool_uint64_vec, binary_arith_vec<aby_uint64_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(and_bool_uint8_vec, binary_arith_vec<aby_uint8_t, BitwiseAndProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(and_bool_uint16_vec, binary_arith_vec<aby_uint16_t, BitwiseAndProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(and_bool_uint32_vec, binary_arith_vec<aby_uint32_t, BitwiseAndProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(and_bool_uint64_vec, binary_arith_vec<aby_uint64_t, BitwiseAndProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(choose_bool_uint8_vec, ternary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, aby_uint8_t, ObliviousChoiceProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(choose_bool_uint16_vec, ternary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, aby_uint16_t, ObliviousChoiceProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(choose_bool_uint32_vec, ternary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, aby_uint32_t, ObliviousChoiceProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(choose_bool_uint64_vec, ternary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, aby_uint64_t, ObliviousChoiceProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(eq_bool_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, EqualityProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(eq_bool_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, EqualityProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(eq_bool_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, EqualityProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(eq_bool_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, EqualityProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gt_bool_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, GreaterThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gt_bool_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, GreaterThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gt_bool_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, GreaterThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gt_bool_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, GreaterThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gte_bool_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, GreaterThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gte_bool_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, GreaterThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gte_bool_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, GreaterThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gte_bool_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, GreaterThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lt_bool_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, LessThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lt_bool_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, LessThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lt_bool_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, LessThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lt_bool_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, LessThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lte_bool_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, LessThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lte_bool_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, LessThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lte_bool_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, LessThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lte_bool_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, LessThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_bool_uint8_vec, binary_arith_vec<aby_uint8_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_bool_uint16_vec, binary_arith_vec<aby_uint16_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_bool_uint32_vec, binary_arith_vec<aby_uint32_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_bool_uint64_vec, binary_arith_vec<aby_uint64_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_bool_uint8_vec, binary_arith_vec<aby_uint8_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_bool_uint16_vec, binary_arith_vec<aby_uint16_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_bool_uint32_vec, binary_arith_vec<aby_uint32_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_bool_uint64_vec, binary_arith_vec<aby_uint64_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(xor_bool_uint8_vec, binary_arith_vec<aby_uint8_t, BitwiseXorProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(xor_bool_uint16_vec, binary_arith_vec<aby_uint16_t, BitwiseXorProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(xor_bool_uint32_vec, binary_arith_vec<aby_uint32_t, BitwiseXorProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(xor_bool_uint64_vec, binary_arith_vec<aby_uint64_t, BitwiseXorProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_yao_uint8_vec, binary_arith_vec<aby_uint8_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_yao_uint16_vec, binary_arith_vec<aby_uint16_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_yao_uint32_vec, binary_arith_vec<aby_uint32_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(add_yao_uint64_vec, binary_arith_vec<aby_uint64_t, AdditionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(and_yao_uint8_vec, binary_arith_vec<aby_uint8_t, BitwiseAndProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(and_yao_uint16_vec, binary_arith_vec<aby_uint16_t, BitwiseAndProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(and_yao_uint32_vec, binary_arith_vec<aby_uint32_t, BitwiseAndProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(and_yao_uint64_vec, binary_arith_vec<aby_uint64_t, BitwiseAndProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(choose_yao_uint8_vec, ternary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, aby_uint8_t, ObliviousChoiceProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(choose_yao_uint16_vec, ternary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, aby_uint16_t, ObliviousChoiceProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(choose_yao_uint32_vec, ternary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, aby_uint32_t, ObliviousChoiceProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(choose_yao_uint64_vec, ternary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, aby_uint64_t, ObliviousChoiceProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(eq_yao_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, EqualityProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(eq_yao_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, EqualityProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(eq_yao_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, EqualityProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(eq_yao_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, EqualityProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gt_yao_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, GreaterThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gt_yao_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, GreaterThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gt_yao_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, GreaterThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gt_yao_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, GreaterThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gte_yao_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, GreaterThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gte_yao_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, GreaterThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gte_yao_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, GreaterThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(gte_yao_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, GreaterThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lt_yao_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, LessThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lt_yao_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, LessThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lt_yao_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, LessThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lt_yao_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, LessThanProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lte_yao_uint8_vec, binary_vec<aby_uint8_t, aby_uint8_t, aby_uint8_t, LessThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lte_yao_uint16_vec, binary_vec<aby_uint16_t, aby_uint16_t, aby_uint16_t, LessThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lte_yao_uint32_vec, binary_vec<aby_uint32_t, aby_uint32_t, aby_uint32_t, LessThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(lte_yao_uint64_vec, binary_vec<aby_uint64_t, aby_uint64_t, aby_uint64_t, LessThanOrEqualProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_yao_uint8_vec, binary_arith_vec<aby_uint8_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_yao_uint16_vec, binary_arith_vec<aby_uint16_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_yao_uint32_vec, binary_arith_vec<aby_uint32_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(mul_yao_uint64_vec, binary_arith_vec<aby_uint64_t, MultiplicationProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_yao_uint8_vec, binary_arith_vec<aby_uint8_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_yao_uint16_vec, binary_arith_vec<aby_uint16_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_yao_uint32_vec, binary_arith_vec<aby_uint32_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(sub_yao_uint64_vec, binary_arith_vec<aby_uint64_t, SubtractionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(xor_yao_uint8_vec, binary_arith_vec<aby_uint8_t, BitwiseXorProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(xor_yao_uint16_vec, binary_arith_vec<aby_uint16_t, BitwiseXorProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(xor_yao_uint32_vec, binary_arith_vec<aby_uint32_t, BitwiseXorProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(xor_yao_uint64_vec, binary_arith_vec<aby_uint64_t, BitwiseXorProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint8_to_uint16_vec, unary_vec<aby_uint8_t, aby_uint16_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint8_to_uint32_vec, unary_vec<aby_uint8_t, aby_uint32_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint8_to_uint64_vec, unary_vec<aby_uint8_t, aby_uint64_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint16_to_uint8_vec, unary_vec<aby_uint16_t, aby_uint8_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint16_to_uint32_vec, unary_vec<aby_uint16_t, aby_uint32_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint16_to_uint64_vec, unary_vec<aby_uint16_t, aby_uint64_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint32_to_uint8_vec, unary_vec<aby_uint32_t, aby_uint8_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint32_to_uint16_vec, unary_vec<aby_uint32_t, aby_uint16_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint32_to_uint64_vec, unary_vec<aby_uint32_t, aby_uint64_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint64_to_uint8_vec, unary_vec<aby_uint64_t, aby_uint8_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint64_to_uint16_vec, unary_vec<aby_uint64_t, aby_uint16_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_uint64_to_uint32_vec, unary_vec<aby_uint64_t, aby_uint32_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_arith_uint8_to_bool_uint8_vec, unary_vec<aby_uint8_t, aby_uint8_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_arith_uint16_to_bool_uint16_vec, unary_vec<aby_uint16_t, aby_uint16_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_arith_uint32_to_bool_uint32_vec, unary_vec<aby_uint32_t, aby_uint32_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_arith_uint64_to_bool_uint64_vec, unary_vec<aby_uint64_t, aby_uint64_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_arith_uint8_to_yao_uint8_vec, unary_vec<aby_uint8_t, aby_uint8_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_arith_uint16_to_yao_uint16_vec, unary_vec<aby_uint16_t, aby_uint16_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_arith_uint32_to_yao_uint32_vec, unary_vec<aby_uint32_t, aby_uint32_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_arith_uint64_to_yao_uint64_vec, unary_vec<aby_uint64_t, aby_uint64_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_bool_uint8_to_arith_uint8_vec, unary_vec<aby_uint8_t, aby_uint8_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_bool_uint16_to_arith_uint16_vec, unary_vec<aby_uint16_t, aby_uint16_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_bool_uint32_to_arith_uint32_vec, unary_vec<aby_uint32_t, aby_uint32_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_bool_uint64_to_arith_uint64_vec, unary_vec<aby_uint64_t, aby_uint64_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_bool_uint8_to_yao_uint8_vec, unary_vec<aby_uint8_t, aby_uint8_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_bool_uint16_to_yao_uint16_vec, unary_vec<aby_uint16_t, aby_uint16_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_bool_uint32_to_yao_uint32_vec, unary_vec<aby_uint32_t, aby_uint32_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_bool_uint64_to_yao_uint64_vec, unary_vec<aby_uint64_t, aby_uint64_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_yao_uint8_to_arith_uint8_vec, unary_vec<aby_uint8_t, aby_uint8_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_yao_uint16_to_arith_uint16_vec, unary_vec<aby_uint16_t, aby_uint16_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_yao_uint32_to_arith_uint32_vec, unary_vec<aby_uint32_t, aby_uint32_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_yao_uint64_to_arith_uint64_vec, unary_vec<aby_uint64_t, aby_uint64_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_yao_uint8_to_bool_uint8_vec, unary_vec<aby_uint8_t, aby_uint8_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_yao_uint16_to_bool_uint16_vec, unary_vec<aby_uint16_t, aby_uint16_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_yao_uint32_to_bool_uint32_vec, unary_vec<aby_uint32_t, aby_uint32_t, ConversionProtocol<AbyPDPI>>)
NAMED_SYSCALL_WRAPPER(conv_yao_uint64_to_bool_uint64_vec, unary_vec<aby_uint64_t, aby_uint64_t, ConversionProtocol<AbyPDPI>>)


SHAREMIND_MODULE_API_0x1_SYSCALL_DEFINITIONS(

  /**
   *  Shared unsigned integer for all circuit types
   */

   // Variable management
    NAMED_SYSCALL_DEFINITION("aby::new_uint8_vec", new_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::new_uint16_vec", new_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::new_uint32_vec", new_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::new_uint64_vec", new_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::init_uint8_vec", init_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::init_uint16_vec", init_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::init_uint32_vec", init_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::init_uint64_vec", init_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::set_shares_uint8_vec", set_shares_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::set_shares_uint16_vec", set_shares_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::set_shares_uint32_vec", set_shares_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::set_shares_uint64_vec", set_shares_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::get_shares_uint8_vec", get_shares_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::get_shares_uint16_vec", get_shares_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::get_shares_uint32_vec", get_shares_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::get_shares_uint64_vec", get_shares_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::fill_uint8_vec", fill_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::fill_uint16_vec", fill_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::fill_uint32_vec", fill_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::fill_uint64_vec", fill_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::assign_uint8_vec", assign_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::assign_uint16_vec", assign_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::assign_uint32_vec", assign_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::assign_uint64_vec", assign_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::delete_uint8_vec", delete_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::delete_uint16_vec", delete_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::delete_uint32_vec", delete_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::delete_uint64_vec", delete_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::load_uint8_vec", load_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::load_uint16_vec", load_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::load_uint32_vec", load_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::load_uint64_vec", load_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::store_uint8_vec", store_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::store_uint16_vec", store_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::store_uint32_vec", store_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::store_uint64_vec", store_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::classify_uint8_vec", classify_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::classify_uint16_vec", classify_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::classify_uint32_vec", classify_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::classify_uint64_vec", classify_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::declassify_uint8_vec", declassify_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::declassify_uint16_vec", declassify_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::declassify_uint32_vec", declassify_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::declassify_uint64_vec", declassify_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::get_type_size_uint8", get_type_size_uint8)
  , NAMED_SYSCALL_DEFINITION("aby::get_type_size_uint16", get_type_size_uint16)
  , NAMED_SYSCALL_DEFINITION("aby::get_type_size_uint32", get_type_size_uint32)
  , NAMED_SYSCALL_DEFINITION("aby::get_type_size_uint64", get_type_size_uint64)

  /**
   * Operations on arithmetic circuits
   */

  , NAMED_SYSCALL_DEFINITION("aby::add_arith_uint8_vec", add_arith_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::add_arith_uint16_vec", add_arith_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::add_arith_uint32_vec", add_arith_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::add_arith_uint64_vec", add_arith_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_arith_uint8_vec", mul_arith_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_arith_uint16_vec", mul_arith_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_arith_uint32_vec", mul_arith_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_arith_uint64_vec", mul_arith_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_arith_uint8_vec", sub_arith_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_arith_uint16_vec", sub_arith_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_arith_uint32_vec", sub_arith_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_arith_uint64_vec", sub_arith_uint64_vec)

  /**
   * Operations on boolean circuits
   */

  , NAMED_SYSCALL_DEFINITION("aby::add_bool_uint8_vec", add_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::add_bool_uint16_vec", add_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::add_bool_uint32_vec", add_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::add_bool_uint64_vec", add_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::and_bool_uint8_vec", and_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::and_bool_uint16_vec", and_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::and_bool_uint32_vec", and_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::and_bool_uint64_vec", and_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::choose_bool_uint8_vec", choose_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::choose_bool_uint16_vec", choose_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::choose_bool_uint32_vec", choose_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::choose_bool_uint64_vec", choose_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::eq_bool_uint8_vec", eq_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::eq_bool_uint16_vec", eq_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::eq_bool_uint32_vec", eq_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::eq_bool_uint64_vec", eq_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gt_bool_uint8_vec", gt_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gt_bool_uint16_vec", gt_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gt_bool_uint32_vec", gt_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gt_bool_uint64_vec", gt_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gte_bool_uint8_vec", gte_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gte_bool_uint16_vec", gte_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gte_bool_uint32_vec", gte_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gte_bool_uint64_vec", gte_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lt_bool_uint8_vec", lt_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lt_bool_uint16_vec", lt_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lt_bool_uint32_vec", lt_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lt_bool_uint64_vec", lt_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lte_bool_uint8_vec", lte_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lte_bool_uint16_vec", lte_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lte_bool_uint32_vec", lte_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lte_bool_uint64_vec", lte_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_bool_uint8_vec", mul_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_bool_uint16_vec", mul_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_bool_uint32_vec", mul_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_bool_uint64_vec", mul_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_bool_uint8_vec", sub_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_bool_uint16_vec", sub_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_bool_uint32_vec", sub_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_bool_uint64_vec", sub_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::xor_bool_uint8_vec", xor_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::xor_bool_uint16_vec", xor_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::xor_bool_uint32_vec", xor_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::xor_bool_uint64_vec", xor_bool_uint64_vec)

  /**
   * Operations on Yao's circuits
   */

  , NAMED_SYSCALL_DEFINITION("aby::add_yao_uint8_vec", add_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::add_yao_uint16_vec", add_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::add_yao_uint32_vec", add_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::add_yao_uint64_vec", add_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::and_yao_uint8_vec", and_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::and_yao_uint16_vec", and_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::and_yao_uint32_vec", and_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::and_yao_uint64_vec", and_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::choose_yao_uint8_vec", choose_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::choose_yao_uint16_vec", choose_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::choose_yao_uint32_vec", choose_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::choose_yao_uint64_vec", choose_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::eq_yao_uint8_vec", eq_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::eq_yao_uint16_vec", eq_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::eq_yao_uint32_vec", eq_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::eq_yao_uint64_vec", eq_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gt_yao_uint8_vec", gt_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gt_yao_uint16_vec", gt_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gt_yao_uint32_vec", gt_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gt_yao_uint64_vec", gt_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gte_yao_uint8_vec", gte_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gte_yao_uint16_vec", gte_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gte_yao_uint32_vec", gte_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::gte_yao_uint64_vec", gte_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lt_yao_uint8_vec", lt_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lt_yao_uint16_vec", lt_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lt_yao_uint32_vec", lt_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lt_yao_uint64_vec", lt_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lte_yao_uint8_vec", lte_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lte_yao_uint16_vec", lte_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lte_yao_uint32_vec", lte_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::lte_yao_uint64_vec", lte_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_yao_uint8_vec", mul_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_yao_uint16_vec", mul_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_yao_uint32_vec", mul_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::mul_yao_uint64_vec", mul_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_yao_uint8_vec", sub_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_yao_uint16_vec", sub_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_yao_uint32_vec", sub_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::sub_yao_uint64_vec", sub_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::xor_yao_uint8_vec", xor_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::xor_yao_uint16_vec", xor_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::xor_yao_uint32_vec", xor_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::xor_yao_uint64_vec", xor_yao_uint64_vec)

  /**
   * Type conversion
   */

  , NAMED_SYSCALL_DEFINITION("aby::conv_uint8_to_uint16_vec", conv_uint8_to_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint8_to_uint32_vec", conv_uint8_to_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint8_to_uint64_vec", conv_uint8_to_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint16_to_uint8_vec", conv_uint16_to_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint16_to_uint32_vec", conv_uint16_to_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint16_to_uint64_vec", conv_uint16_to_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint32_to_uint8_vec", conv_uint32_to_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint32_to_uint16_vec", conv_uint32_to_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint32_to_uint64_vec", conv_uint32_to_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint64_to_uint8_vec", conv_uint64_to_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint64_to_uint16_vec", conv_uint64_to_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_uint64_to_uint32_vec", conv_uint64_to_uint32_vec)

  /**
   * Circuit type conversion
   */

  , NAMED_SYSCALL_DEFINITION("aby::conv_arith_uint8_to_bool_uint8_vec", conv_arith_uint8_to_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_arith_uint16_to_bool_uint16_vec", conv_arith_uint16_to_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_arith_uint32_to_bool_uint32_vec", conv_arith_uint32_to_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_arith_uint64_to_bool_uint64_vec", conv_arith_uint64_to_bool_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_arith_uint8_to_yao_uint8_vec", conv_arith_uint8_to_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_arith_uint16_to_yao_uint16_vec", conv_arith_uint16_to_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_arith_uint32_to_yao_uint32_vec", conv_arith_uint32_to_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_arith_uint64_to_yao_uint64_vec", conv_arith_uint64_to_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_bool_uint8_to_arith_uint8_vec", conv_bool_uint8_to_arith_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_bool_uint16_to_arith_uint16_vec", conv_bool_uint16_to_arith_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_bool_uint32_to_arith_uint32_vec", conv_bool_uint32_to_arith_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_bool_uint64_to_arith_uint64_vec", conv_bool_uint64_to_arith_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_bool_uint8_to_yao_uint8_vec", conv_bool_uint8_to_yao_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_bool_uint16_to_yao_uint16_vec", conv_bool_uint16_to_yao_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_bool_uint32_to_yao_uint32_vec", conv_bool_uint32_to_yao_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_bool_uint64_to_yao_uint64_vec", conv_bool_uint64_to_yao_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_yao_uint8_to_arith_uint8_vec", conv_yao_uint8_to_arith_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_yao_uint16_to_arith_uint16_vec", conv_yao_uint16_to_arith_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_yao_uint32_to_arith_uint32_vec", conv_yao_uint32_to_arith_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_yao_uint64_to_arith_uint64_vec", conv_yao_uint64_to_arith_uint64_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_yao_uint8_to_bool_uint8_vec", conv_yao_uint8_to_bool_uint8_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_yao_uint16_to_bool_uint16_vec", conv_yao_uint16_to_bool_uint16_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_yao_uint32_to_bool_uint32_vec", conv_yao_uint32_to_bool_uint32_vec)
  , NAMED_SYSCALL_DEFINITION("aby::conv_yao_uint64_to_bool_uint64_vec", conv_yao_uint64_to_bool_uint64_vec)

  /**
   *  Other functions
   */

  , { "aby::get_domain_name", get_domain_name }
);


SHAREMIND_MODULE_API_0x1_PD_STARTUP(aby_emu_startup, w) SHAREMIND_VISIBILITY_HIDDEN;
SHAREMIND_MODULE_API_0x1_PD_STARTUP(aby_emu_startup, w) {
    assert(w);
    assert(w->moduleHandle);
    assert(w->conf);
    assert(w->conf->pd_name);

    sharemind::AbyModule * const m =
        static_cast<sharemind::AbyModule*>(w->moduleHandle);

    try {
        w->pdHandle = new AbyPD(w->conf->pd_name,
                                     w->conf->pd_conf_string
                                     ? w->conf->pd_conf_string
                                     : "",
                                     *m);
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (const AbyPD::ConfigurationException & e) {
        m->logger().error() << "Error on protection domain '"
            << w->conf->pd_name << "' startup: " << e.what();
        return SHAREMIND_MODULE_API_0x1_INVALID_PD_CONFIGURATION;
    } catch (...) {
        return catchModuleApiErrors ();
    }
}

SHAREMIND_MODULE_API_0x1_PD_SHUTDOWN(aby_emu_shutdown, w) SHAREMIND_VISIBILITY_HIDDEN;
SHAREMIND_MODULE_API_0x1_PD_SHUTDOWN(aby_emu_shutdown, w) {
    assert(w);
    assert(w->pdHandle);
    assert(w->moduleHandle);

    static_assert(std::is_nothrow_destructible<sharemind::AbyPD>::value, "");
    delete static_cast<sharemind::AbyPD *>(w->pdHandle);
    #ifndef NDEBUG
    w->pdHandle = nullptr; // Not needed, but may help debugging.
    #endif
}

SHAREMIND_MODULE_API_0x1_PDPI_STARTUP(aby_emu_PDPI_startup, w) SHAREMIND_VISIBILITY_HIDDEN;
SHAREMIND_MODULE_API_0x1_PDPI_STARTUP(aby_emu_PDPI_startup, w) {
    assert(w);
    assert(w->pdHandle);

    try {
        sharemind::AbyPD * const pd =
            static_cast<sharemind::AbyPD*>(w->pdHandle);
        w->pdProcessHandle = new AbyPDPI(*pd);
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (...) {
        return catchModuleApiErrors ();
    }
}

SHAREMIND_MODULE_API_0x1_PDPI_SHUTDOWN(aby_emu_PDPI_shutdown, w) SHAREMIND_VISIBILITY_HIDDEN;
SHAREMIND_MODULE_API_0x1_PDPI_SHUTDOWN(aby_emu_PDPI_shutdown, w) {
    assert(w);
    assert(w->pdHandle);
    assert(w->pdProcessHandle);

    static_assert(std::is_nothrow_destructible<sharemind::AbyPDPI>::value, "");
    delete static_cast<sharemind::AbyPDPI *>(w->pdProcessHandle);
    #ifndef NDEBUG
    w->pdProcessHandle = nullptr; // Not needed, but may help debugging.
    #endif
}

SHAREMIND_MODULE_API_0x1_PDK_DEFINITIONS(
    {
        "aby",
        &aby_emu_startup,
        &aby_emu_shutdown,
        &aby_emu_PDPI_startup,
        &aby_emu_PDPI_shutdown
    }
);

} // extern "C" {
