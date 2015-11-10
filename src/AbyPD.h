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

#ifndef MOD_SPDZ_FRESCO_EMU_SHARED3PPD_H
#define MOD_SPDZ_FRESCO_EMU_SHARED3PPD_H

#include <memory>
#include <sharemind/Exception.h>
#include "AbyConfiguration.h"


namespace sharemind {

class ExecutionProfiler;
class ExecutionModelEvaluator;
class AbyModule;

class __attribute__ ((visibility("internal"))) AbyPD {

public: /* Types: */

    SHAREMIND_DEFINE_EXCEPTION(std::exception, Exception);

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            Exception,
            ConfigurationException,
            "Error in protection domain configuration!");

public: /* Methods: */

    AbyPD(const std::string & pdName,
               const std::string & pdConfiguration,
               AbyModule & module);
    ~AbyPD() noexcept;

    inline AbyConfiguration & configuration() noexcept
    { return m_configuration; }

    inline const AbyConfiguration & configuration() const noexcept
    { return m_configuration; }

    inline ExecutionModelEvaluator & modelEvaluator() noexcept
    { return *m_modelEvaluator; }

    inline const ExecutionModelEvaluator & modelEvaluator() const noexcept
    { return *m_modelEvaluator; }

    inline ExecutionProfiler & profiler() noexcept
    { return m_profiler; }

    inline const ExecutionProfiler & profiler() const noexcept
    { return m_profiler; }

    inline const std::string & name() const noexcept
    { return m_name; }

private: /* Fields: */

    AbyConfiguration m_configuration;
    std::string m_name;

    ExecutionProfiler & m_profiler;

    std::unique_ptr<ExecutionModelEvaluator> m_modelEvaluator;

}; /* class AbyPD { */

} /* namespace sharemind { */

#endif /* MOD_SPDZ_FRESCO_EMU_SHARED3PPD_H */
