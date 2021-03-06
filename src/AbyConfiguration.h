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

#ifndef MOD_ABY_EMU_SHARED3PCONFIGURATION_H
#define MOD_ABY_EMU_SHARED3PCONFIGURATION_H

#include <sharemind/libconfiguration/Configuration.h>
#include <sharemind/visibility.h>
#include <string>


namespace LogHard { class Logger; }

namespace sharemind {

class SHAREMIND_VISIBILITY_INTERNAL AbyConfiguration
    : public Configuration {

public: /* Methods: */

    AbyConfiguration(const std::string & pdConf);

    const std::string & modelEvaluatorConfiguration() const noexcept
    { return m_modelEvaluatorConfiguration; }

private: /* Fields: */

    std::string m_modelEvaluatorConfiguration;

}; /* class AbyConfiguration { */

} /* namespace sharemind { */

#endif /* MOD_ABY_EMU_SHARED3PCONFIGURATION_H */
