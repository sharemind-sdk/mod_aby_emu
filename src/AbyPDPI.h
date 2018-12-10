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

#ifndef MOD_ABY_EMU_SHARED3PPDPI_H
#define MOD_ABY_EMU_SHARED3PPDPI_H

#include <sharemind/ShareVector.h>
#include <sharemind/SharedValueHeap.h>
#include <sharemind/visibility.h>
#include "AbyPD.h"

namespace sharemind {

class ExecutionModelEvaluator;
class AbyConfiguration;

class SHAREMIND_VISIBILITY_INTERNAL AbyPDPI {

public: /* Methods: */

    AbyPDPI(AbyPD & pd);
    inline ~AbyPDPI() noexcept {}

    inline const std::string & pdName() const noexcept
    { return m_pd.name(); }

    inline const AbyConfiguration & pdConfiguration() const noexcept
    { return m_pd.configuration(); }

    inline ExecutionModelEvaluator & modelEvaluator() noexcept
    { return m_modelEvaluator; }

    inline const ExecutionModelEvaluator & modelEvaluator() const noexcept
    { return m_modelEvaluator; }

    template <typename T>
    inline bool isValidHandle(void * hndl) const {
        return m_heap.check<T>(hndl);
    }

    template <typename T>
    inline bool registerVector(ShareVec<T> * vec) {
        return m_heap.insert(vec);
    }

    template <typename T>
    inline bool freeRegisteredVector(ShareVec<T> * vec) {
        return m_heap.erase(vec);
    }

private: /* Fields: */

    AbyPD & m_pd;
    AbyConfiguration & m_pdConfiguration;
    ExecutionModelEvaluator & m_modelEvaluator;
    SharedValueHeap m_heap;

}; /* class AbyPDPI { */

} /* namespace sharemind { */

#endif /* MOD_ABY_EMU_SHARED3PPDPI_H */
