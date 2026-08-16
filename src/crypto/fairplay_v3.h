// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 matkhl. See LICENSE and THIRD_PARTY_NOTICES.md.
// Internal interface for the FairPlay v3 unwrap implementation.
#pragma once

#include "fairplay.h"

#include <string>
#include <vector>

namespace airplayc::crypto {

bool derive_fairplay_tokenless_key_native(const FairPlayActiveUnwrapInput& input,
                                          std::vector<uint8_t>& tokenless_key,
                                          std::string& error);

}
