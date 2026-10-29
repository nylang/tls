// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief TLS session and transport contracts exercised through their product interfaces. */
module TlsContractTests;
part "engine_selftest.ny";
part "stream_selftest.ny";
part "stream_control_selftest.ny";
part "channel_selftest.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/tls.ni";
import "interface/stream.ni";
import "interface/channel.ni";
import "private/tls.ny";
import "private/stream.ny";
