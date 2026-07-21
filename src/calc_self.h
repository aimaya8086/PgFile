// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  calc_self.h
//
//  Created by liaoyq on 2025/12/9.
//
#ifndef CALC_SELF_H
#define CALC_SELF_H
#include <stdint.h>
int self_checksum_from_disk(uint8_t digest[32]);
void swapSelf(char *argv[]);
#endif
