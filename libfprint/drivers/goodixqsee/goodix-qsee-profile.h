/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Per-TA layout of the Goodix trusted-application protocol.
 *
 * Command ids and the QSEE transport are shared across the TA generations
 * seen so far; payload sizes and field offsets are not.  Offsets are from the
 * start of the payload buffer (the command body starts after a TA header of
 * 100 bytes on gfenu and 96 bytes on Milan).  An offset of 0 means the field
 * does not exist in that profile.
 */
struct goodix_qsee_profile
{
  uint32_t id;
  const char *name;

  size_t   init_len, init_finished_len;
  bool     get_dev_info;

  size_t   set_group_len, set_group;
  size_t   pre_enroll_len, pre_enroll_challenge;
  size_t   enroll_len, enroll_group, enroll_hat;
  size_t   auth_len, auth_group, auth_screen;
  size_t   get_auth_id_len;
  size_t   finger_group, finger_id;     /* SAVE and REMOVE arguments */
  size_t   save_len, remove_len, cancel_len;
  size_t   enumerate_len, enumerate_count, enumerate_groups, enumerate_fingers;

  size_t   irq_len, irq_mask, irq_operation;
  size_t   irq_group, irq_finger, irq_remaining;
  size_t   irq_mode, irq_size, irq_arm;
  size_t   irq_clear8, irq_clear64;     /* zeroed before each IRQ invoke */
  bool     irq_drain_on_arm2;           /* TA sets arm=2 while more is pending */

  size_t   finish_len, finish_mask, finish_operation, finish_group, finish_finger;
  bool     finish_big_endian;

  int      enroll_stages;
};

#define GOODIX_QSEE_PROFILE_GFENU 1u
#define GOODIX_QSEE_PROFILE_MILAN 2u

/* Largest payloads across profiles, for stack buffers. */
#define GOODIX_QSEE_SMALL_MAX 200u

extern const struct goodix_qsee_profile goodix_qsee_profile_gfenu;
extern const struct goodix_qsee_profile goodix_qsee_profile_milan;

const struct goodix_qsee_profile *goodix_qsee_profile_get (uint32_t id);
