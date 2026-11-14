/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix-qsee-proto.h"

#include <string.h>

/* gfenu: the Xiaomi Pad 5 Pro (gf3626) TA the driver was written against. */
const struct goodix_qsee_profile goodix_qsee_profile_gfenu = {
  .id = GOODIX_QSEE_PROFILE_GFENU, .name = "gfenu",
  .init_len = 348, .init_finished_len = 104, .get_dev_info = true,
  .set_group_len = 104, .set_group = 100,
  .pre_enroll_len = 112, .pre_enroll_challenge = 104,
  .enroll_len = 180, .enroll_group = 100, .enroll_hat = 110,
  .auth_len = 112, .auth_group = 100, .auth_screen = 0,
  .get_auth_id_len = 112,
  .finger_group = 100, .finger_id = 104,
  .save_len = 112, .remove_len = 112, .cancel_len = 104,
  .enumerate_len = 184, .enumerate_count = 100,
  .enumerate_groups = 104, .enumerate_fingers = 144,
  .irq_len = 327624, .irq_mask = 100, .irq_operation = 104,
  .irq_group = 0x4fce4, .irq_finger = 0x4fce8, .irq_remaining = 0x4fcec,
  .irq_mode = 327049, .irq_size = 327096, .irq_arm = 327616,
  .finish_len = 124, .finish_mask = 104, .finish_operation = 108,
  .finish_group = 112, .finish_finger = 116, .finish_big_endian = true,
  .enroll_stages = 25,
};

/*
 * Milan: the goodixfp TA of the Xiaomi POCO X3 NFC (GF_CHIP_316M), recovered
 * from its Android HAL (libgf_hal.so).  The body starts at +96, so the simple
 * commands are gfenu's shifted down by 4; the IRQ tail fields by 0x24.
 */
const struct goodix_qsee_profile goodix_qsee_profile_milan = {
  .id = GOODIX_QSEE_PROFILE_MILAN, .name = "milan",
  .init_len = 344, .init_finished_len = 100, .get_dev_info = false,
  .set_group_len = 100, .set_group = 96,
  .pre_enroll_len = 104, .pre_enroll_challenge = 96,
  .enroll_len = 176, .enroll_group = 96, .enroll_hat = 106,
  .auth_len = 120, .auth_group = 96, .auth_screen = 112,
  .get_auth_id_len = 104,
  .finger_group = 96, .finger_id = 100,
  .save_len = 108, .remove_len = 188, .cancel_len = 100,
  .enumerate_len = 180, .enumerate_count = 0,
  .enumerate_groups = 100, .enumerate_fingers = 140,
  .irq_len = 327584, .irq_mask = 96, .irq_operation = 100,
  .irq_group = 0x4fcc0, .irq_finger = 0x4fcc4, .irq_remaining = 0x4fcc8,
  .irq_mode = 0x4fd65, .irq_size = 0x4fd94, .irq_arm = 0x4ff9c,
  .irq_clear8 = 0x4fd4c, .irq_clear64 = 0x4fd69, .irq_drain_on_arm2 = true,
  .finish_len = 120, .finish_operation = 100, .finish_mask = 104,
  .finish_group = 108, .finish_finger = 112, .finish_big_endian = false,
  /* goodixfp V00.04.05.01 asks for 26 samples: remaining reads 25 after the first */
  .enroll_stages = 26,
};

const struct goodix_qsee_profile *
goodix_qsee_profile_get (uint32_t id)
{
  switch (id)
    {
    case GOODIX_QSEE_PROFILE_GFENU:
      return &goodix_qsee_profile_gfenu;
    case GOODIX_QSEE_PROFILE_MILAN:
      return &goodix_qsee_profile_milan;
    default:
      return NULL;
    }
}

static uint32_t
get32 (const uint8_t *p)
{
  uint32_t value;
  memcpy (&value, p, sizeof (value));
  return value;
}

static void
put32 (uint8_t *p, uint32_t value)
{
  memcpy (p, &value, sizeof (value));
}

static uint32_t
to_be32 (uint32_t v)
{
  return ((v & 0xffu) << 24) | ((v & 0xff00u) << 8) |
         ((v >> 8) & 0xff00u) | (v >> 24);
}

uint32_t
goodix_qsee_parse_response_status (const uint8_t response[GOODIX_QSEE_RESPONSE_SIZE])
{
  if (get32 (response + 4))
    return GOODIX_QSEE_TA_DEAD;

  return get32 (response);
}

size_t
goodix_qsee_parse_enumerate (const struct goodix_qsee_profile *p,
                             const uint8_t *payload,
                             struct goodix_qsee_finger out[GOODIX_QSEE_ENUMERATE_MAX],
                             bool *count_mismatch)
{
  size_t i, count = 0;

  for (i = 0; i < GOODIX_QSEE_ENUMERATE_MAX; i++)
    {
      uint32_t finger = get32 (payload + p->enumerate_fingers + 4 * i);
      if (!finger)
        continue;
      out[count].group_id = get32 (payload + p->enumerate_groups + 4 * i);
      out[count].finger_id = finger;
      count++;
    }
  if (count_mismatch)
    *count_mismatch = p->enumerate_count &&
                      get32 (payload + p->enumerate_count) != count;
  return count;
}

bool
goodix_qsee_prepare_irq (const struct goodix_qsee_profile *p, uint8_t *payload)
{
  if (p->irq_clear8)
    payload[p->irq_clear8] = 0;
  if (p->irq_clear64)
    memset (payload + p->irq_clear64, 0, 8);
  put32 (payload + p->irq_mode, 0x02000000);
  put32 (payload + p->irq_size, 512);
  put32 (payload + p->irq_arm, 1);
  return true;
}

bool
goodix_qsee_parse_irq (const struct goodix_qsee_profile *p, const uint8_t *payload,
                       struct goodix_qsee_irq_result *out)
{
  if (!payload || !out)
    return false;
  out->status = get32 (payload + 12);
  out->mask = get32 (payload + p->irq_mask);
  out->operation = get32 (payload + p->irq_operation);
  out->group_id = get32 (payload + p->irq_group);
  out->finger_id = get32 (payload + p->irq_finger);
  out->samples_remaining = get32 (payload + p->irq_remaining);
  out->more_pending = p->irq_drain_on_arm2 && get32 (payload + p->irq_arm) == 2;
  return true;
}

bool
goodix_qsee_build_enroll (const struct goodix_qsee_profile *p, uint8_t *payload,
                          size_t size, uint32_t group_id,
                          const uint8_t hat[GOODIX_QSEE_HAT_SIZE])
{
  if (!payload || !hat || size < p->enroll_len)
    return false;
  memset (payload, 0, p->enroll_len);
  put32 (payload + p->enroll_group, group_id);
  memcpy (payload + p->enroll_hat, hat, GOODIX_QSEE_HAT_SIZE);
  return true;
}

bool
goodix_qsee_build_finger_command (const struct goodix_qsee_profile *p, uint8_t *payload,
                                  size_t size, size_t len,
                                  uint32_t group_id, uint32_t finger_id)
{
  if (!payload || size < len || len < p->finger_id + 4)
    return false;
  memset (payload, 0, len);
  put32 (payload + p->finger_group, group_id);
  put32 (payload + p->finger_id, finger_id);
  return true;
}

bool
goodix_qsee_build_finish (const struct goodix_qsee_profile *p, uint8_t *payload,
                          size_t size, const uint8_t *irq)
{
  uint32_t mask, operation;

  if (!payload || !irq || size < p->finish_len)
    return false;
  mask = get32 (irq + p->irq_mask);
  operation = get32 (irq + p->irq_operation);
  if (p->finish_big_endian)
    {
      mask = to_be32 (mask);
      operation = to_be32 (operation);
    }
  memset (payload, 0, p->finish_len);
  put32 (payload + p->finish_mask, mask);
  put32 (payload + p->finish_operation, operation);
  memcpy (payload + p->finish_group, irq + p->irq_group, 4);
  memcpy (payload + p->finish_finger, irq + p->irq_finger, 4);
  return true;
}
