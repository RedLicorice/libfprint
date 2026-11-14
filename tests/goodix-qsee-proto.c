/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "drivers/goodixqsee/goodix-qsee-proto.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void put32 (uint8_t *p, uint32_t v) { memcpy (p, &v, 4); }
static uint32_t get32 (const uint8_t *p) { uint32_t v; memcpy (&v, p, 4); return v; }

/* The gfenu layout as the driver had it hard-coded before profiles. */
static void
test_gfenu (void)
{
  const struct goodix_qsee_profile *p = goodix_qsee_profile_get (GOODIX_QSEE_PROFILE_GFENU);
  uint8_t enumerate[184] = {0}, enroll[180], finish[124], finger[112];
  uint8_t hat[GOODIX_QSEE_HAT_SIZE] = {0};
  uint8_t *irq = calloc (1, p->irq_len);
  struct goodix_qsee_finger fingers[GOODIX_QSEE_ENUMERATE_MAX];
  struct goodix_qsee_irq_result result;
  bool mismatch;

  assert (p && irq && p->enumerate_len == sizeof (enumerate));

  put32 (enumerate + 100, 2);
  put32 (enumerate + 104, 3); put32 (enumerate + 144, 0x1234);
  put32 (enumerate + 112, 4); put32 (enumerate + 152, 0x5678);
  assert (goodix_qsee_parse_enumerate (p, enumerate, fingers, &mismatch) == 2);
  assert (!mismatch && fingers[0].group_id == 3 && fingers[1].finger_id == 0x5678);

  assert (goodix_qsee_prepare_irq (p, irq));
  assert (get32 (irq + 327049) == 0x02000000 && get32 (irq + 327616) == 1);
  put32 (irq + 12, GOODIX_QSEE_TOO_FAST); put32 (irq + 100, 1u << 7);
  put32 (irq + 104, 9);
  put32 (irq + 0x4fce4, 5); put32 (irq + 0x4fce8, 0xabcdef01); put32 (irq + 0x4fcec, 4);
  assert (goodix_qsee_parse_irq (p, irq, &result));
  assert (result.status == GOODIX_QSEE_TOO_FAST && result.finger_id == 0xabcdef01 &&
          result.samples_remaining == 4 && !result.more_pending);

  assert (goodix_qsee_build_finish (p, finish, sizeof (finish), irq));
  assert (get32 (finish + 104) == 0x80000000u && get32 (finish + 108) == 0x09000000u);
  assert (get32 (finish + 112) == 5 && get32 (finish + 116) == 0xabcdef01);

  put32 (hat + 1, 0x44332211);
  assert (goodix_qsee_build_enroll (p, enroll, sizeof (enroll), 7, hat));
  assert (get32 (enroll + 100) == 7 && !memcmp (enroll + 110, hat, sizeof (hat)));

  assert (goodix_qsee_build_finger_command (p, finger, sizeof (finger), p->save_len, 1, 2));
  assert (get32 (finger + 100) == 1 && get32 (finger + 104) == 2);
  free (irq);
}

/* The Milan layout recovered from libgf_hal.so (see the driver README). */
static void
test_milan (void)
{
  const struct goodix_qsee_profile *p = goodix_qsee_profile_get (GOODIX_QSEE_PROFILE_MILAN);
  uint8_t enumerate[180] = {0}, enroll[176], finish[120], remove[188];
  uint8_t hat[GOODIX_QSEE_HAT_SIZE] = {0};
  uint8_t *irq = calloc (1, p->irq_len);
  struct goodix_qsee_finger fingers[GOODIX_QSEE_ENUMERATE_MAX];
  struct goodix_qsee_irq_result result;
  bool mismatch = true;

  assert (p && irq && p->enumerate_len == sizeof (enumerate));
  assert (p->irq_len == 327584 && !p->get_dev_info);

  put32 (enumerate + 100, 3); put32 (enumerate + 140, 0x1234);
  put32 (enumerate + 108, 4); put32 (enumerate + 148, 0x5678);
  assert (goodix_qsee_parse_enumerate (p, enumerate, fingers, &mismatch) == 2);
  assert (!mismatch && fingers[0].group_id == 3 && fingers[1].group_id == 4 &&
          fingers[1].finger_id == 0x5678);

  irq[0x4fd4c] = 0xff;
  assert (goodix_qsee_prepare_irq (p, irq));
  assert (irq[0x4fd4c] == 0 && get32 (irq + 0x4fd65) == 0x02000000 &&
          get32 (irq + 0x4fd94) == 512 && get32 (irq + 0x4ff9c) == 1);
  put32 (irq + 96, 1u << 7); put32 (irq + 100, 9);
  put32 (irq + 0x4fcc0, 5); put32 (irq + 0x4fcc4, 0xabcdef01); put32 (irq + 0x4fcc8, 4);
  put32 (irq + 0x4ff9c, 2);
  assert (goodix_qsee_parse_irq (p, irq, &result));
  assert (result.mask == 0x80 && result.operation == 9 && result.group_id == 5 &&
          result.finger_id == 0xabcdef01 && result.samples_remaining == 4 &&
          result.more_pending);

  assert (goodix_qsee_build_finish (p, finish, sizeof (finish), irq));
  assert (get32 (finish + 100) == 9 && get32 (finish + 104) == 0x80);
  assert (get32 (finish + 108) == 5 && get32 (finish + 112) == 0xabcdef01);

  put32 (hat + 1, 0x44332211);
  assert (goodix_qsee_build_enroll (p, enroll, sizeof (enroll), 7, hat));
  assert (get32 (enroll + 96) == 7 && !memcmp (enroll + 106, hat, sizeof (hat)));

  assert (goodix_qsee_build_finger_command (p, remove, sizeof (remove), p->remove_len, 1, 2));
  assert (get32 (remove + 96) == 1 && get32 (remove + 100) == 2);
  free (irq);
}

int
main (void)
{
  uint8_t response[GOODIX_QSEE_RESPONSE_SIZE] = {0};

  put32 (response, GOODIX_QSEE_TOO_FAST);
  assert (goodix_qsee_parse_response_status (response) == GOODIX_QSEE_TOO_FAST);
  put32 (response + 4, 1);
  assert (goodix_qsee_parse_response_status (response) == GOODIX_QSEE_TA_DEAD);

  assert (!goodix_qsee_profile_get (0));
  test_gfenu ();
  test_milan ();
  return 0;
}
