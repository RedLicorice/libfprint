/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "fpi-device.h"

G_DECLARE_FINAL_TYPE (FpiDeviceAndroidHal, fpi_device_androidhal,
                      FPI, DEVICE_ANDROIDHAL, FpDevice)

struct _FpiDeviceAndroidHal
{
  FpDevice parent;
  GSocket *socket;         /* the bridge's root-only socket, one per open */
  gchar   *socket_path;    /* FP_ANDROIDHAL_SOCKET */
  guint    enroll_timeout; /* FP_ANDROIDHAL_ENROLL_TIMEOUT, seconds the HAL waits during an enrolment */
};
