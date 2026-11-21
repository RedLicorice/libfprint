/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * androidhal: a phone's own Android fingerprint HAL, run by a bridge service.
 *
 * Some sensors only work through their vendor's Android HAL and trusted
 * application (UMI's in-display Goodix sensor: its HAL drives the panel and
 * the touchscreen as much as the TA).  A bridge runs that HAL in a read-only
 * chroot of the phone's Android partitions and serves it on a Unix socket
 * that only root may reach (Minerva's fingerprint/gfhost, "serve").  This
 * driver is that socket's client: the matching, the templates and the
 * enrolment authorisation (a Gatekeeper-signed token the bridge obtains when
 * the owner confirms the credential) all stay with the HAL and its TA.
 *
 * The bridge's protocol is one request per packet and one answer ("ok ..."
 * or "error <reason>"), with the HAL's notifications as "event <type> <d0>
 * <d1> <d2>" packets in between (AOSP fingerprint.h: -1 error, 1 acquired,
 * 3 enrolling gid fid remaining, 4 removed gid fid remaining, 5 authenticated
 * gid fid, 6 enumerating gid fid remaining).
 *
 * The device is the sensor's misc node; which sensors are bridged is the id
 * table below.  Per installation, from fprintd's environment:
 *   FP_ANDROIDHAL_SOCKET          the bridge's socket
 *   FP_ANDROIDHAL_ENROLL_STAGES   the samples one enrolment takes
 *   FP_ANDROIDHAL_ENROLL_TIMEOUT  seconds the HAL waits for each sample
 *   FP_ANDROIDHAL_ACQUIRED_FINGER_DOWN, FP_ANDROIDHAL_ACQUIRED_FINGER_UP
 *                                 the HAL's vendor acquired codes for a finger put on and lifted (optional)
 *
 * While an enrolment or an identify waits for a finger the device reports
 * FP_FINGER_STATUS_NEEDED (fprintd's finger-needed property), and PRESENT
 * while a finger is down: what a shell needs to show an in-display sensor
 * (Minerva's Phosh draws its UDFPS circle from these).
 */
#define FP_COMPONENT "androidhal"

#include "drivers_api.h"
#include "androidhal.h"

#include <gio/gunixsocketaddress.h>
#include <stdio.h>
#include <string.h>

#define MSG_MAX 512

/* AOSP hardware/fingerprint.h */
enum {
  MSG_ERROR = -1,
  MSG_ACQUIRED = 1,
  MSG_TEMPLATE_ENROLLING = 3,
  MSG_TEMPLATE_REMOVED = 4,
  MSG_AUTHENTICATED = 5,
  MSG_TEMPLATE_ENUMERATING = 6,
};
enum {
  ERROR_TIMEOUT = 3,
  ERROR_NO_SPACE = 4,
  ERROR_CANCELED = 5,
  ERROR_LOCKOUT = 7,
};
enum {
  ACQUIRED_GOOD = 0,
  ACQUIRED_PARTIAL = 1,
  ACQUIRED_INSUFFICIENT = 2,
  ACQUIRED_IMAGER_DIRTY = 3,
  ACQUIRED_TOO_SLOW = 4,
  ACQUIRED_TOO_FAST = 5,
};

enum worker_operation { WORK_OPEN, WORK_CLOSE, WORK_LIST, WORK_DELETE,
                        WORK_ENROLL, WORK_IDENTIFY };

struct worker_data {
  enum worker_operation operation;
  guint32 group_id, finger_id;
};

struct finger { guint32 group_id, finger_id; };

struct message {
  gboolean is_event, ok;
  gint type;
  guint32 d[3];
  gchar text[MSG_MAX];
};

struct progress_event {
  FpiDeviceAndroidHal *self;
  FpFingerStatusFlags finger_status;
  gint completed;
  GError *retry;
};

G_DEFINE_TYPE (FpiDeviceAndroidHal, fpi_device_androidhal, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_MISC,
    .misc_name = "goodix_fp", .misc_compatible = "goodix,delmar" },
  { .udev_types = 0 }
};

static guint
env_uint (const char *name, guint fallback)
{
  const char *v = g_getenv (name);
  return v && *v ? (guint) g_ascii_strtoull (v, NULL, 10) : fallback;
}

static gboolean
send_request (FpiDeviceAndroidHal *self, GError **error, const char *fmt, ...) G_GNUC_PRINTF (3, 4);
static gboolean
send_request (FpiDeviceAndroidHal *self, GError **error, const char *fmt, ...)
{
  g_autofree gchar *line = NULL;
  va_list ap;

  va_start (ap, fmt);
  line = g_strdup_vprintf (fmt, ap);
  va_end (ap);
  return g_socket_send (self->socket, line, strlen (line), NULL, error) >= 0;
}

/* the next packet: a reply or an event */
static gboolean
receive (FpiDeviceAndroidHal *self, GCancellable *cancellable,
         struct message *m, GError **error)
{
  gssize n = g_socket_receive (self->socket, m->text, sizeof (m->text) - 1,
                               cancellable, error);
  if (n < 0)
    return FALSE;
  if (n == 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED,
                           "fingerprint bridge closed the connection");
      return FALSE;
    }
  m->text[n] = 0;
  m->is_event = g_str_has_prefix (m->text, "event ");
  m->ok = g_str_has_prefix (m->text, "ok");
  m->type = 0;
  memset (m->d, 0, sizeof (m->d));
  if (m->is_event)
    sscanf (m->text, "event %d %u %u %u", &m->type, &m->d[0], &m->d[1], &m->d[2]);
  fp_dbg ("bridge: %s", m->text);
  return TRUE;
}

static GError *
reply_error (const struct message *m)
{
  if (g_str_has_prefix (m->text, "error unauthorized"))
    return fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                     "Enrolment needs the owner's credential: "
                                     "confirm it and start again");
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                   "fingerprint bridge: %s", m->text);
}

static GError *
hal_error (guint32 code)
{
  switch (code)
    {
    case ERROR_TIMEOUT:
      return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                                  "Fingerprint operation timed out");
    case ERROR_CANCELED:
      return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                  "Fingerprint operation cancelled");
    case ERROR_NO_SPACE:
      return fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL);
    default:
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                       "fingerprint HAL error %u", code);
    }
}

static GError *
retry_for (guint32 acquired)
{
  switch (acquired)
    {
    case ACQUIRED_PARTIAL:
    case ACQUIRED_INSUFFICIENT:
      return fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL);
    case ACQUIRED_IMAGER_DIRTY:
      return fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER);
    case ACQUIRED_TOO_SLOW:
      return fpi_device_retry_new (FP_DEVICE_RETRY_TOO_SHORT);
    case ACQUIRED_TOO_FAST:
      return fpi_device_retry_new (FP_DEVICE_RETRY_TOO_FAST);
    default:
      return NULL;  /* good, or a vendor code (>= 1000): nothing to tell the user */
    }
}

static gboolean
progress_in_main (gpointer user_data)
{
  struct progress_event *event = user_data;
  if (event->finger_status != (FpFingerStatusFlags) -1)
    fpi_device_report_finger_status (FP_DEVICE (event->self), event->finger_status);
  if (event->completed >= 0 || event->retry)
    fpi_device_enroll_progress (FP_DEVICE (event->self), MAX (event->completed, 0),
                                NULL, g_steal_pointer (&event->retry));
  g_object_unref (event->self);
  g_free (event);
  return G_SOURCE_REMOVE;
}

static void
queue_progress (FpiDeviceAndroidHal *self, FpFingerStatusFlags finger_status,
                gint completed, GError *retry)
{
  struct progress_event *event = g_new0 (struct progress_event, 1);
  event->self = g_object_ref (self);
  event->finger_status = finger_status;
  event->completed = completed;
  event->retry = retry;
  g_main_context_invoke (NULL, progress_in_main, event);
}

/* the finger status while an operation waits for a finger: needed, and present while a finger is down */
static FpFingerStatusFlags
waiting (gboolean present)
{
  return FP_FINGER_STATUS_NEEDED | (present ? FP_FINGER_STATUS_PRESENT : 0);
}

/* a request whose only answer is the reply */
static gboolean
call (FpiDeviceAndroidHal *self, GError **error, const char *request)
{
  struct message m;
  if (!send_request (self, error, "%s", request))
    return FALSE;
  do
    if (!receive (self, NULL, &m, error))
      return FALSE;
  while (m.is_event);
  if (!m.ok)
    {
      g_propagate_error (error, reply_error (&m));
      return FALSE;
    }
  return TRUE;
}

/* an operation stopped by the user: cancel it at the HAL, then read up to the cancel's own reply */
static void
cancel_operation (FpiDeviceAndroidHal *self)
{
  g_autoptr(GError) error = NULL;
  if (!call (self, &error, "cancel"))
    fp_warn ("cancelling at the fingerprint bridge failed: %s", error->message);
}

/* the templates: enumerate, its events until the last one (remaining 0) and the reply */
static GArray *
list_fingers (FpiDeviceAndroidHal *self, GError **error)
{
  g_autoptr(GArray) fingers = g_array_new (FALSE, FALSE, sizeof (struct finger));
  gboolean replied = FALSE, last = FALSE;
  struct message m;

  if (!send_request (self, error, "list"))
    return NULL;
  while (!replied || !last)
    {
      if (!receive (self, NULL, &m, error))
        return NULL;
      if (!m.is_event)
        {
          if (!m.ok)
            {
              g_propagate_error (error, reply_error (&m));
              return NULL;
            }
          replied = TRUE;
        }
      else if (m.type == MSG_TEMPLATE_ENUMERATING)
        {
          struct finger f = { m.d[0], m.d[1] };
          if (f.finger_id)
            g_array_append_val (fingers, f);
          last = m.d[2] == 0;
        }
      else if (m.type == MSG_ERROR)
        {
          g_propagate_error (error, hal_error (m.d[0]));
          return NULL;
        }
    }
  return g_steal_pointer (&fingers);
}

static gboolean
delete_finger (FpiDeviceAndroidHal *self, guint32 finger, GError **error)
{
  gboolean replied = FALSE, removed = FALSE;
  struct message m;

  if (!send_request (self, error, "remove %u", finger))
    return FALSE;
  while (!replied || !removed)
    {
      if (!receive (self, NULL, &m, error))
        return FALSE;
      if (!m.is_event)
        {
          if (!m.ok)
            {
              g_propagate_error (error, reply_error (&m));
              return FALSE;
            }
          replied = TRUE;
        }
      else if (m.type == MSG_TEMPLATE_REMOVED)
        {
          removed = m.d[2] == 0;
        }
      else if (m.type == MSG_ERROR)
        {
          g_propagate_error (error, hal_error (m.d[0]));
          return FALSE;
        }
    }
  return TRUE;
}

/* enroll and identify: the request, then the HAL's events until a result, an error or the user's cancel */
static struct finger *
interactive (FpiDeviceAndroidHal *self, gboolean enrolling, GCancellable *cancellable,
             GError **error)
{
  FpDevice *device = FP_DEVICE (self);
  gint stages = fp_device_get_nr_enroll_stages (device), last_completed = -1;
  struct finger *result = NULL;
  gboolean present = FALSE;
  struct message m;

  queue_progress (self, waiting (FALSE), -1, NULL);
  if (enrolling ? !send_request (self, error, "enroll %u", self->enroll_timeout)
                : !send_request (self, error, "identify"))
    return NULL;
  for (;;)
    {
      g_autoptr(GError) local = NULL;
      if (!receive (self, cancellable, &m, &local))
        {
          if (g_error_matches (local, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            cancel_operation (self);
          g_propagate_error (error, g_steal_pointer (&local));
          break;
        }
      if (!m.is_event)
        {
          if (!m.ok)  /* the request itself was refused */
            {
              g_propagate_error (error, reply_error (&m));
              break;
            }
          continue;
        }
      if (m.type == MSG_ACQUIRED)
        {
          GError *retry = retry_for (m.d[0]);
          if (self->acquired_down && m.d[0] == self->acquired_down)
            present = TRUE;
          else if (self->acquired_up && m.d[0] == self->acquired_up)
            present = FALSE;
          if (enrolling && retry)
            queue_progress (self, waiting (present), -1, retry);
          else
            {
              g_clear_error (&retry);
              queue_progress (self, waiting (present), -1, NULL);
            }
        }
      else if (m.type == MSG_TEMPLATE_ENROLLING && enrolling)
        {
          /* the HAL counts down; a HAL that wants more samples than announced stretches the scale */
          if ((gint) m.d[2] >= stages)
            stages = (gint) m.d[2] + 1;
          gint completed = CLAMP (stages - (gint) m.d[2], 0, stages);
          if (completed != last_completed)
            queue_progress (self, waiting (present), completed, NULL);
          last_completed = completed;
          if (m.d[2] == 0)
            {
              g_autoptr(GError) end_error = NULL;
              if (!call (self, &end_error, "enroll-end"))
                fp_warn ("enroll-end: %s", end_error->message);
              result = g_new0 (struct finger, 1);
              result->group_id = m.d[0];
              result->finger_id = m.d[1];
              break;
            }
        }
      else if (m.type == MSG_AUTHENTICATED && !enrolling)
        {
          result = g_new0 (struct finger, 1);
          result->group_id = m.d[0];
          result->finger_id = m.d[1];  /* 0: no match */
          if (!result->finger_id)
            cancel_operation (self);  /* one attempt per identify */
          break;
        }
      else if (m.type == MSG_ERROR)
        {
          if (enrolling)
            {
              g_autoptr(GError) end_error = NULL;
              if (!call (self, &end_error, "enroll-end"))
                fp_warn ("enroll-end: %s", end_error->message);
            }
          g_propagate_error (error, hal_error (m.d[0]));
          break;
        }
    }
  queue_progress (self, FP_FINGER_STATUS_NONE, -1, NULL);
  return result;
}

static void
worker_thread (GTask *task, gpointer object, gpointer task_data, GCancellable *cancellable)
{
  FpiDeviceAndroidHal *self = object;
  struct worker_data *work = task_data;
  g_autoptr(GError) error = NULL;

  switch (work->operation)
    {
    case WORK_OPEN:
      {
        g_autoptr(GSocketAddress) address = g_unix_socket_address_new (self->socket_path);
        self->socket = g_socket_new (G_SOCKET_FAMILY_UNIX, G_SOCKET_TYPE_SEQPACKET,
                                     G_SOCKET_PROTOCOL_DEFAULT, &error);
        if (self->socket && g_socket_connect (self->socket, address, NULL, &error) &&
            call (self, &error, "info"))
          {
            g_task_return_boolean (task, TRUE);
            return;
          }
        g_clear_object (&self->socket);
        break;
      }
    case WORK_CLOSE:
      if (self->socket)
        g_socket_close (self->socket, NULL);
      g_clear_object (&self->socket);
      g_task_return_boolean (task, TRUE);
      return;
    case WORK_LIST:
      {
        GArray *fingers = list_fingers (self, &error);
        if (!fingers)
          break;
        g_task_return_pointer (task, fingers, (GDestroyNotify) g_array_unref);
        return;
      }
    case WORK_DELETE:
      if (!delete_finger (self, work->finger_id, &error))
        break;
      g_task_return_boolean (task, TRUE);
      return;
    case WORK_ENROLL:
    case WORK_IDENTIFY:
      {
        struct finger *result = interactive (self, work->operation == WORK_ENROLL,
                                             cancellable, &error);
        if (!result)
          break;
        g_task_return_pointer (task, result, g_free);
        return;
      }
    }
  g_task_return_error (task, g_steal_pointer (&error));
}

static void
start_worker (FpiDeviceAndroidHal *self, enum worker_operation operation, guint32 group,
              guint32 finger, GAsyncReadyCallback callback)
{
  g_autoptr(GTask) task = g_task_new (self,
      operation == WORK_OPEN || operation == WORK_CLOSE ? NULL :
      fpi_device_get_cancellable (FP_DEVICE (self)), callback, NULL);
  struct worker_data *work = g_new0 (struct worker_data, 1);
  work->operation = operation;
  work->group_id = group;
  work->finger_id = finger;
  g_task_set_task_data (task, work, g_free);
  g_task_run_in_thread (task, worker_thread);
}

static void
set_print_data (FpPrint *print, guint32 group, guint32 finger)
{
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", g_variant_new ("(uu)", group, finger), NULL);
}

static gboolean
parse_print (FpPrint *print, guint32 *group, guint32 *finger)
{
  g_autoptr(GVariant) data = NULL;
  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE ("(uu)")))
    return FALSE;
  g_variant_get (data, "(uu)", group, finger);
  return TRUE;
}

static void open_done (GObject *o, GAsyncResult *r, gpointer unused)
{ g_autoptr(GError) e = NULL; (void) unused; g_task_propagate_boolean (G_TASK (r), &e); fpi_device_open_complete (FP_DEVICE (o), g_steal_pointer (&e)); }
static void close_done (GObject *o, GAsyncResult *r, gpointer unused)
{ g_autoptr(GError) e = NULL; (void) unused; g_task_propagate_boolean (G_TASK (r), &e); fpi_device_close_complete (FP_DEVICE (o), g_steal_pointer (&e)); }
static void delete_done (GObject *o, GAsyncResult *r, gpointer unused)
{ g_autoptr(GError) e = NULL; (void) unused; g_task_propagate_boolean (G_TASK (r), &e); fpi_device_delete_complete (FP_DEVICE (o), g_steal_pointer (&e)); }

static void
list_done (GObject *object, GAsyncResult *async_result, gpointer unused)
{
  FpDevice *device = FP_DEVICE (object);
  g_autoptr(GError) error = NULL;
  g_autoptr(GArray) fingers = g_task_propagate_pointer (G_TASK (async_result), &error);
  GPtrArray *prints;
  (void) unused;
  if (!fingers)
    {
      fpi_device_list_complete (device, NULL, g_steal_pointer (&error));
      return;
    }
  prints = g_ptr_array_new_with_free_func (g_object_unref);
  for (guint i = 0; i < fingers->len; i++)
    {
      struct finger *f = &g_array_index (fingers, struct finger, i);
      FpPrint *print = fp_print_new (device);
      set_print_data (print, f->group_id, f->finger_id);
      g_ptr_array_add (prints, g_object_ref_sink (print));
    }
  fpi_device_list_complete (device, prints, NULL);
}

static void
enroll_done (GObject *object, GAsyncResult *async_result, gpointer unused)
{
  FpDevice *device = FP_DEVICE (object);
  g_autoptr(GError) error = NULL;
  g_autofree struct finger *result = g_task_propagate_pointer (G_TASK (async_result), &error);
  FpPrint *print = NULL;
  (void) unused;
  if (!result)
    {
      fpi_device_enroll_complete (device, NULL, g_steal_pointer (&error));
      return;
    }
  fpi_device_get_enroll_data (device, &print);
  set_print_data (print, result->group_id, result->finger_id);
  fpi_device_enroll_complete (device, g_object_ref (print), NULL);
}

static void
identify_done (GObject *object, GAsyncResult *async_result, gpointer unused)
{
  FpDevice *device = FP_DEVICE (object);
  g_autoptr(GError) error = NULL;
  g_autofree struct finger *result = g_task_propagate_pointer (G_TASK (async_result), &error);
  GPtrArray *gallery = NULL;
  FpPrint *match = NULL, *scan = NULL;
  (void) unused;
  if (!result)
    {
      fpi_device_identify_complete (device, g_steal_pointer (&error));
      return;
    }
  if (result->finger_id)
    {
      scan = fp_print_new (device);
      set_print_data (scan, result->group_id, result->finger_id);
      g_object_ref_sink (scan);
      fpi_device_get_identify_data (device, &gallery);
      for (guint i = 0; i < gallery->len; i++)
        {
          guint32 group, finger;
          if (parse_print (g_ptr_array_index (gallery, i), &group, &finger) &&
              group == result->group_id && finger == result->finger_id)
            {
              match = g_ptr_array_index (gallery, i);
              break;
            }
        }
    }
  fpi_device_identify_report (device, match, scan, NULL);
  fpi_device_identify_complete (device, NULL);
  g_clear_object (&scan);
}

static void hal_open (FpDevice *d) { start_worker (FPI_DEVICE_ANDROIDHAL (d), WORK_OPEN, 0, 0, open_done); }
static void hal_close (FpDevice *d) { start_worker (FPI_DEVICE_ANDROIDHAL (d), WORK_CLOSE, 0, 0, close_done); }
static void hal_list (FpDevice *d) { start_worker (FPI_DEVICE_ANDROIDHAL (d), WORK_LIST, 0, 0, list_done); }
static void hal_enroll (FpDevice *d) { start_worker (FPI_DEVICE_ANDROIDHAL (d), WORK_ENROLL, 0, 0, enroll_done); }

static void
hal_identify (FpDevice *d)
{
  GPtrArray *gallery = NULL;

  /* nothing to match against (fprintd's identify-before-enroll on an empty device): no match, sensor untouched */
  fpi_device_get_identify_data (d, &gallery);
  if (!gallery || gallery->len == 0)
    {
      fpi_device_identify_report (d, NULL, NULL, NULL);
      fpi_device_identify_complete (d, NULL);
      return;
    }
  start_worker (FPI_DEVICE_ANDROIDHAL (d), WORK_IDENTIFY, 0, 0, identify_done);
}

static void
hal_delete (FpDevice *device)
{
  FpPrint *print = NULL;
  guint32 group, finger;
  fpi_device_get_delete_data (device, &print);
  if (!parse_print (print, &group, &finger))
    {
      fpi_device_delete_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }
  start_worker (FPI_DEVICE_ANDROIDHAL (device), WORK_DELETE, group, finger, delete_done);
}

static void
hal_cancel (FpDevice *device)
{
  /* the worker sees the action's cancellable and cancels at the bridge itself */
  (void) device;
}

static void
hal_probe (FpDevice *device)
{
  FpiDeviceAndroidHal *self = FPI_DEVICE_ANDROIDHAL (device);
  guint stages = env_uint ("FP_ANDROIDHAL_ENROLL_STAGES", 0);

  self->socket_path = g_strdup (g_getenv ("FP_ANDROIDHAL_SOCKET"));
  self->enroll_timeout = env_uint ("FP_ANDROIDHAL_ENROLL_TIMEOUT", 0);
  self->acquired_down = env_uint ("FP_ANDROIDHAL_ACQUIRED_FINGER_DOWN", 0);
  self->acquired_up = env_uint ("FP_ANDROIDHAL_ACQUIRED_FINGER_UP", 0);
  if (!self->socket_path || !*self->socket_path || !stages)
    {
      fpi_device_probe_complete (device, NULL, NULL,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                   "FP_ANDROIDHAL_SOCKET and FP_ANDROIDHAL_ENROLL_STAGES are not set"));
      return;
    }
  fpi_device_set_nr_enroll_stages (device, stages);
  fpi_device_probe_complete (device, self->socket_path, NULL, NULL);
}

static void
fpi_device_androidhal_init (FpiDeviceAndroidHal *self)
{
  (void) self;
}

static void
fpi_device_androidhal_finalize (GObject *object)
{
  FpiDeviceAndroidHal *self = FPI_DEVICE_ANDROIDHAL (object);
  g_clear_object (&self->socket);
  g_clear_pointer (&self->socket_path, g_free);
  G_OBJECT_CLASS (fpi_device_androidhal_parent_class)->finalize (object);
}

static void
fpi_device_androidhal_class_init (FpiDeviceAndroidHalClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);
  object_class->finalize = fpi_device_androidhal_finalize;
  device_class->id = FP_COMPONENT;
  device_class->full_name = "Android fingerprint HAL (bridged)";
  device_class->type = FP_DEVICE_TYPE_UDEV;
  device_class->id_table = id_table;
  device_class->scan_type = FP_SCAN_TYPE_PRESS;
  device_class->temp_hot_seconds = -1;
  device_class->open = hal_open;
  device_class->probe = hal_probe;
  device_class->close = hal_close;
  device_class->list = hal_list;
  device_class->delete = hal_delete;
  device_class->enroll = hal_enroll;
  device_class->identify = hal_identify;
  device_class->cancel = hal_cancel;
  fpi_device_class_auto_initialize_features (device_class);
  /* the HAL's TA refuses a finger it already holds; this also skips fprintd's identify-before-enroll */
  device_class->features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;
}
