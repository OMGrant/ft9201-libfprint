/*
 * Focal-systems FT9201 USB fingerprint reader driver for libfprint
 *
 * Copyright (C) 2026 Grant Garrison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Protocol reverse-engineered from:
 *   - banianitc/ft9201-fingerprint-driver (GPLv2)
 *   - FocalTech libfprint .deb (Feb 2025, v1.94.4)
 *   - Manual USB traffic analysis / binary disassembly
 *
 * Supported devices:
 *   2808:93a9 - Focal-systems.Corp FT9201Fingerprint (standalone USB reader)
 *
 * Init sequence overview:
 *   1. WakeupSensor x2  (req=0x22, val=0x70, idx=0x70)
 *   2. Read reg 0x90    (req=0x64 setup + req=0x60 read)
 *   3. F906 command     (req=0x64, val=0x0603, idx=0x00f9)
 *   4. WriteData        (req=0x34 arm + req=0x35 size + bulk 11ee0200)
 *   5. Hw reg a4=1      (req=0x03, val=1, idx=0xa4)
 *   6. Sensor status    (req=0x30, idx=0x85c0 → 0xfe = default path)
 *   7. MCUDownloadMode  (req=0x57)
 *   8. Detect sensor type via NEW SPI protocol:
 *        req=0x66 writes + req=0x65 reads → type byte @ idx=0xf3
 *        type = (raw >> 1) & 0xF; type 3 → FT9348W
 *   9. Firmware upload:
 *        req=0x34(0xff) reset + req=0x34(0x02) mode + req=0x35(64) chunk size
 *        + 64-byte bulk chunks of ft9348 firmware blob
 *  10. SensorReset      (req=0x40, val=0, idx=0) — NOT req=0x22!
 *  11. msleep(160)
 *  12. WakeupSensor x2
 *  13. Poll req=0x3a idx=0x20 len=2 for [0xa5, 0x5a]  (MCU ready)
 *  14. Read sensor dimensions (reg 0x14, 0x15)
 */

#define FP_COMPONENT "ft9201"
#include "fpi-log.h"
#include "drivers_api.h"

/* ------------------------------------------------------------------ */
/* Embedded FT9348W firmware                                           */
/* ------------------------------------------------------------------ */
#include "ft9201_fw.h"
#include "ft_engine.h"
#include <math.h>

/* ------------------------------------------------------------------ */
/* USB constants                                                        */
/* ------------------------------------------------------------------ */

#define FT9201_EP_OUT           0x02
#define FT9201_EP_IN            0x83

/* Control request codes */
#define REQ_WAKEUP              0x22  /* OUT val=0x70 idx=0x70 */
#define REQ_HW_REG              0x03  /* OUT write hw register */
#define REQ_BULK_ARM            0x34  /* OUT arm / reset bulk endpoint */
#define REQ_BULK_SIZE           0x35  /* OUT set chunk size */
#define REQ_SUI_CMD             0x64  /* OUT SUI command */
#define REQ_SUI_READ            0x60  /* IN  SUI register readback */
#define REQ_STATUS              0x30  /* IN  sensor status */
#define REQ_MCU_DL_MODE         0x57  /* OUT enter MCU download mode */
#define REQ_SPI_WRITE           0x66  /* OUT new-protocol SPI write */
#define REQ_SPI_READ            0x65  /* IN  new-protocol SPI read */
#define REQ_AFE_READ            0x3a  /* IN  read AFE register */
#define REQ_AFE_WRITE           0x3b  /* OUT write AFE register (val=value, idx=reg) */
#define REQ_SENSOR_RESET        0x40  /* OUT hardware MCU reset */

/* AFE register indices */
#define REG_DIM_W               0x14
#define REG_DIM_H               0x15
#define REG_MCU_STATUS          0x20  /* [0xa5,0x5a] → ready */
#define REG_DATA_READY          0x30  /* 0xbb → image available */
#define REG_FINGER              0x1d  /* 0x01 idle, 0xa0 finger present */
#define REG_VARIANT_CFG1        0x22  /* variant config byte 1 (write 0x00) */
#define REG_VARIANT_CFG2        0x23  /* variant config byte 2 (write 0x0e) */
#define REG_POWER_1F            0x1f  /* AFE power control (write 0x01 to power on) */
#define REG_POWER_1E            0x1e  /* AFE power control (write 0x01 to power on) */

/* Timeouts */
#define CTRL_TIMEOUT            5000
#define BULK_TIMEOUT            5000

/* Sensor geometry fallback */
#define DEFAULT_WIDTH           96
#define DEFAULT_HEIGHT          96

/* Firmware chunk size */
#define FW_CHUNK                64

/* Sensor type, bits 1..4 of SPI register 0xf3 */
#define SENSOR_TYPE_FT9348W     2
#define SENSOR_TYPE_FT9348W_B   3
#define SENSOR_TYPE_FT9361W     4
#define SENSOR_TYPE_64X80       14  /* raw 0x3c: native 64x80 frame */

/* ------------------------------------------------------------------ */
/* Device struct                                                        */
/* ------------------------------------------------------------------ */

struct _FpiDeviceFt9201
{
  FpDevice parent;

  FpiSsm   *loop_ssm;
  guint8    sensor_width;
  guint8    sensor_height;
  guint8   *image_buf;        /* raw scan + 2 quality bytes (w*h+2) */
  guint8   *background_buf;   /* FPN background frame */
  gboolean  has_background;

  /* Image matching state */
  guint32  *accum_buf;        /* enrollment accumulator (w*h uint32) */
  guint8   *tmpl_buf;         /* stored enrollment template (w*h) */
  guint     enroll_done;      /* enrollment stages completed */
  FpPrint  *cur_print;        /* FpPrint being enrolled or verified against */
  gboolean  is_verify;        /* current operation type */
  gboolean  scan_ok;          /* SCAN_SUBMIT sets TRUE if image was accepted */

  /* Vendor engine (ft_engine): opaque template blob for verify */
  gboolean  engine_ok;        /* engine initialized */
  guint8   *tmpl_blob;        /* committed engine template (verify) */
  gsize     tmpl_len;

  /* scratch buffers */
  guint8    sensor_variant;
  guint8    reg_buf[4];
  guint8    fw_chunk_buf[FW_CHUNK];
  guint     fw_offset;
  guint     fw_retries;
};

G_DECLARE_FINAL_TYPE (FpiDeviceFt9201, fpi_device_ft9201,
                      FPI, DEVICE_FT9201, FpDevice)
G_DEFINE_TYPE (FpiDeviceFt9201, fpi_device_ft9201, FP_TYPE_DEVICE)

/* ================================================================== */
/* Generic USB helpers                                                 */
/* ================================================================== */

static void
ctrl_out_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  if (err)
    fpi_ssm_mark_failed (t->ssm, err);
  else
    fpi_ssm_next_state (t->ssm);
}

/* vendor OUT, no data payload */
static void
ctrl_out (FpiSsm *ssm, FpDevice *dev,
          guint8 req, guint16 val, guint16 idx)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  t->ssm = ssm;
  fpi_usb_transfer_fill_control (t,
    G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
    G_USB_DEVICE_REQUEST_TYPE_VENDOR,
    G_USB_DEVICE_RECIPIENT_DEVICE,
    req, val, idx, 0);
  fpi_usb_transfer_submit (t, CTRL_TIMEOUT,
    fpi_device_get_cancellable (dev), ctrl_out_cb, NULL);
}

/* vendor IN, reads `len` bytes into self->reg_buf, then calls `cb` */
static void
ctrl_in (FpiSsm *ssm, FpDevice *dev,
         guint8 req, guint16 val, guint16 idx, guint16 len,
         FpiUsbTransferCallback cb)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  t->ssm = ssm;
  fpi_usb_transfer_fill_control (t,
    G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
    G_USB_DEVICE_REQUEST_TYPE_VENDOR,
    G_USB_DEVICE_RECIPIENT_DEVICE,
    req, val, idx, len);
  fpi_usb_transfer_submit (t, CTRL_TIMEOUT,
    fpi_device_get_cancellable (dev), cb, NULL);
}


/* ================================================================== */
/* Init state machine                                                  */
/* ================================================================== */

enum {
  /* ---- preamble ---- */
  INIT_WAKE1,           /* WakeupSensor 1 */
  INIT_WAKE2,           /* WakeupSensor 2 */
  INIT_REG90_SETUP,     /* req=0x64 val=0x9001 idx=0 */
  INIT_REG90_READ,      /* req=0x60 read */
  INIT_F906,            /* req=0x64 val=0x0603 idx=0x00f9 */
  INIT_BULK_ARM,        /* req=0x34 val=2 idx=0 */
  INIT_BULK_SIZE4,      /* req=0x35 val=4 idx=0x85c0 */
  INIT_BULK_PAYLOAD,    /* bulk-out 11ee0200 */
  INIT_HW_A4,           /* req=0x03 val=1 idx=0xa4 */
  INIT_SENSOR_STATUS,   /* req=0x30 idx=0x85c0 → ignore result */

  /* ---- sensor type detection (new SPI protocol) ---- */
  INIT_MCU_DL,          /* req=0x57 */
  INIT_SPI_W_C8,        /* req=0x66 val=0x00df idx=0xc8 */
  INIT_SPI_R_C8,        /* req=0x65 read idx=0xc8 (byte1, ignored) */
  INIT_SPI_W_F1,        /* req=0x66 val=0x001d idx=0xf1 */
  INIT_SPI_R_F4,        /* req=0x65 read idx=0xf4 (byte2) */
  INIT_SPI_W_F4,        /* req=0x66 val=(byte2|1) idx=0xf4 */
  INIT_SPI_R_F3,        /* req=0x65 read idx=0xf3 → type byte */
  INIT_SPI_FIN,         /* req=0x66 val=0 idx=0xf4 (finalize) */

  /* ---- firmware upload ---- */
  INIT_FW_WAKE1,        /* WakeupSensor before LoadFW */
  INIT_FW_WAKE2,
  INIT_FW_MCU_DL,       /* req=0x57 again */
  INIT_FW_RESET_EP,     /* req=0x34 val=0xff idx=0 */
  INIT_FW_DL_MODE,      /* req=0x34 val=0x02 idx=0 */
  INIT_FW_BRIDGE_VER,   /* req=0x1a read (GetBridgeVersion, ignored) */
  INIT_FW_CHUNK_SIZE,   /* req=0x35 val=64 idx=0 */
  INIT_FW_UPLOAD,       /* bulk-out loop: handled in state handler */

  /* ---- post-upload MCU config (from vendor blob: InitMcuConfig +
   *      SwitchNextSensorWorkMode) — this is what makes the MCU run the
   *      firmware. All AFE writes: req 0x3b, wValue=value, wIndex=reg. ---- */
  INIT_CFG_R01,         /* reg 0x01 = 0x01 */
  INIT_CFG_R41,         /* reg 0x41 = 0x0f */
  INIT_CFG_R30,         /* reg 0x30 = 0xbb */
  INIT_CFG_R30_RD,      /* read reg 0x30 (ignored) */
  INIT_CFG_R22,         /* reg 0x22 = 0x00 */
  INIT_CFG_R23,         /* reg 0x23 = 0x0e */
  INIT_CFG_R54,         /* reg 0x54 = 0x01 (SwitchNextSensorWorkMode) */
  INIT_CFG_R1F,         /* reg 0x1f = 0x01 (power on) */
  INIT_CFG_R1E,         /* reg 0x1e = 0x01 (power on) */

  /* ---- post-upload reset & MCU poll ---- */
  INIT_SENSOR_RESET,    /* req=0x40 val=0 idx=0  ← the real MCU reset */
  INIT_RESET_DELAY,     /* 160 ms sleep */
  INIT_POST_WAKE1,      /* WakeupSensor 1 */
  INIT_POST_WAKE2,      /* WakeupSensor 2 */
  INIT_MCU_WAIT,        /* 2 ms delay between polls */
  INIT_MCU_POLL,        /* read reg 0x20 len=2; loops back to MCU_WAIT if not ready */

  /* ---- read dimensions ---- */
  INIT_READ_W,
  INIT_READ_H,

  /* ---- variant 2/3 (FT9348W) AFE power-on ---- */
  INIT_POWER_CFG1,          /* REG_VARIANT_CFG1 (0x22) = 0x00 */
  INIT_POWER_CFG2,          /* REG_VARIANT_CFG2 (0x23) = 0x0e */
  INIT_POWER_1F,            /* REG_POWER_1F (0x1f) = 0x01 */
  INIT_POWER_1E,            /* REG_POWER_1E (0x1e) = 0x01 */

  INIT_NUM_STATES,
};

/* ---- preamble callbacks ---- */

/* FT9348W (types 2/3) and the 0x3c unit seen on 2808:93a9 (type 14) need the
 * extra AFE power-on writes. */
static gboolean
needs_afe_power_on (FpiDeviceFt9201 *self)
{
  return self->sensor_variant == SENSOR_TYPE_FT9348W ||
         self->sensor_variant == SENSOR_TYPE_FT9348W_B ||
         self->sensor_variant == SENSOR_TYPE_64X80;
}

static void
ignore_read_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  /* swallow errors on optional reads, just advance */
  if (err)
    g_error_free (err);
  fpi_ssm_next_state (t->ssm);
}

static void
bulk_payload_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }
  fpi_ssm_next_state (t->ssm);
}

/* ---- SPI detection callbacks ---- */

static void
spi_r_f4_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }
  self->reg_buf[0] = t->buffer[0];   /* byte2 for next write */
  fpi_ssm_next_state (t->ssm);
}

static void
spi_r_f3_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  guint8 raw, type;
  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }
  raw  = t->buffer[0];
  type = (raw >> 1) & 0x0f;
  self->sensor_variant = type;
  fp_dbg ("ft9201: SPI type_raw=0x%02x  sensor_type=%u (%s)",
          raw, type,
          type == SENSOR_TYPE_FT9348W   ? "FT9348W" :
          type == SENSOR_TYPE_FT9348W_B ? "FT9348W(var)" :
          type == SENSOR_TYPE_FT9361W   ? "FT9361W" :
          type == SENSOR_TYPE_64X80     ? "64x80" : "unknown");
  fpi_ssm_next_state (t->ssm);
}

/* ---- firmware upload callbacks ---- */

static void
fw_chunk_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }
  self->fw_offset += FW_CHUNK;
  /* stay in INIT_FW_UPLOAD — the state handler loops until done */
  fpi_ssm_jump_to_state (t->ssm, INIT_FW_UPLOAD);
}

/* ---- MCU poll callback ---- */

static void
mcu_poll_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);

  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }

  if (t->buffer[0] == 0xa5 && t->buffer[1] == 0x5a)
    {
      fp_dbg ("ft9201: MCU ready after %u polls", self->fw_retries + 1);
      fpi_ssm_next_state (t->ssm);
      return;
    }

  self->fw_retries++;
  if (self->fw_retries > 200)   /* ~400 ms total */
    {
      fpi_ssm_mark_failed (t->ssm,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                  "ft9201: MCU did not boot"));
      return;
    }

  /* wait 2 ms then try again */
  fpi_ssm_jump_to_state (t->ssm, INIT_MCU_WAIT);
}

/* ---- dimension callbacks ---- */

static void
read_w_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }
  self->sensor_width = t->buffer[0] ? t->buffer[0] : DEFAULT_WIDTH;
  fpi_ssm_next_state (t->ssm);
}

static void
read_h_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }
  self->sensor_height = t->buffer[0] ? t->buffer[0] : DEFAULT_HEIGHT;

  /* Type 14 reports 96x96 but sends a 64x80 frame in the first 5120 bytes;
   * the rest of the buffer is noise. */
  if (self->sensor_variant == SENSOR_TYPE_64X80)
    {
      self->sensor_width  = 64;
      self->sensor_height = 80;
    }

  fp_dbg ("ft9201: sensor %ux%u", self->sensor_width, self->sensor_height);
  fpi_ssm_next_state (t->ssm);
}

/* ---- init SSM dispatcher ---- */

static void
init_ssm_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  FpiUsbTransfer *t;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    /* --- preamble --- */
    case INIT_WAKE1:
      ctrl_out (ssm, dev, REQ_WAKEUP, 0x70, 0x70);
      break;
    case INIT_WAKE2:
      ctrl_out (ssm, dev, REQ_WAKEUP, 0x70, 0x70);
      break;
    case INIT_REG90_SETUP:
      ctrl_out (ssm, dev, REQ_SUI_CMD, 0x9001, 0x0000);
      break;
    case INIT_REG90_READ:
      ctrl_in (ssm, dev, REQ_SUI_READ, 0, 0, 1, ignore_read_cb);
      break;
    case INIT_F906:
      ctrl_out (ssm, dev, REQ_SUI_CMD, 0x0603, 0x00f9);
      break;
    case INIT_BULK_ARM:
      ctrl_out (ssm, dev, REQ_BULK_ARM, 0x0002, 0x0000);
      break;
    case INIT_BULK_SIZE4:
      ctrl_out (ssm, dev, REQ_BULK_SIZE, 0x0004, 0x85c0);
      break;
    case INIT_BULK_PAYLOAD:
      {
        static const guint8 payload[] = { 0x11, 0xee, 0x02, 0x00 };
        t = fpi_usb_transfer_new (dev);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk_full (t, FT9201_EP_OUT,
                                         (guint8 *) payload, sizeof payload,
                                         NULL);
        fpi_usb_transfer_submit (t, BULK_TIMEOUT,
          fpi_device_get_cancellable (dev), bulk_payload_cb, NULL);
      }
      break;
    case INIT_HW_A4:
      ctrl_out (ssm, dev, REQ_HW_REG, 0x0001, 0x00a4);
      break;
    case INIT_SENSOR_STATUS:
      ctrl_in (ssm, dev, REQ_STATUS, 0, 0x85c0, 2, ignore_read_cb);
      break;

    /* --- sensor type detection --- */
    case INIT_MCU_DL:
      ctrl_out (ssm, dev, REQ_MCU_DL_MODE, 0, 0);
      break;
    case INIT_SPI_W_C8:
      ctrl_out (ssm, dev, REQ_SPI_WRITE, 0x00df, 0x00c8);
      break;
    case INIT_SPI_R_C8:
      ctrl_in (ssm, dev, REQ_SPI_READ, 0, 0x00c8, 1, ignore_read_cb);
      break;
    case INIT_SPI_W_F1:
      ctrl_out (ssm, dev, REQ_SPI_WRITE, 0x001d, 0x00f1);
      break;
    case INIT_SPI_R_F4:
      ctrl_in (ssm, dev, REQ_SPI_READ, 0, 0x00f4, 1, spi_r_f4_cb);
      break;
    case INIT_SPI_W_F4:
      ctrl_out (ssm, dev, REQ_SPI_WRITE,
                (guint16) (self->reg_buf[0] | 0x01), 0x00f4);
      break;
    case INIT_SPI_R_F3:
      ctrl_in (ssm, dev, REQ_SPI_READ, 0, 0x00f3, 1, spi_r_f3_cb);
      break;
    case INIT_SPI_FIN:
      ctrl_out (ssm, dev, REQ_SPI_WRITE, 0x0000, 0x00f4);
      break;

    /* --- firmware upload --- */
    case INIT_FW_WAKE1:
      ctrl_out (ssm, dev, REQ_WAKEUP, 0x70, 0x70);
      break;
    case INIT_FW_WAKE2:
      ctrl_out (ssm, dev, REQ_WAKEUP, 0x70, 0x70);
      break;
    case INIT_FW_MCU_DL:
      ctrl_out (ssm, dev, REQ_MCU_DL_MODE, 0, 0);
      break;
    case INIT_FW_RESET_EP:
      ctrl_out (ssm, dev, REQ_BULK_ARM, 0x00ff, 0x0000);
      break;
    case INIT_FW_DL_MODE:
      ctrl_out (ssm, dev, REQ_BULK_ARM, 0x0002, 0x0000);
      break;
    case INIT_FW_BRIDGE_VER:
      ctrl_in (ssm, dev, 0x1a, 0, 0, 2, ignore_read_cb);
      break;
    case INIT_FW_CHUNK_SIZE:
      self->fw_offset = 0;
      ctrl_out (ssm, dev, REQ_BULK_SIZE, FW_CHUNK, 0);
      break;

    case INIT_FW_UPLOAD:
      if (self->fw_offset >= ft9201_fw_size)
        {
          fp_dbg ("ft9201: firmware upload complete (%u bytes)", self->fw_offset);
          fpi_ssm_next_state (ssm);
          break;
        }
      {
        guint remaining = ft9201_fw_size - self->fw_offset;
        guint n = MIN (remaining, (guint) FW_CHUNK);
        memset (self->fw_chunk_buf, 0, FW_CHUNK);
        memcpy (self->fw_chunk_buf, ft9201_fw_data + self->fw_offset, n);
        t = fpi_usb_transfer_new (dev);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk_full (t, FT9201_EP_OUT,
                                         self->fw_chunk_buf, FW_CHUNK, NULL);
        fpi_usb_transfer_submit (t, BULK_TIMEOUT,
          fpi_device_get_cancellable (dev), fw_chunk_cb, NULL);
      }
      break;

    /* --- MCU config writes (make the uploaded firmware run) --- */
    case INIT_CFG_R01:
      ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x01, 0x01);
      break;
    case INIT_CFG_R41:
      ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x0f, 0x41);
      break;
    case INIT_CFG_R30:
      ctrl_out (ssm, dev, REQ_AFE_WRITE, 0xbb, 0x30);
      break;
    case INIT_CFG_R30_RD:
      ctrl_in (ssm, dev, REQ_AFE_READ, 0, 0x30, 1, ignore_read_cb);
      break;
    case INIT_CFG_R22:
      ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x00, 0x22);
      break;
    case INIT_CFG_R23:
      ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x0e, 0x23);
      break;
    case INIT_CFG_R54:
      ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x01, 0x54);
      break;
    case INIT_CFG_R1F:
      ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x01, 0x1f);
      break;
    case INIT_CFG_R1E:
      ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x01, 0x1e);
      break;

    /* --- post-config reset that starts the uploaded firmware --- */
    case INIT_SENSOR_RESET:
      ctrl_out (ssm, dev, REQ_SENSOR_RESET, 0, 0);
      break;
    case INIT_RESET_DELAY:
      fpi_ssm_next_state_delayed (ssm, 160);
      break;
    case INIT_POST_WAKE1:
      ctrl_out (ssm, dev, REQ_WAKEUP, 0x70, 0x70);
      break;
    case INIT_POST_WAKE2:
      ctrl_out (ssm, dev, REQ_WAKEUP, 0x70, 0x70);
      break;

    case INIT_MCU_WAIT:
      fpi_ssm_next_state_delayed (ssm, 2);  /* 2 ms before next poll */
      break;

    case INIT_MCU_POLL:
      ctrl_in (ssm, dev, REQ_AFE_READ, 0, REG_MCU_STATUS, 2, mcu_poll_cb);
      break;

    /* ---- dimension reads ---- */
    case INIT_READ_W:
      ctrl_in (ssm, dev, REQ_AFE_READ, 0, REG_DIM_W, 4, read_w_cb);
      break;
    case INIT_READ_H:
      ctrl_in (ssm, dev, REQ_AFE_READ, 0, REG_DIM_H, 4, read_h_cb);
      break;

    /* ---- variant 2/3 AFE power-on ---- */
    case INIT_POWER_CFG1:
      if (needs_afe_power_on (self))
        ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x00, REG_VARIANT_CFG1);
      else
        fpi_ssm_next_state (ssm);
      break;
    case INIT_POWER_CFG2:
      if (needs_afe_power_on (self))
        ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x0e, REG_VARIANT_CFG2);
      else
        fpi_ssm_next_state (ssm);
      break;
    case INIT_POWER_1F:
      if (needs_afe_power_on (self))
        ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x01, REG_POWER_1F);
      else
        fpi_ssm_next_state (ssm);
      break;
    case INIT_POWER_1E:
      if (needs_afe_power_on (self))
        ctrl_out (ssm, dev, REQ_AFE_WRITE, 0x01, REG_POWER_1E);
      else
        fpi_ssm_next_state (ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}


static void
init_ssm_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);

  if (!error)
    {
      gsize img_bytes = (gsize) self->sensor_width * self->sensor_height;
      self->image_buf    = g_malloc0 (img_bytes + 2);
      self->background_buf = g_malloc0 (img_bytes);

      /* Bring up the vendor matching engine (ftWbioEngineAdapter.dll). */
      const char *dll = g_getenv ("FT9201_ENGINE_DLL");
      if (!dll)
        dll = "/usr/lib/libfprint-2/ftWbioEngineAdapter.dll";
      self->engine_ok = (ft_engine_open (dll) == 0);
      if (!self->engine_ok)
        fp_warn ("ft9201: vendor engine failed to load from %s "
                 "(set FT9201_ENGINE_DLL to override)", dll);
      else
        fp_info ("ft9201: vendor matching engine loaded");
    }
  fpi_device_open_complete (dev, error);
}

/* ================================================================== */
/* Scan loop state machine                                             */
/* ================================================================== */

enum {
  /* Background (FPN) capture — runs at start of every scan cycle */
  SCAN_BG_RESET_EP,       /* 0xff reset for background capture */
  SCAN_BG_CAP_DELAY,      /* 20ms */
  SCAN_BG_ARM,            /* 0x03 arm for background */
  SCAN_BG_CFG_BULK,       /* set bulk transfer size */
  SCAN_BG_READ,           /* bulk-in: capture background frame */
  /* Finger detection and image capture */
  SCAN_WAIT_DELAY,        /* 20ms between 0x1d polls */
  SCAN_WAIT_FINGER,       /* read reg 0x1d; loop until 0xa0 (finger on sensor) */
  SCAN_SETTLE_DELAY,      /* 50ms for finger to fully settle before capture */
  SCAN_START_FF,          /* reset bulk endpoint */
  SCAN_CAP_DELAY,         /* 20ms between reset and arm */
  SCAN_START_03,          /* arm capture with finger already present */
  SCAN_CONFIG_BULK,       /* set bulk transfer size */
  SCAN_READ_IMAGE,        /* bulk-in */
  SCAN_SUBMIT,            /* hand image to libfprint */
  SCAN_WAIT_LIFT_DELAY,   /* 20ms between polls waiting for finger removal */
  SCAN_WAIT_LIFT,         /* read reg 0x1d; loop until != 0xa0 (finger gone) */
  SCAN_NUM_STATES,
};

static void
wait_lift_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }

  if (t->buffer[0] != 0xa0)
    {
      /* Finger has left — scan cycle complete */
      fpi_ssm_mark_completed (t->ssm);
    }
  else
    {
      fpi_ssm_jump_to_state (t->ssm, SCAN_WAIT_LIFT_DELAY);
    }
}

static void
wait_finger_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }

  if (t->buffer[0] == 0xa0)
    {
      /* Finger detected — proceed to arm and capture */
      fpi_ssm_next_state (t->ssm);
    }
  else
    {
      fpi_ssm_jump_to_state (t->ssm, SCAN_WAIT_DELAY);
    }
}

static void
scan_bg_image_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  gsize img_bytes = (gsize) self->sensor_width * self->sensor_height;

  if (!err && t->actual_length >= (gssize) (img_bytes + 2))
    {
      memcpy (self->background_buf, t->buffer + 2, img_bytes);
      self->has_background = TRUE;
    }
  else
    {
      self->has_background = FALSE;
      if (err) g_error_free (err);
    }
  fpi_ssm_next_state (t->ssm);
}

static void
scan_image_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  gsize img_bytes = (gsize) self->sensor_width * self->sensor_height;

  if (err) { fpi_ssm_mark_failed (t->ssm, err); return; }

  if (t->actual_length >= (gssize) (img_bytes + 2))
    {
      /* buffer[0..1] are chip quality bytes; buffer[2..] is image data */
      self->image_buf[img_bytes]     = t->buffer[0];
      self->image_buf[img_bytes + 1] = t->buffer[1];
      fp_dbg ("chip quality bytes: 0x%02x 0x%02x", t->buffer[0], t->buffer[1]);
      memcpy (self->image_buf, t->buffer + 2, img_bytes);
    }
  else
    {
      fp_warn ("ft9201: short read: %zd < %zu",
               (ssize_t) t->actual_length, img_bytes + 2);
      /* Invalidate the previous frame's quality bytes. Otherwise SCAN_SUBMIT
         reads them as ok and feeds the stale frame to the engine (a stale
         frame could match during verify). Both-zero = bad scan, so this takes
         the bad-scan path instead. */
      self->image_buf[img_bytes]     = 0;
      self->image_buf[img_bytes + 1] = 0;
    }

  fpi_ssm_next_state (t->ssm);
}

static void
scan_ssm_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  FpiUsbTransfer *t;
  gsize total;

  /* Fail, don't complete cleanly: scan_ssm_complete restarts the scan on a
   * clean completion with no accepted frame, which recurses forever once
   * the cancellable stays cancelled. */
  if (g_cancellable_is_cancelled (fpi_device_get_cancellable (dev)))
    {
      fpi_ssm_mark_failed (ssm, g_error_new_literal (G_IO_ERROR,
                                                     G_IO_ERROR_CANCELLED,
                                                     "scan cancelled"));
      return;
    }

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_BG_RESET_EP:
      ctrl_out (ssm, dev, REQ_BULK_ARM, 0xff, 0);
      break;

    case SCAN_BG_CAP_DELAY:
      fpi_ssm_next_state_delayed (ssm, 20);
      break;

    case SCAN_BG_ARM:
      ctrl_out (ssm, dev, REQ_BULK_ARM, 0x03, 0);
      break;

    case SCAN_BG_CFG_BULK:
      {
        guint16 size = (guint16) (self->sensor_width * self->sensor_height + 2);
        ctrl_out (ssm, dev, REQ_BULK_SIZE, size, 0x3400);
      }
      break;

    case SCAN_BG_READ:
      {
        total = (gsize) self->sensor_width * self->sensor_height + 2;
        t = fpi_usb_transfer_new (dev);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk (t, FT9201_EP_IN, total);
        fpi_usb_transfer_submit (t, 500,
          fpi_device_get_cancellable (dev), scan_bg_image_cb, NULL);
      }
      break;

    case SCAN_WAIT_DELAY:
      fpi_ssm_next_state_delayed (ssm, 20);
      break;

    case SCAN_WAIT_FINGER:
      ctrl_in (ssm, dev, REQ_AFE_READ, 0, REG_FINGER, 4, wait_finger_cb);
      break;

    case SCAN_SETTLE_DELAY:
      /* 50ms for finger to fully press before capture */
      fpi_ssm_next_state_delayed (ssm, 50);
      break;

    case SCAN_START_FF:
      ctrl_out (ssm, dev, REQ_BULK_ARM, 0xff, 0);
      break;

    case SCAN_CAP_DELAY:
      fpi_ssm_next_state_delayed (ssm, 20);
      break;

    case SCAN_START_03:
      ctrl_out (ssm, dev, REQ_BULK_ARM, 0x03, 0);
      break;

    case SCAN_CONFIG_BULK:
      {
        guint16 size = (guint16) (self->sensor_width * self->sensor_height + 2);
        ctrl_out (ssm, dev, REQ_BULK_SIZE, size, 0x3400);
      }
      break;

    case SCAN_READ_IMAGE:
      total = (gsize) self->sensor_width * self->sensor_height + 2;
      t = fpi_usb_transfer_new (dev);
      t->ssm = ssm;
      fpi_usb_transfer_fill_bulk (t, FT9201_EP_IN, total);
      fpi_usb_transfer_submit (t, BULK_TIMEOUT,
        fpi_device_get_cancellable (dev), scan_image_cb, NULL);
      break;

    case SCAN_SUBMIT:
      {
        gsize img_bytes = (gsize) self->sensor_width * self->sensor_height;

        /* quality bytes (0xdd 0xdd = normal; both 0 = bad scan) */
        self->scan_ok = !(self->image_buf[img_bytes] == 0 &&
                          self->image_buf[img_bytes + 1] == 0);
        fp_dbg ("chip quality=%u/%u ok=%d",
                self->image_buf[img_bytes], self->image_buf[img_bytes + 1],
                self->scan_ok);

        if (self->scan_ok)
          {
            /* FPN correction */
            if (self->has_background && !g_getenv ("FP_NO_FPN"))
              for (gsize i = 0; i < img_bytes; i++)
                {
                  gint v = (gint) self->image_buf[i]
                         - (gint) self->background_buf[i] + 128;
                  self->image_buf[i] = (guint8) CLAMP (v, 0, 255);
                }

            /* histogram stretch */
            guint8 lo = 255, hi = 0;
            for (gsize i = 0; i < img_bytes; i++)
              {
                if (self->image_buf[i] < lo) lo = self->image_buf[i];
                if (self->image_buf[i] > hi) hi = self->image_buf[i];
              }
            if (hi > lo)
              for (gsize i = 0; i < img_bytes; i++)
                self->image_buf[i] = (guint8)
                  (((guint)(self->image_buf[i] - lo) * 255) / (hi - lo));
          }
        fpi_ssm_next_state (ssm);
      }
      break;

    case SCAN_WAIT_LIFT_DELAY:
      fpi_ssm_next_state_delayed (ssm, 20);
      break;

    case SCAN_WAIT_LIFT:
      ctrl_in (ssm, dev, REQ_AFE_READ, 0, REG_FINGER, 4, wait_lift_cb);
      break;

    default:
      g_assert_not_reached ();
    }
}

/* ================================================================== */
/* Scan SSM completion → enroll / verify dispatch                      */
/* ================================================================== */

static void start_scan (FpDevice *dev);  /* forward declaration */

static void
scan_ssm_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  self->loop_ssm = NULL;

  if (error)
    {
      if (self->is_verify)
        fpi_device_verify_complete (dev, error);
      else
        fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  if (!self->scan_ok)
    {
      /* Bad scan. During verify, a report IS the result — so silently re-scan
       * instead of reporting, and only report once we have a real match. */
      if (self->is_verify)
        {
          start_scan (dev);
          return;
        }
      GError *retry = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);
      fpi_device_enroll_progress (dev, self->enroll_done, NULL, g_steal_pointer (&retry));
      start_scan (dev);
      return;
    }

  int w = self->sensor_width, h = self->sensor_height;

  if (!self->engine_ok)
    {
      GError *e = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                            "ft9201: vendor engine not loaded");
      if (self->is_verify)
        fpi_device_verify_complete (dev, e);
      else
        fpi_device_enroll_complete (dev, NULL, e);
      return;
    }

  /* Feed the raw captured frame to the vendor engine (it resizes internally). */
  uint32_t ahr = ft_engine_accept (self->image_buf, w, h,
                                    self->is_verify ? 1 : 4);
  if (ahr != 0)
    {
      /* Engine rejected the frame (quality/format). Verify: silent re-scan.
       * Enroll: report a retry for this stage. */
      if (self->is_verify)
        {
          start_scan (dev);
          return;
        }
      GError *retry = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);
      fpi_device_enroll_progress (dev, self->enroll_done, NULL, g_steal_pointer (&retry));
      start_scan (dev);
      return;
    }

  if (self->is_verify)
    {
      int match = ft_engine_verify (self->tmpl_blob, self->tmpl_len);
      fp_info ("ft9201: engine verify -> %s", match ? "MATCH" : "no match");
      fpi_device_verify_report (dev,
                                match ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                NULL, NULL);
      fpi_device_verify_complete (dev, NULL);
      return;
    }

  /* Enrollment: fold this frame into the engine's template. */
  int st = ft_engine_enroll_update ();
  if (st == 2)
    {
      /* Frame rejected (duplicate area / low quality) — retry same stage. */
      GError *retry = fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER);
      fpi_device_enroll_progress (dev, self->enroll_done, NULL, g_steal_pointer (&retry));
      start_scan (dev);
      return;
    }

  self->enroll_done++;
  guint nr = FP_DEVICE_GET_CLASS (dev)->nr_enroll_stages;
  fpi_device_enroll_progress (dev, self->enroll_done, NULL, NULL);

  if (self->enroll_done < nr && st != 0)
    {
      start_scan (dev);
      return;
    }

  /* Enough coverage (or engine reports complete): commit the template. */
  uint8_t *blob = NULL;
  size_t   blen = 0;
  if (ft_engine_enroll_commit (&blob, &blen) != 0)
    {
      fpi_device_enroll_complete (dev, NULL,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                  "ft9201: engine enroll commit failed"));
      return;
    }

  GVariant *arr = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                              blob, blen, 1);
  GVariant *data = g_variant_new ("(@ay)", arr);
  fpi_print_set_type (self->cur_print, FPI_PRINT_RAW);
  g_object_set (self->cur_print, "fpi-data", data, NULL);
  fp_info ("ft9201: enrollment committed, template %zu bytes", blen);
  free (blob);

  fpi_device_enroll_complete (dev, g_object_ref (self->cur_print), NULL);
}

/* ================================================================== */
/* FpDevice vfuncs                                                     */
/* ================================================================== */

static void
start_scan (FpDevice *dev)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  self->loop_ssm = fpi_ssm_new (dev, scan_ssm_run_state, SCAN_NUM_STATES);
  fpi_ssm_start (self->loop_ssm, scan_ssm_complete);
}

static void
dev_cancel (FpDevice *dev)
{
  /* USB transfers already hold fpi_device_get_cancellable(), so they abort
   * automatically.  The scan SSM will complete with a cancellation error and
   * fpi_device_{enroll,verify}_complete will propagate it upstream. */
}

static void
dev_open (FpDevice *dev)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  GError          *error = NULL;
  FpiSsm          *ssm;

  g_usb_device_claim_interface (fpi_device_get_usb_device (dev), 0, 0, &error);
  if (error) { fpi_device_open_complete (dev, error); return; }

  self->fw_offset  = 0;
  self->fw_retries = 0;

  ssm = fpi_ssm_new (dev, init_ssm_run_state, INIT_NUM_STATES);
  fpi_ssm_start (ssm, init_ssm_complete);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  GError          *error = NULL;

  g_clear_pointer (&self->image_buf,      g_free);
  g_clear_pointer (&self->background_buf, g_free);
  g_clear_pointer (&self->accum_buf,      g_free);
  g_clear_pointer (&self->tmpl_buf,       g_free);
  g_clear_pointer (&self->tmpl_blob,      g_free);
  if (self->engine_ok)
    ft_engine_close ();
  g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, &error);
  fpi_device_close_complete (dev, error);
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  gsize img_bytes = (gsize) self->sensor_width * self->sensor_height;

  self->is_verify    = FALSE;
  self->enroll_done  = 0;
  self->has_background = FALSE;
  (void) img_bytes;

  if (self->engine_ok)
    ft_engine_enroll_begin ();

  fpi_device_get_enroll_data (dev, &self->cur_print);
  start_scan (dev);
}

static void
dev_verify (FpDevice *dev)
{
  FpiDeviceFt9201 *self = FPI_DEVICE_FT9201 (dev);
  gsize img_bytes = (gsize) self->sensor_width * self->sensor_height;

  (void) img_bytes;
  fpi_device_get_verify_data (dev, &self->cur_print);

  /* Load the opaque engine template blob from the stored print. */
  GVariant *data = NULL;
  g_object_get (self->cur_print, "fpi-data", &data, NULL);
  if (!data || !g_variant_check_format_string (data, "(@ay)", FALSE))
    {
      if (data) g_variant_unref (data);
      fpi_device_verify_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                  "ft9201: stored template invalid"));
      return;
    }

  GVariant *arr = NULL;
  g_variant_get (data, "(@ay)", &arr);
  gsize stored_len = 0;
  const guint8 *stored = g_variant_get_fixed_array (arr, &stored_len, 1);

  g_clear_pointer (&self->tmpl_blob, g_free);
  self->tmpl_blob = g_malloc (stored_len);
  memcpy (self->tmpl_blob, stored, stored_len);
  self->tmpl_len  = stored_len;
  g_variant_unref (arr);
  g_variant_unref (data);

  self->is_verify      = TRUE;
  self->has_background = FALSE;
  start_scan (dev);
}

/* ================================================================== */
/* Driver registration                                                 */
/* ================================================================== */

static const FpIdEntry id_table[] = {
  { .vid = 0x2808, .pid = 0x93a9 },
  { .vid = 0,      .pid = 0      },
};

static void
fpi_device_ft9201_init (FpiDeviceFt9201 *self)
{
}

static void
fpi_device_ft9201_class_init (FpiDeviceFt9201Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id               = "ft9201";
  dev_class->full_name        = "Focal-systems FT9201 Fingerprint Reader";
  dev_class->type             = FP_DEVICE_TYPE_USB;
  dev_class->id_table         = id_table;
  dev_class->nr_enroll_stages = 8;
  dev_class->scan_type        = FP_SCAN_TYPE_PRESS;
  dev_class->temp_hot_seconds = -1;

  dev_class->open    = dev_open;
  dev_class->close   = dev_close;
  dev_class->enroll  = dev_enroll;
  dev_class->verify  = dev_verify;
  dev_class->cancel  = dev_cancel;

  fpi_device_class_auto_initialize_features (dev_class);
}
