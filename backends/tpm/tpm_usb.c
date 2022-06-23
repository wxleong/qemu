/*
 *  usb TPM driver
 *
 *  Copyright (c) 2010 - 2013 IBM Corporation
 *  Authors:
 *    Stefan Berger <stefanb@us.ibm.com>
 *
 *  Copyright (C) 2011 IAIK, Graz University of Technology
 *    Author: Andreas Niederl
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */
/*
 * MIT License
 *
 * Copyright (c) 2022 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */
/*
 * This file is taken from tpm_passthrough.c and modified accordingly.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "qemu/sockets.h"
#include "sysemu/tpm_backend.h"
#include "sysemu/tpm_util.h"
#include "tpm_int.h"
#include "qapi/clone-visitor.h"
#include "qapi/qapi-visit-tpm.h"
#include "trace.h"
#include "qom/object.h"
#include "io/channel-socket.h"

#define TYPE_TPM_USB "tpm-usb"
OBJECT_DECLARE_SIMPLE_TYPE(TPMUsbState, TPM_USB)

/* data structures */
struct TPMUsbState {
    TPMBackend parent;

    TPMUsbOptions *options;
    QIOChannel *data_ioc;

    TPMVersion tpm_version;
    size_t tpm_buffersize;
};


/* functions */

static void tpm_usb_cancel_cmd(TPMBackend *tb);

#if 0
static int tpm_usb_unix_read(int fd, uint8_t *buf, uint32_t len)
{
    int ret;
 reread:
    ret = read(fd, buf, len);
    if (ret < 0) {
        if (errno != EINTR && errno != EAGAIN) {
            return -1;
        }
        goto reread;
    }
    return ret;
}
#endif

static void tpm_usb_unix_tx_bufs(TPMUsbState *tpm_usb,
                                 const uint8_t *in, uint32_t in_len,
                                 uint8_t *out, uint32_t out_len,
                                 bool *selftest_done, Error **errp)
{

}

static void tpm_usb_handle_request(TPMBackend *tb, TPMBackendCmd *cmd,
                                           Error **errp)
{
    TPMUsbState *tpm_usb = TPM_USB(tb);

    trace_tpm_usb_handle_request(cmd);

    tpm_usb_unix_tx_bufs(tpm_usb, cmd->in, cmd->in_len,
                                 cmd->out, cmd->out_len, &cmd->selftest_done,
                                 errp);
}

static void tpm_usb_reset(TPMBackend *tb)
{
    trace_tpm_usb_reset();

    tpm_usb_cancel_cmd(tb);
}

static bool tpm_usb_get_tpm_established_flag(TPMBackend *tb)
{
    return false;
}

static int tpm_usb_reset_tpm_established_flag(TPMBackend *tb,
                                              uint8_t locty)
{
    /* only a TPM 2.0 will support this */
    return 0;
}

static void tpm_usb_cancel_cmd(TPMBackend *tb)
{
    /* not supported */
}

static TPMVersion tpm_usb_get_tpm_version(TPMBackend *tb)
{
    TPMUsbState *tpm_usb = TPM_USB(tb);

    return tpm_usb->tpm_version;
}

static size_t tpm_usb_get_buffer_size(TPMBackend *tb)
{
    TPMUsbState *tpm_usb = TPM_USB(tb);
    int ret;

    ret = tpm_util_get_buffer_size(QIO_CHANNEL_SOCKET(tpm_usb->data_ioc)->fd,
                                   tpm_usb->tpm_version,
                                   &tpm_usb->tpm_buffersize);
    if (ret < 0) {
        tpm_usb->tpm_buffersize = 4096;
    }
    return tpm_usb->tpm_buffersize;
}

static int
connect_socket(const char *hostname, int port)
{
    int s;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        return -1;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    s = qemu_socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return -1;
    }

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return -1;
    }

    return s;
}

static int
tpm_usb_handle_device_opts(TPMUsbState *tpm_usb, QemuOpts *opts)
{
    const char *value;
    Error *err = NULL;
    int fd;

    value = qemu_opt_get(opts, "host");
    if (value) {
        tpm_usb->options->host = g_strdup(value);
        tpm_usb->options->has_host = true;
    }

    value = qemu_opt_get(opts, "port");
    if (value) {
        tpm_usb->options->port = g_strdup(value);
        tpm_usb->options->has_port = true;
    }

    fd = connect_socket("localhost", 9883);
    if (!fd) {
        error_report("tpm-usb: Failed to create socket");
        goto err_exit;
    }

    tpm_usb->data_ioc = QIO_CHANNEL(qio_channel_socket_new_fd(fd, &err));
    if (err) {
        error_prepend(&err, "tpm-usb: Failed to create io channel: ");
        error_report_err(err);
        goto err_exit;
    }

    if (tpm_util_test_tpmdev(QIO_CHANNEL_SOCKET(tpm_usb->data_ioc)->fd,
                             &tpm_usb->tpm_version)) {
        error_report("tpm-usb: Failed to reach TPM");
        goto err_exit;
    }

    return 0;

err_exit:
    closesocket(fd);
    return -1;
}

static TPMBackend *tpm_usb_create(QemuOpts *opts)
{
    Object *obj = object_new(TYPE_TPM_USB);

    if (tpm_usb_handle_device_opts(TPM_USB(obj), opts)) {
        object_unref(obj);
        return NULL;
    }

    return TPM_BACKEND(obj);
}

static int tpm_usb_startup_tpm(TPMBackend *tb, size_t buffersize)
{
    TPMUsbState *tpm_usb = TPM_USB(tb);

    if (buffersize && buffersize < tpm_usb->tpm_buffersize) {
        error_report("Requested buffer size of %zu is smaller than host TPM's "
                     "fixed buffer size of %zu",
                     buffersize, tpm_usb->tpm_buffersize);
        return -1;
    }

    return 0;
}

static TpmTypeOptions *tpm_usb_get_tpm_options(TPMBackend *tb)
{
    TpmTypeOptions *options = g_new0(TpmTypeOptions, 1);

    options->type = TPM_TYPE_USB;
    options->u.usb.data = QAPI_CLONE(TPMUsbOptions,
                                     TPM_USB(tb)->options);

    return options;
}

static const QemuOptDesc tpm_usb_cmdline_opts[] = {
    TPM_STANDARD_CMDLINE_OPTS,
    {
        .name = "host",
        .type = QEMU_OPT_STRING,
        .help = "Connecting to tpm2_server host",
    },
    {
        .name = "port",
        .type = QEMU_OPT_STRING,
        .help = "Connecting to tpm2_server port",
    },
    { /* end of list */ },
};

static void tpm_usb_inst_init(Object *obj)
{
    TPMUsbState *tpm_usb = TPM_USB(obj);

    tpm_usb->options = g_new0(TPMUsbOptions, 1);
}

static void tpm_usb_inst_finalize(Object *obj)
{
    TPMUsbState *tpm_usb = TPM_USB(obj);
    int fd = QIO_CHANNEL_SOCKET(tpm_usb->data_ioc)->fd;

    tpm_usb_cancel_cmd(TPM_BACKEND(obj));

    if (fd >= 0) {
        qemu_close(fd);
    }

    object_unref(OBJECT(tpm_usb->data_ioc));

    qapi_free_TPMUsbOptions(tpm_usb->options);
}

static void tpm_usb_class_init(ObjectClass *klass, void *data)
{
    TPMBackendClass *tbc = TPM_BACKEND_CLASS(klass);

    tbc->type = TPM_TYPE_USB;
    tbc->opts = tpm_usb_cmdline_opts;
    tbc->desc = "Usb TPM backend driver";
    tbc->create = tpm_usb_create;
    tbc->startup_tpm = tpm_usb_startup_tpm;
    tbc->reset = tpm_usb_reset;
    tbc->cancel_cmd = tpm_usb_cancel_cmd;
    tbc->get_tpm_established_flag = tpm_usb_get_tpm_established_flag;
    tbc->reset_tpm_established_flag =
        tpm_usb_reset_tpm_established_flag;
    tbc->get_tpm_version = tpm_usb_get_tpm_version;
    tbc->get_buffer_size = tpm_usb_get_buffer_size;
    tbc->get_tpm_options = tpm_usb_get_tpm_options;
    tbc->handle_request = tpm_usb_handle_request;
}

static const TypeInfo tpm_usb_info = {
    .name = TYPE_TPM_USB,
    .parent = TYPE_TPM_BACKEND,
    .instance_size = sizeof(TPMUsbState),
    .class_init = tpm_usb_class_init,
    .instance_init = tpm_usb_inst_init,
    .instance_finalize = tpm_usb_inst_finalize,
};

static void tpm_usb_register(void)
{
    type_register_static(&tpm_usb_info);
}

type_init(tpm_usb_register)
