/**
 * @file
 * @brief
 *
 * @author  Anton Kozlov
 * @date    17.01.2014
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <endian.h>

#include <mem/misc/pool.h>
#include <embox/unit.h>
#include <drivers/usb/usb_driver.h>
#include <drivers/usb/usb.h>
#include <drivers/usb/class/usb_mass_storage.h>
#include <drivers/scsi.h>

#include <util/log.h>

#define USB_MS_MIGHTY_TAG 0xff00ff00

#define USB_CBW_SIGNATURE 0x43425355
#define USB_CBW_FLAGS_IN  0x80
#define USB_CBW_FLAGS_OUT 0x00

#define USB_CSW_SIGNATURE 0x53425355

EMBOX_UNIT_INIT(usb_mass_init);

POOL_DEF(usb_mass_classes, struct usb_mass, USB_MASS_MAX_DEVS);

static int usb_cbw_fill(struct usb_mscbw *cbw, uint32_t tag, uint32_t tr_len,
		enum usb_direction dir, uint8_t lun, void *cb, size_t len) {

	cbw->cbw_signature = USB_CBW_SIGNATURE;
	cbw->cbw_tag = tag;
	cbw->cbw_transfer_len = tr_len;
	cbw->cbw_flags = dir == USB_DIRECTION_IN ? USB_CBW_FLAGS_IN : USB_CBW_FLAGS_OUT;
	cbw->cbw_lun = lun;

	memcpy(cbw->cbw_cb, cb, len);
	memset(cbw->cbw_cb + len, 0, USB_CBW_CB_MAXLEN - len);
	cbw->cbw_len = len;

	return cbw->cbw_transfer_len;
}

static void usb_ms_transfer_done(struct usb_request *req, void *arg) {
	struct usb_dev *dev = req->endp->dev;
	struct usb_mass *mass = usb2massdata(dev);
	struct usb_mass_request_ctx *req_ctx;
	struct usb_endp *endp = NULL;

	req_ctx = &mass->req_ctx;

	log_debug("req_state %d", req_ctx->req_state);

	switch(req_ctx->req_state) {
	case USB_MASS_REQST_CBW:

		assert(req_ctx->dir == USB_DIRECTION_IN || req_ctx->dir == USB_DIRECTION_OUT);

		if (req_ctx->dir == USB_DIRECTION_IN) {
			endp = dev->endpoints[mass->blkin];
		} else if (req_ctx->dir == USB_DIRECTION_OUT) {
			endp = dev->endpoints[mass->blkout];
		}

		req_ctx->req_state = USB_MASS_REQST_DATA;

		usb_endp_bulk(endp, usb_ms_transfer_done, req_ctx->buf, req_ctx->len);
		break;
	case USB_MASS_REQST_DATA:
		endp = dev->endpoints[mass->blkin];

		req_ctx->req_state = USB_MASS_REQST_CSW;

		memset(&req_ctx->csw, 0, sizeof(struct usb_mscsw));

		usb_endp_bulk(endp, usb_ms_transfer_done, &req_ctx->csw, sizeof(struct usb_mscsw));
		break;
	case USB_MASS_REQST_CSW:
		log_debug("csw_signature=0x%x; csw_tag=0x%x; "
				"csw_data_resude=0x%x; csw_status=0x%x",
				req_ctx->csw.csw_signature, req_ctx->csw.csw_tag,
				req_ctx->csw.csw_data_resude, req_ctx->csw.csw_status);

		assert(req_ctx->csw.csw_signature == USB_CSW_SIGNATURE);
		assert(req_ctx->csw.csw_tag == USB_MS_MIGHTY_TAG);

		req_ctx->holded_hnd(req, &req_ctx->csw);
		break;
	default:
		log_error("Unknown req_ctx->req_state %d", req_ctx->req_state);
		assert(0);
		break;
	}
}

int usb_ms_transfer(struct usb_dev *dev, void *ms_cmd,
		size_t ms_cmd_len, enum usb_direction dir, void *buf, size_t len,
	       	usb_request_notify_hnd_t notify_hnd) {
	struct usb_mass *mass = usb2massdata(dev);
	struct usb_mass_request_ctx *req_ctx;
	int res;

	req_ctx = &mass->req_ctx;
	req_ctx->dir = dir;
	req_ctx->buf = buf;
	req_ctx->len = len;
	req_ctx->holded_hnd = notify_hnd;
	if (len) {
		req_ctx->req_state = USB_MASS_REQST_CBW;
	} else {
		req_ctx->req_state = USB_MASS_REQST_DATA;
	}

	res = usb_cbw_fill(&req_ctx->cbw, USB_MS_MIGHTY_TAG, len,
			dir, 0, ms_cmd, ms_cmd_len);
	if (res < 0) {
		return res;
	}

	log_debug("len=%d, dir=0x%x", len, dir);

	return usb_endp_bulk(dev->endpoints[mass->blkout], usb_ms_transfer_done,
			&req_ctx->cbw, sizeof(struct usb_mscbw));
}

static void usb_mass_start(struct usb_dev *dev) {
	struct usb_mass *mass = usb2massdata(dev);
	int ret;
	int i;

	mass->blkin = mass->blkout = -1;

	for (i = 1; i < dev->endp_n; i++) {
		struct usb_endp *endp = dev->endpoints[i];

		if (endp->type == USB_COMM_BULK) {
			if (endp->direction == USB_DIRECTION_IN) {
				mass->blkin = i;
			}
			if (endp->direction == USB_DIRECTION_OUT) {
				mass->blkout = i;
			}
		}
	}

	ret = usb_endp_control_wait(dev->endpoints[0],
			USB_DIR_OUT | USB_REQ_TYPE_CLASS | USB_REQ_RECIP_IFACE,
			USB_REQ_MASS_RESET, 0,
			dev->iface_desc.b_interface_number, 0, NULL, 1000);
	if (ret) {
		log_error("Mass storage reset error\n\n");
		return;
	}

	usleep(100000);

	ret = usb_endp_control_wait(dev->endpoints[0],
			USB_DIR_IN | USB_REQ_TYPE_CLASS | USB_REQ_RECIP_IFACE,
			USB_REQ_MASS_MAXLUN, 0,
			dev->iface_desc.b_interface_number, 1, &mass->maxlun, 1000);
	if (ret) {
		log_error("Mass storage conftrol error\n\n");
		return;
	}
	log_debug("mass(blkin = %d, blkout = %d, maxlun=%d)", mass->blkin, mass->blkout, mass->maxlun);

	scsi_dev_init(&mass->scsi_dev);
	scsi_dev_attached(&mass->scsi_dev);
}

static int usb_ms_probe(struct usb_dev *dev) {
	struct usb_mass *mass;

	mass = pool_alloc(&usb_mass_classes);
	if (!mass) {
		return -1;
	}
	mass->usb_dev = dev;
	dev->driver_data = mass;

	usb_mass_start(dev);

	return 0;
}

static void usb_ms_disconnect(struct usb_dev *dev, void *data) {
	struct usb_mass *mass = usb2massdata(dev);
	scsi_dev_detached(&mass->scsi_dev);
	pool_free(&usb_mass_classes, mass);
}

/* TODO */
static struct usb_device_id usb_ms_id_table[] = {
	{USB_CLASS_MASS, 0xffff, 0xffff},
	{ },
};

struct usb_driver usb_driver_ms = {
	.name = "mass_storage",
	.probe = usb_ms_probe,
	.disconnect = usb_ms_disconnect,
	.id_table = usb_ms_id_table,
};

static int usb_mass_init(void) {
	return usb_driver_register(&usb_driver_ms);
}
