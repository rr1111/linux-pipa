// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 */

#include <linux/devcoredump.h>
#include <linux/device.h>
#include <linux/device/devres.h>
#include <linux/firmware.h>
#include <linux/limits.h>
#include <linux/mhi.h>
#include <linux/minmax.h>
#include <linux/mod_devicetable.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#define SAHARA_HELLO_CMD		0x1  /* Min protocol version 1.0 */
#define SAHARA_HELLO_RESP_CMD		0x2  /* Min protocol version 1.0 */
#define SAHARA_READ_DATA_CMD		0x3  /* Min protocol version 1.0 */
#define SAHARA_END_OF_IMAGE_CMD		0x4  /* Min protocol version 1.0 */
#define SAHARA_DONE_CMD			0x5  /* Min protocol version 1.0 */
#define SAHARA_DONE_RESP_CMD		0x6  /* Min protocol version 1.0 */
#define SAHARA_RESET_CMD		0x7  /* Min protocol version 1.0 */
#define SAHARA_RESET_RESP_CMD		0x8  /* Min protocol version 1.0 */
#define SAHARA_MEM_DEBUG_CMD		0x9  /* Min protocol version 2.0 */
#define SAHARA_MEM_READ_CMD		0xa  /* Min protocol version 2.0 */
#define SAHARA_CMD_READY_CMD		0xb  /* Min protocol version 2.1 */
#define SAHARA_SWITCH_MODE_CMD		0xc  /* Min protocol version 2.1 */
#define SAHARA_EXECUTE_CMD		0xd  /* Min protocol version 2.1 */
#define SAHARA_EXECUTE_RESP_CMD		0xe  /* Min protocol version 2.1 */
#define SAHARA_EXECUTE_DATA_CMD		0xf  /* Min protocol version 2.1 */
#define SAHARA_MEM_DEBUG64_CMD		0x10 /* Min protocol version 2.5 */
#define SAHARA_MEM_READ64_CMD		0x11 /* Min protocol version 2.5 */
#define SAHARA_READ_DATA64_CMD		0x12 /* Min protocol version 2.8 */
#define SAHARA_RESET_STATE_CMD		0x13 /* Min protocol version 2.9 */
#define SAHARA_WRITE_DATA_CMD		0x14 /* Min protocol version 3.0 */

#define SAHARA_PACKET_MAX_SIZE		0xffffU /* MHI_MAX_MTU */
#define SAHARA_TRANSFER_MAX_SIZE	0x100000
#define SAHARA_READ_MAX_SIZE		0xfff0U /* Avoid unaligned requests */
#define SAHARA_READ_DATA_CHUNK		0x8000U
#define SAHARA_NUM_TX_BUF		DIV_ROUND_UP(SAHARA_TRANSFER_MAX_SIZE,\
							SAHARA_READ_DATA_CHUNK)
#define SAHARA_IMAGE_ID_NONE		U32_MAX

#define SAHARA_VERSION			2
#define SAHARA_SUCCESS			0
#define SAHARA_TABLE_ENTRY_STR_LEN	20

#define SAHARA_MODE_IMAGE_TX_PENDING	0x0
#define SAHARA_MODE_IMAGE_TX_COMPLETE	0x1
#define SAHARA_MODE_MEMORY_DEBUG	0x2
#define SAHARA_MODE_COMMAND		0x3

#define SAHARA_HELLO_LENGTH		0x30
#define SAHARA_READ_DATA_LENGTH		0x14
#define SAHARA_END_OF_IMAGE_LENGTH	0x10
#define SAHARA_DONE_LENGTH		0x8
#define SAHARA_RESET_LENGTH		0x8
#define SAHARA_MEM_DEBUG_LENGTH		0x10
#define SAHARA_MEM_READ_LENGTH		0x10
#define SAHARA_MEM_DEBUG64_LENGTH	0x18
#define SAHARA_MEM_READ64_LENGTH	0x18
#define SAHARA_COMMAND_READY_LENGTH	0x8
#define SAHARA_COMMAND_EXEC_RESP_LENGTH	0x10
#define SAHARA_COMMAND_EXECUTE_LENGTH	0xc
#define SAHARA_COMMAND_EXEC_DATA_LENGTH	0xc
#define SAHARA_SWITCH_MODE_LENGTH	0xc
#define SAHARA_EXEC_CMD_GET_COMMAND_ID_LIST	0x8
#define SAHARA_EXEC_CMD_GET_TRAINING_DATA	0x9
#define SAHARA_DDR_TRAINING_IMG_ID	34
#define SAHARA_NUM_CMD_BUF		SAHARA_NUM_TX_BUF

struct sahara_packet {
	__le32 cmd;
	__le32 length;

	union {
		struct {
			__le32 version;
			__le32 version_compat;
			__le32 max_length;
			__le32 mode;
		} hello;
		struct {
			__le32 version;
			__le32 version_compat;
			__le32 status;
			__le32 mode;
		} hello_resp;
		struct {
			__le32 image;
			__le32 offset;
			__le32 length;
		} read_data;
		struct {
			__le32 image;
			__le32 status;
		} end_of_image;
		struct {
			__le32 table_address;
			__le32 table_length;
		} memory_debug;
		struct {
			__le32 memory_address;
			__le32 memory_length;
		} memory_read;
		struct {
			__le64 table_address;
			__le64 table_length;
		} memory_debug64;
		struct {
			__le64 memory_address;
			__le64 memory_length;
		} memory_read64;
		struct {
			__le32 client_command;
		} command_execute;
		struct {
			__le32 client_command;
			__le32 response_length;
		} command_execute_resp;
		struct {
			__le32 client_command;
		} command_exec_data;
		struct {
			__le32 mode;
		} mode_switch;
	};
};

struct sahara_debug_table_entry32 {
	__le32	type;
	__le32	address;
	__le32	length;
	char	description[SAHARA_TABLE_ENTRY_STR_LEN];
	char	filename[SAHARA_TABLE_ENTRY_STR_LEN];
};

struct sahara_debug_table_entry64 {
	__le64	type;
	__le64	address;
	__le64	length;
	char	description[SAHARA_TABLE_ENTRY_STR_LEN];
	char	filename[SAHARA_TABLE_ENTRY_STR_LEN];
};

struct sahara_dump_table_entry {
	u64	type;
	u64	address;
	u64	length;
	char	description[SAHARA_TABLE_ENTRY_STR_LEN];
	char	filename[SAHARA_TABLE_ENTRY_STR_LEN];
};

#define SAHARA_DUMP_V1_MAGIC 0x1234567890abcdef
#define SAHARA_DUMP_V1_VER   1
struct sahara_memory_dump_meta_v1 {
	u64	magic;
	u64	version;
	u64	dump_size;
	u64	table_size;
};

/*
 * Layout of crashdump provided to user via devcoredump
 *              +------------------------------------------+
 *              |         Crashdump Meta structure         |
 *              | type: struct sahara_memory_dump_meta_v1  |
 *              +------------------------------------------+
 *              |             Crashdump Table              |
 *              | type: array of struct                    |
 *              |       sahara_dump_table_entry            |
 *              |                                          |
 *              |                                          |
 *              +------------------------------------------+
 *              |                Crashdump                 |
 *              |                                          |
 *              |                                          |
 *              |                                          |
 *              |                                          |
 *              |                                          |
 *              +------------------------------------------+
 *
 * First is the metadata header. Userspace can use the magic number to verify
 * the content type, and then check the version for the rest of the format.
 * New versions should keep the magic number location/value, and version
 * location, but increment the version value.
 *
 * For v1, the metadata lists the size of the entire dump (header + table +
 * dump) and the size of the table. Then the dump image table, which describes
 * the contents of the dump. Finally all the images are listed in order, with
 * no deadspace in between. Userspace can use the sizes listed in the image
 * table to reconstruct the individual images.
 */

struct sahara_context {
	struct sahara_packet		*tx[SAHARA_NUM_TX_BUF];
	struct sahara_packet		*rx;
	struct work_struct		fw_work;
	struct work_struct		dump_work;
	struct work_struct		read_data_work;
	struct work_struct		cmd_work;
	struct mhi_device		*mhi_dev;
	const char * const		*image_table;
	u32				table_size;
	u32				active_image_id;
	const struct firmware		*firmware;
	u64				dump_table_address;
	u64				dump_table_length;
	size_t				rx_size;
	size_t				rx_size_requested;
	void				*mem_dump;
	size_t				mem_dump_sz;
	struct sahara_dump_table_entry	*dump_image;
	u64				dump_image_offset;
	void				*mem_dump_freespace;
	u64				dump_images_left;
	u32				read_data_offset;
	u32				read_data_length;
	struct sahara_packet		*read_data_group_end;
	bool				is_mem_dump_mode;
	bool				is_mem_debug32;
	bool				non_streaming;
	const char			*fw_folder;
	bool				is_cmd_mode;
	bool				receiving_training_data;
	size_t				training_size;
	size_t				training_rcvd;
	u32				training_nbuf;
	char				*cmd_buff[SAHARA_NUM_CMD_BUF];
};

/*
 * Controller-scoped training data store (per MHI controller device).
 * Stored as devres resource on mhi_dev->mhi_cntrl->mhi_dev->dev.
 */
struct sahara_cntrl_training_data {
	struct mutex lock;	/* Protects data, size, copied and receiving */
	void *data;
	size_t size;
	size_t copied;
	bool receiving;
};

static bool is_streaming(struct sahara_context *context)
{
	return !context->non_streaming;
}

static void sahara_cntrl_training_release(struct device *dev, void *res)
{
	struct sahara_cntrl_training_data *ct = res;

	mutex_lock(&ct->lock);
	kfree(ct->data);
	ct->data = NULL;
	ct->size = 0;
	ct->copied = 0;
	ct->receiving = false;
	mutex_unlock(&ct->lock);
}

static int sahara_cntrl_training_match(struct device *dev, void *res, void *match_data)
{
	/* Exactly one instance per controller */
	return 1;
}

static struct sahara_cntrl_training_data *sahara_cntrl_training_get(struct device *dev)
{
	struct sahara_cntrl_training_data *ct;

	ct = devres_find(dev, sahara_cntrl_training_release,
			 sahara_cntrl_training_match, NULL);
	if (ct)
		return ct;

	ct = devres_alloc(sahara_cntrl_training_release, sizeof(*ct), GFP_KERNEL);
	if (!ct)
		return NULL;

	mutex_init(&ct->lock);
	ct->data = NULL;
	ct->size = 0;
	ct->copied = 0;
	ct->receiving = false;

	devres_add(dev, ct);
	return ct;
}

static ssize_t ddr_training_data_read(struct file *filp, struct kobject *kobj,
				      const struct bin_attribute *attr, char *buf,
				      loff_t offset, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct sahara_cntrl_training_data *ct;
	size_t available;

	ct = sahara_cntrl_training_get(dev);
	if (!ct)
		return -ENODEV;

	mutex_lock(&ct->lock);

	/* No data yet or offset past end */
	if (!ct->data || offset >= ct->size) {
		mutex_unlock(&ct->lock);
		return 0;
	}

	available = ct->size - offset;
	count = min(count, available);
	memcpy(buf, (u8 *)ct->data + offset, count);

	mutex_unlock(&ct->lock);

	return count;
}
static BIN_ATTR_RO(ddr_training_data, 0);

static void sahara_sysfs_devres_release(struct device *dev, void *res)
{
	device_remove_bin_file(dev, &bin_attr_ddr_training_data);
}

static void sahara_sysfs_create(struct mhi_device *mhi_dev)
{
	struct device *dev = &mhi_dev->mhi_cntrl->mhi_dev->dev;
	void *cookie;
	int ret;

	if (devres_find(dev, sahara_sysfs_devres_release, NULL, NULL))
		return;

	ret = device_create_bin_file(dev, &bin_attr_ddr_training_data);
	if (ret) {
		dev_warn(&mhi_dev->dev,
			 "Failed to create DDR training sysfs node (%d)\n", ret);
		return;
	}

	cookie = devres_alloc(sahara_sysfs_devres_release, 1, GFP_KERNEL);
	if (!cookie) {
		device_remove_bin_file(dev, &bin_attr_ddr_training_data);
		return;
	}

	devres_add(dev, cookie);
}

static int sahara_find_image(struct sahara_context *context, u32 image_id)
{
	char *fw_path;
	int ret;

	if (image_id == context->active_image_id)
		return 0;

	if (context->active_image_id != SAHARA_IMAGE_ID_NONE) {
		dev_err(&context->mhi_dev->dev, "image id %d is not valid as %d is active\n",
			image_id, context->active_image_id);
		return -EINVAL;
	}

	if (image_id >= context->table_size || !context->image_table[image_id]) {
		if (!context->fw_folder) {
			dev_err(&context->mhi_dev->dev,
				"Request for unknown image: %u (no fw folder)\n", image_id);
			return -EINVAL;
		}

		fw_path = kasprintf(GFP_KERNEL, "qcom/%s/%u",
				    context->fw_folder, image_id);
		if (!fw_path)
			return -ENOMEM;

		ret = firmware_request_nowarn(&context->firmware,
					      fw_path,
					      &context->mhi_dev->dev);
		kfree(fw_path);
		if (ret) {
			dev_err(&context->mhi_dev->dev,
				"request for unknown image: %d\n", image_id);
			return -EINVAL;
		}
		context->active_image_id = image_id;
		return 0;
	}

	/* DDR training special case: Try per-serial number file first */
	if (image_id == SAHARA_DDR_TRAINING_IMG_ID && context->fw_folder) {
		u32 serial_num = context->mhi_dev->mhi_cntrl->serial_number;

		fw_path = kasprintf(GFP_KERNEL,
				    "qcom/%s/mdmddr_0x%x.mbn",
				    context->fw_folder, serial_num);
		if (!fw_path)
			return -ENOMEM;

		ret = firmware_request_nowarn(&context->firmware,
					      fw_path,
					      &context->mhi_dev->dev);
		kfree(fw_path);

		if (!ret) {
			context->active_image_id = image_id;
			return 0;
		}
	}

	/*
	 * This image might be optional. The device may continue without it.
	 * Only the device knows. Suppress error messages that could suggest an
	 * a problem when we were actually able to continue.
	 */
	ret = firmware_request_nowarn(&context->firmware,
				      context->image_table[image_id],
				      &context->mhi_dev->dev);
	if (ret) {
		dev_dbg(&context->mhi_dev->dev,
			"request for image id %d / file %s failed %d\n",
			image_id, context->image_table[image_id], ret);
		return ret;
	}

	context->active_image_id = image_id;

	return 0;
}

static void sahara_release_image(struct sahara_context *context)
{
	if (context->active_image_id != SAHARA_IMAGE_ID_NONE)
		release_firmware(context->firmware);
	context->active_image_id = SAHARA_IMAGE_ID_NONE;
}

static void sahara_send_reset(struct sahara_context *context)
{
	int ret;

	context->is_mem_dump_mode = false;
	context->read_data_offset = 0;
	context->read_data_length = 0;
	context->is_cmd_mode = false;
	context->receiving_training_data = false;
	context->training_size = 0;
	context->training_rcvd = 0;
	context->training_nbuf = 0;

	context->tx[0]->cmd = cpu_to_le32(SAHARA_RESET_CMD);
	context->tx[0]->length = cpu_to_le32(SAHARA_RESET_LENGTH);

	ret = mhi_queue_buf(context->mhi_dev, DMA_TO_DEVICE, context->tx[0],
			    SAHARA_RESET_LENGTH, MHI_EOT);
	if (ret)
		dev_err(&context->mhi_dev->dev, "Unable to send reset response %d\n", ret);
}

static void sahara_hello(struct sahara_context *context)
{
	int ret;

	dev_dbg(&context->mhi_dev->dev,
		"HELLO cmd received. length:%d version:%d version_compat:%d max_length:%d mode:%d\n",
		le32_to_cpu(context->rx->length),
		le32_to_cpu(context->rx->hello.version),
		le32_to_cpu(context->rx->hello.version_compat),
		le32_to_cpu(context->rx->hello.max_length),
		le32_to_cpu(context->rx->hello.mode));

	if (le32_to_cpu(context->rx->length) != SAHARA_HELLO_LENGTH) {
		dev_err(&context->mhi_dev->dev, "Malformed hello packet - length %d\n",
			le32_to_cpu(context->rx->length));
		return;
	}
	if (le32_to_cpu(context->rx->hello.version) != SAHARA_VERSION) {
		dev_err(&context->mhi_dev->dev, "Unsupported hello packet - version %d\n",
			le32_to_cpu(context->rx->hello.version));
		return;
	}

	if (le32_to_cpu(context->rx->hello.mode) != SAHARA_MODE_IMAGE_TX_PENDING &&
	    le32_to_cpu(context->rx->hello.mode) != SAHARA_MODE_IMAGE_TX_COMPLETE &&
	    le32_to_cpu(context->rx->hello.mode) != SAHARA_MODE_MEMORY_DEBUG &&
	    le32_to_cpu(context->rx->hello.mode) != SAHARA_MODE_COMMAND) {
		dev_err(&context->mhi_dev->dev, "Unsupported hello packet - mode %d\n",
			le32_to_cpu(context->rx->hello.mode));
		return;
	}

	context->tx[0]->cmd = cpu_to_le32(SAHARA_HELLO_RESP_CMD);
	context->tx[0]->length = cpu_to_le32(SAHARA_HELLO_LENGTH);
	context->tx[0]->hello_resp.version = cpu_to_le32(SAHARA_VERSION);
	context->tx[0]->hello_resp.version_compat = cpu_to_le32(SAHARA_VERSION);
	context->tx[0]->hello_resp.status = cpu_to_le32(SAHARA_SUCCESS);
	context->tx[0]->hello_resp.mode = context->rx->hello_resp.mode;

	ret = mhi_queue_buf(context->mhi_dev, DMA_TO_DEVICE, context->tx[0],
			    SAHARA_HELLO_LENGTH, MHI_EOT);
	if (ret)
		dev_err(&context->mhi_dev->dev, "Unable to send hello response %d\n", ret);
}

static void sahara_switch_mode_to_img_tx(struct sahara_context *context)
{
	int ret;

	context->tx[0]->cmd = cpu_to_le32(SAHARA_SWITCH_MODE_CMD);
	context->tx[0]->length = cpu_to_le32(SAHARA_SWITCH_MODE_LENGTH);
	context->tx[0]->mode_switch.mode = cpu_to_le32(SAHARA_MODE_IMAGE_TX_PENDING);

	ret = mhi_queue_buf(context->mhi_dev, DMA_TO_DEVICE, context->tx[0],
			    SAHARA_SWITCH_MODE_LENGTH, MHI_EOT);

	if (ret)
		dev_err(&context->mhi_dev->dev, "Unable to send mode switch %d\n", ret);
}

static void sahara_command_execute(struct sahara_context *context, u32 client_command)
{
	int ret;

	context->tx[0]->cmd = cpu_to_le32(SAHARA_EXECUTE_CMD);
	context->tx[0]->length = cpu_to_le32(SAHARA_COMMAND_EXECUTE_LENGTH);
	context->tx[0]->command_execute.client_command = cpu_to_le32(client_command);

	ret = mhi_queue_buf(context->mhi_dev, DMA_TO_DEVICE, context->tx[0],
			    SAHARA_COMMAND_EXECUTE_LENGTH, MHI_EOT);
	if (ret)
		dev_err(&context->mhi_dev->dev, "Unable to send command execute %d\n", ret);
}

static void sahara_command_execute_data(struct sahara_context *context, u32 client_command)
{
	int ret;

	context->tx[0]->cmd = cpu_to_le32(SAHARA_EXECUTE_DATA_CMD);
	context->tx[0]->length = cpu_to_le32(SAHARA_COMMAND_EXEC_DATA_LENGTH);
	context->tx[0]->command_exec_data.client_command = cpu_to_le32(client_command);

	ret = mhi_queue_buf(context->mhi_dev, DMA_TO_DEVICE, context->tx[0],
			    SAHARA_COMMAND_EXEC_DATA_LENGTH, MHI_EOT);
	if (ret)
		dev_err(&context->mhi_dev->dev, "Unable to send execute data %d\n", ret);
}

static void sahara_command_ready(struct sahara_context *context)
{
	if (le32_to_cpu(context->rx->length) != SAHARA_COMMAND_READY_LENGTH) {
		dev_err(&context->mhi_dev->dev,
			"Malformed command ready packet - length %u\n",
			le32_to_cpu(context->rx->length));
		return;
	}

	context->is_cmd_mode = true;
	context->receiving_training_data = false;

	sahara_command_execute(context, SAHARA_EXEC_CMD_GET_COMMAND_ID_LIST);
}

static void sahara_command_execute_resp(struct sahara_context *context)
{
	struct device *dev = &context->mhi_dev->mhi_cntrl->mhi_dev->dev;
	struct sahara_cntrl_training_data *ct;
	u32 client_cmd, resp_len;
	int ret;
	u64 remaining;
	u32 i;

	if (le32_to_cpu(context->rx->length) != SAHARA_COMMAND_EXEC_RESP_LENGTH ||
	    le32_to_cpu(context->rx->command_execute_resp.response_length) < 0) {
		dev_err(&context->mhi_dev->dev,
			"Malformed command execute resp packet - length %d\n",
			le32_to_cpu(context->rx->length));
		return;
	}

	client_cmd = le32_to_cpu(context->rx->command_execute_resp.client_command);
	resp_len = le32_to_cpu(context->rx->command_execute_resp.response_length);

	sahara_command_execute_data(context, client_cmd);

	if (client_cmd == SAHARA_EXEC_CMD_GET_COMMAND_ID_LIST) {
		sahara_command_execute(context, SAHARA_EXEC_CMD_GET_TRAINING_DATA);
		return;
	}

	if (client_cmd != SAHARA_EXEC_CMD_GET_TRAINING_DATA)
		return;

	ct = sahara_cntrl_training_get(dev);
	if (!ct) {
		context->is_cmd_mode = false;
		sahara_switch_mode_to_img_tx(context);
		return;
	}

	mutex_lock(&ct->lock);
	kfree(ct->data);
	ct->data = kzalloc(resp_len, GFP_KERNEL);
	ct->size = resp_len;
	ct->copied = 0;
	ct->receiving = true;
	mutex_unlock(&ct->lock);

	if (!ct->data) {
		context->is_cmd_mode = false;
		sahara_switch_mode_to_img_tx(context);
		return;
	}

	context->training_size = resp_len;
	context->training_rcvd = 0;
	context->receiving_training_data = true;

	remaining = resp_len;
	for (i = 0; i < SAHARA_NUM_CMD_BUF && remaining; i++) {
		size_t pkt = min_t(size_t, remaining, SAHARA_PACKET_MAX_SIZE);

		ret = mhi_queue_buf(context->mhi_dev, DMA_FROM_DEVICE,
				    context->cmd_buff[i], pkt,
				    (remaining <= pkt) ? MHI_EOT : MHI_CHAIN);
		if (ret)
			break;

		remaining -= pkt;
	}

	context->training_nbuf = i;
}

static void sahara_command_processing(struct work_struct *work)
{
	struct sahara_context *context = container_of(work, struct sahara_context, cmd_work);
	int ret;

	if (le32_to_cpu(context->rx->cmd) == SAHARA_EXECUTE_RESP_CMD)
		sahara_command_execute_resp(context);

	if (!context->receiving_training_data) {
		ret = mhi_queue_buf(context->mhi_dev, DMA_FROM_DEVICE,
				    context->rx, SAHARA_PACKET_MAX_SIZE, MHI_EOT);

		if (ret)
			dev_err(&context->mhi_dev->dev,
				"Unable to requeue rx buf %d\n", ret);
	}
}

static int read_data_helper(struct sahara_context *context, int buf_index,
			    u32 pkt_data_len, bool eot)
{
	int ret;

	memcpy(context->tx[buf_index],
	       &context->firmware->data[context->read_data_offset],
	       pkt_data_len);

	context->read_data_offset += pkt_data_len;
	context->read_data_length -= pkt_data_len;

	ret = mhi_queue_buf(context->mhi_dev, DMA_TO_DEVICE,
			    context->tx[buf_index], pkt_data_len,
			    eot ? MHI_EOT : MHI_CHAIN);
	if (ret) {
		dev_err(&context->mhi_dev->dev, "Unable to send read_data response %d\n", ret);
		return ret;
	}

	return 0;
}

static void sahara_send_read_data_group(struct sahara_context *context)
{
	u32 group_len = min(context->read_data_length, SAHARA_TRANSFER_MAX_SIZE);
	u32 pkt_data_len;
	int i;

	for (i = 0; i < SAHARA_NUM_TX_BUF && group_len; ++i) {
		pkt_data_len = min(group_len, SAHARA_READ_DATA_CHUNK);
		group_len -= pkt_data_len;
		context->read_data_group_end = context->tx[i];
		if (read_data_helper(context, i, pkt_data_len, !group_len))
			break;
	}
}

static void sahara_send_read_data(struct sahara_context *context)
{
	if (is_streaming(context))
		read_data_helper(context, 0,
				 min(context->read_data_length, SAHARA_PACKET_MAX_SIZE),
				 true);
	else
		sahara_send_read_data_group(context);
}

static void sahara_read_data(struct sahara_context *context)
{
	u32 image_id, data_offset, data_len;
	int ret;

	dev_dbg(&context->mhi_dev->dev,
		"READ_DATA cmd received. length:%d image:%d offset:%d data_length:%d\n",
		le32_to_cpu(context->rx->length),
		le32_to_cpu(context->rx->read_data.image),
		le32_to_cpu(context->rx->read_data.offset),
		le32_to_cpu(context->rx->read_data.length));

	if (le32_to_cpu(context->rx->length) != SAHARA_READ_DATA_LENGTH) {
		dev_err(&context->mhi_dev->dev, "Malformed read_data packet - length %d\n",
			le32_to_cpu(context->rx->length));
		return;
	}

	image_id = le32_to_cpu(context->rx->read_data.image);
	data_offset = le32_to_cpu(context->rx->read_data.offset);
	data_len = le32_to_cpu(context->rx->read_data.length);

	ret = sahara_find_image(context, image_id);
	if (ret) {
		sahara_send_reset(context);
		return;
	}

	/*
	 * Image is released when the device is done with it via
	 * SAHARA_END_OF_IMAGE_CMD. sahara_send_reset() will either cause the
	 * device to retry the operation with a modification, or decide to be
	 * done with the image and trigger SAHARA_END_OF_IMAGE_CMD.
	 * release_image() is called from SAHARA_END_OF_IMAGE_CMD. processing
	 * and is not needed here on error.
	 */

	if (data_offset >= context->firmware->size) {
		dev_err(&context->mhi_dev->dev, "Malformed read_data packet - data offset %d exceeds file size %zu\n",
			data_offset, context->firmware->size);
		sahara_send_reset(context);
		return;
	}

	if (size_add(data_offset, data_len) > context->firmware->size) {
		dev_err(&context->mhi_dev->dev, "Malformed read_data packet - data offset %d and length %d exceeds file size %zu\n",
			data_offset, data_len, context->firmware->size);
		sahara_send_reset(context);
		return;
	}

	context->read_data_offset = data_offset;
	context->read_data_length = data_len;

	if (is_streaming(context)) {
		schedule_work(&context->read_data_work);
		return;
	}

	sahara_send_read_data_group(context);
}

static void sahara_end_of_image(struct sahara_context *context)
{
	int ret;

	dev_dbg(&context->mhi_dev->dev,
		"END_OF_IMAGE cmd received. length:%d image:%d status:%d\n",
		le32_to_cpu(context->rx->length),
		le32_to_cpu(context->rx->end_of_image.image),
		le32_to_cpu(context->rx->end_of_image.status));

	if (le32_to_cpu(context->rx->length) != SAHARA_END_OF_IMAGE_LENGTH) {
		dev_err(&context->mhi_dev->dev, "Malformed end_of_image packet - length %d\n",
			le32_to_cpu(context->rx->length));
		return;
	}

	if (context->active_image_id != SAHARA_IMAGE_ID_NONE &&
	    le32_to_cpu(context->rx->end_of_image.image) != context->active_image_id) {
		dev_err(&context->mhi_dev->dev, "Malformed end_of_image packet - image %d is not the active image\n",
			le32_to_cpu(context->rx->end_of_image.image));
		return;
	}

	sahara_release_image(context);

	if (le32_to_cpu(context->rx->end_of_image.status))
		return;

	context->tx[0]->cmd = cpu_to_le32(SAHARA_DONE_CMD);
	context->tx[0]->length = cpu_to_le32(SAHARA_DONE_LENGTH);

	ret = mhi_queue_buf(context->mhi_dev, DMA_TO_DEVICE, context->tx[0],
			    SAHARA_DONE_LENGTH, MHI_EOT);
	if (ret)
		dev_dbg(&context->mhi_dev->dev, "Unable to send done response %d\n", ret);
}

static int sahara_send_memory_read(struct sahara_context *context, u64 address, u64 length)
{
	u32 packet_length;

	if (context->is_mem_debug32) {
		packet_length = SAHARA_MEM_READ_LENGTH;
		context->tx[0]->cmd = cpu_to_le32(SAHARA_MEM_READ_CMD);
		context->tx[0]->memory_read.memory_address = cpu_to_le32(address);
		context->tx[0]->memory_read.memory_length = cpu_to_le32(length);
	} else {
		packet_length = SAHARA_MEM_READ64_LENGTH;
		context->tx[0]->cmd = cpu_to_le32(SAHARA_MEM_READ64_CMD);
		context->tx[0]->memory_read64.memory_address = cpu_to_le64(address);
		context->tx[0]->memory_read64.memory_length = cpu_to_le64(length);
	}
	context->tx[0]->length = cpu_to_le32(packet_length);

	return mhi_queue_buf(context->mhi_dev, DMA_TO_DEVICE, context->tx[0],
			     packet_length, MHI_EOT);
}

static void sahara_memory_debug(struct sahara_context *context, bool is64)
{
	size_t entry_size;
	u32 packet_length;
	int ret;

	if (is64) {
		packet_length = SAHARA_MEM_DEBUG64_LENGTH;
		entry_size = sizeof(struct sahara_debug_table_entry64);
		context->dump_table_address =
			le64_to_cpu(context->rx->memory_debug64.table_address);
		context->dump_table_length =
			le64_to_cpu(context->rx->memory_debug64.table_length);
	} else {
		packet_length = SAHARA_MEM_DEBUG_LENGTH;
		entry_size = sizeof(struct sahara_debug_table_entry32);
		context->dump_table_address = le32_to_cpu(context->rx->memory_debug.table_address);
		context->dump_table_length = le32_to_cpu(context->rx->memory_debug.table_length);
	}

	dev_dbg(&context->mhi_dev->dev,
		"MEMORY DEBUG%s cmd received. length:%d table_address:%#llx table_length:%#llx\n",
		is64 ? "64" : "", le32_to_cpu(context->rx->length),
		context->dump_table_address, context->dump_table_length);

	if (le32_to_cpu(context->rx->length) != packet_length) {
		dev_err(&context->mhi_dev->dev, "Malformed memory debug packet - length %d\n",
			le32_to_cpu(context->rx->length));
		return;
	}

	if (context->dump_table_length % entry_size != 0 || !context->dump_table_length) {
		dev_err(&context->mhi_dev->dev, "Malformed memory debug packet - table length %lld\n",
			context->dump_table_length);
		return;
	}

	context->is_mem_debug32 = !is64;

	/*
	 * From this point, the protocol flips. We make memory_read requests to
	 * the device, and the device responds with the raw data. If the device
	 * has an error, it will send an End of Image command. First we need to
	 * request the memory dump table so that we know where all the pieces
	 * of the dump are that we can consume.
	 */

	context->is_mem_dump_mode = true;

	/*
	 * Assume that the table is smaller than our MTU so that we can read it
	 * in one shot. The spec does not put an upper limit on the table, but
	 * no known device will exceed this.
	 */
	if (context->dump_table_length > SAHARA_PACKET_MAX_SIZE) {
		dev_err(&context->mhi_dev->dev, "Memory dump table length %lld exceeds supported size. Discarding dump\n",
			context->dump_table_length);
		sahara_send_reset(context);
		return;
	}

	context->rx_size_requested = context->dump_table_length;

	ret = sahara_send_memory_read(context, context->dump_table_address,
				      context->dump_table_length);
	if (ret)
		dev_err(&context->mhi_dev->dev, "Unable to send read for dump table %d\n", ret);
}

static void sahara_processing(struct work_struct *work)
{
	struct sahara_context *context = container_of(work, struct sahara_context, fw_work);
	int ret;

	switch (le32_to_cpu(context->rx->cmd)) {
	case SAHARA_HELLO_CMD:
		sahara_hello(context);
		break;
	case SAHARA_READ_DATA_CMD:
		sahara_read_data(context);
		break;
	case SAHARA_END_OF_IMAGE_CMD:
		sahara_end_of_image(context);
		break;
	case SAHARA_DONE_RESP_CMD:
		/* Intentional do nothing as we don't need to exit an app */
		break;
	case SAHARA_RESET_RESP_CMD:
		/* Intentional do nothing as we don't need to exit an app */
		break;
	case SAHARA_MEM_DEBUG_CMD:
		sahara_memory_debug(context, false);
		break;
	case SAHARA_MEM_DEBUG64_CMD:
		sahara_memory_debug(context, true);
		break;
	case SAHARA_CMD_READY_CMD:
		sahara_command_ready(context);
		break;
	default:
		dev_err(&context->mhi_dev->dev, "Unknown command %d\n",
			le32_to_cpu(context->rx->cmd));
		break;
	}

	ret = mhi_queue_buf(context->mhi_dev, DMA_FROM_DEVICE, context->rx,
			    SAHARA_PACKET_MAX_SIZE, MHI_EOT);
	if (ret)
		dev_err(&context->mhi_dev->dev, "Unable to requeue rx buf %d\n", ret);
}

static void sahara_get_table_entry(struct sahara_context *context, u64 index,
				   struct sahara_dump_table_entry *entry)
{
	struct sahara_debug_table_entry32 *entry32;
	struct sahara_debug_table_entry64 *entry64;

	if (context->is_mem_debug32) {
		entry32 = (struct sahara_debug_table_entry32 *)context->rx + index;
		entry->type = le32_to_cpu(entry32->type);
		entry->address = le32_to_cpu(entry32->address);
		entry->length = le32_to_cpu(entry32->length);
		strscpy(entry->description, entry32->description, SAHARA_TABLE_ENTRY_STR_LEN);
		strscpy(entry->filename, entry32->filename, SAHARA_TABLE_ENTRY_STR_LEN);
	} else {
		entry64 = (struct sahara_debug_table_entry64 *)context->rx + index;
		entry->type = le64_to_cpu(entry64->type);
		entry->address = le64_to_cpu(entry64->address);
		entry->length = le64_to_cpu(entry64->length);
		strscpy(entry->description, entry64->description, SAHARA_TABLE_ENTRY_STR_LEN);
		strscpy(entry->filename, entry64->filename, SAHARA_TABLE_ENTRY_STR_LEN);
	}
}

static void sahara_parse_dump_table(struct sahara_context *context)
{
	struct sahara_dump_table_entry *image_out_table;
	struct sahara_memory_dump_meta_v1 *dump_meta;
	struct sahara_dump_table_entry entry;
	size_t entry_size;
	u64 table_nents;
	u64 dump_length;
	u64 mul_bytes;
	int ret;
	u64 i;

	if (context->is_mem_debug32)
		entry_size = sizeof(struct sahara_debug_table_entry32);
	else
		entry_size = sizeof(struct sahara_debug_table_entry64);
	table_nents = context->dump_table_length / entry_size;
	context->dump_images_left = table_nents;
	dump_length = 0;

	for (i = 0; i < table_nents; ++i) {
		sahara_get_table_entry(context, i, &entry);

		if (check_add_overflow(dump_length, entry.length, &dump_length)) {
			/* Discard the dump */
			sahara_send_reset(context);
			return;
		}

		dev_dbg(&context->mhi_dev->dev,
			"Memory dump table entry %lld type: %lld address: %#llx length: %#llx description: \"%s\" filename \"%s\"\n",
			i, entry.type, entry.address, entry.length,
			entry.description, entry.filename);
	}

	if (check_add_overflow(dump_length, (u64)sizeof(*dump_meta), &dump_length)) {
		/* Discard the dump */
		sahara_send_reset(context);
		return;
	}
	if (check_mul_overflow((u64)sizeof(*image_out_table), table_nents, &mul_bytes)) {
		/* Discard the dump */
		sahara_send_reset(context);
		return;
	}
	if (check_add_overflow(dump_length, mul_bytes, &dump_length)) {
		/* Discard the dump */
		sahara_send_reset(context);
		return;
	}

	context->mem_dump_sz = dump_length;
	context->mem_dump = vzalloc(dump_length);
	if (!context->mem_dump) {
		/* Discard the dump */
		sahara_send_reset(context);
		return;
	}

	/* Populate the dump metadata and table for userspace */
	dump_meta = context->mem_dump;
	dump_meta->magic = SAHARA_DUMP_V1_MAGIC;
	dump_meta->version = SAHARA_DUMP_V1_VER;
	dump_meta->dump_size = dump_length;
	dump_meta->table_size = context->dump_table_length;

	image_out_table = context->mem_dump + sizeof(*dump_meta);
	for (i = 0; i < table_nents; ++i)
		sahara_get_table_entry(context, i, &image_out_table[i]);

	context->mem_dump_freespace = &image_out_table[i];

	/* Done parsing the table, switch to image dump mode */
	context->dump_table_length = 0;

	/* Request the first chunk of the first image */
	context->dump_image = &image_out_table[0];
	dump_length = min_t(u64, context->dump_image->length, SAHARA_READ_MAX_SIZE);
	/* Avoid requesting EOI sized data so that we can identify errors */
	if (dump_length == SAHARA_END_OF_IMAGE_LENGTH)
		dump_length = SAHARA_END_OF_IMAGE_LENGTH / 2;

	context->dump_image_offset = dump_length;

	context->rx_size_requested = dump_length;

	ret = sahara_send_memory_read(context, context->dump_image->address, dump_length);
	if (ret)
		dev_err(&context->mhi_dev->dev, "Unable to send read for dump content %d\n", ret);
}

static void sahara_parse_dump_image(struct sahara_context *context)
{
	u64 dump_length;
	int ret;

	memcpy(context->mem_dump_freespace, context->rx, context->rx_size);
	context->mem_dump_freespace += context->rx_size;

	if (context->dump_image_offset >= context->dump_image->length) {
		/* Need to move to next image */
		context->dump_image++;
		context->dump_images_left--;
		context->dump_image_offset = 0;

		if (!context->dump_images_left) {
			/* Dump done */
			dev_coredumpv(context->mhi_dev->mhi_cntrl->cntrl_dev,
				      context->mem_dump,
				      context->mem_dump_sz,
				      GFP_KERNEL);
			context->mem_dump = NULL;
			sahara_send_reset(context);
			return;
		}
	}

	/* Get next image chunk */
	dump_length = context->dump_image->length - context->dump_image_offset;
	dump_length = min_t(u64, dump_length, SAHARA_READ_MAX_SIZE);
	/* Avoid requesting EOI sized data so that we can identify errors */
	if (dump_length == SAHARA_END_OF_IMAGE_LENGTH)
		dump_length = SAHARA_END_OF_IMAGE_LENGTH / 2;

	ret = sahara_send_memory_read(context,
				      context->dump_image->address + context->dump_image_offset,
				      dump_length);

	context->dump_image_offset += dump_length;
	context->rx_size_requested = dump_length;

	if (ret)
		dev_err(&context->mhi_dev->dev,
			"Unable to send read for dump content %d\n", ret);
}

static void sahara_dump_processing(struct work_struct *work)
{
	struct sahara_context *context = container_of(work, struct sahara_context, dump_work);
	int ret;

	/*
	 * We should get the expected raw data, but if the device has an error
	 * it is supposed to send EOI with an error code.
	 */
	if (context->rx_size != context->rx_size_requested &&
	    context->rx_size != SAHARA_END_OF_IMAGE_LENGTH) {
		dev_err(&context->mhi_dev->dev,
			"Unexpected response to read_data. Expected size: %#zx got: %#zx\n",
			context->rx_size_requested,
			context->rx_size);
		goto error;
	}

	if (context->rx_size == SAHARA_END_OF_IMAGE_LENGTH &&
	    le32_to_cpu(context->rx->cmd) == SAHARA_END_OF_IMAGE_CMD) {
		dev_err(&context->mhi_dev->dev,
			"Unexpected EOI response to read_data. Status: %d\n",
			le32_to_cpu(context->rx->end_of_image.status));
		goto error;
	}

	if (context->rx_size == SAHARA_END_OF_IMAGE_LENGTH &&
	    le32_to_cpu(context->rx->cmd) != SAHARA_END_OF_IMAGE_CMD) {
		dev_err(&context->mhi_dev->dev,
			"Invalid EOI response to read_data. CMD: %d\n",
			le32_to_cpu(context->rx->cmd));
		goto error;
	}

	/*
	 * Need to know if we received the dump table, or part of a dump image.
	 * Since we get raw data, we cannot tell from the data itself. Instead,
	 * we use the stored dump_table_length, which we zero after we read and
	 * process the entire table.
	 */
	if (context->dump_table_length)
		sahara_parse_dump_table(context);
	else
		sahara_parse_dump_image(context);

	ret = mhi_queue_buf(context->mhi_dev, DMA_FROM_DEVICE, context->rx,
			    SAHARA_PACKET_MAX_SIZE, MHI_EOT);
	if (ret)
		dev_err(&context->mhi_dev->dev, "Unable to requeue rx buf %d\n", ret);

	return;

error:
	vfree(context->mem_dump);
	context->mem_dump = NULL;
	sahara_send_reset(context);
}

static void sahara_read_data_processing(struct work_struct *work)
{
	struct sahara_context *context = container_of(work, struct sahara_context, read_data_work);

	sahara_send_read_data(context);
}

static int sahara_mhi_probe(struct mhi_device *mhi_dev, const struct mhi_device_id *id)
{
	const struct mhi_sahara_fw_table *sahara_fw;
	struct sahara_context *context;
	int ret;
	int i;

	context = devm_kzalloc(&mhi_dev->dev, sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;

	context->rx = devm_kzalloc(&mhi_dev->dev, SAHARA_PACKET_MAX_SIZE, GFP_KERNEL);
	if (!context->rx)
		return -ENOMEM;

	sahara_fw = mhi_dev->mhi_cntrl->sahara_fw;
	if (!sahara_fw || !sahara_fw->image_table || !sahara_fw->table_size)
		return -ENODEV;

	context->image_table = sahara_fw->image_table;
	context->table_size = sahara_fw->table_size;
	context->non_streaming = sahara_fw->non_streaming;
	context->fw_folder = sahara_fw->fw_folder;

	/*
	 * There are two firmware implementations for READ_DATA handling.
	 * The older "SBL" implementation defines a Sahara transfer size, and
	 * expects that the response is a single transport transfer. If the
	 * FW wants to transfer a file that is larger than the transfer size,
	 * the FW will issue multiple READ_DATA commands. For this
	 * implementation, we need to allocate enough buffers to contain the
	 * entire Sahara transfer size.
	 *
	 * The newer "XBL" implementation does not define a maximum transfer
	 * size and instead expects the data to be streamed over using the
	 * transport level MTU. The FW will issue a single READ_DATA command
	 * of whatever size, and consume multiple transport level transfers
	 * until the expected amount of data is consumed. For this
	 * implementation we only need a single buffer of the transport MTU
	 * but we'll need to be able to use it multiple times for a single
	 * READ_DATA request.
	 *
	 * AIC100 is the SBL implementation and defines SAHARA_TRANSFER_MAX_SIZE
	 * and we need 9x SAHARA_PACKET_MAX_SIZE to cover that. We can use
	 * MHI_CHAIN to link multiple buffers into a single transfer but the
	 * remote side will not consume the buffers until it sees an EOT, thus
	 * we need to allocate enough buffers to put in the tx fifo to cover an
	 * entire READ_DATA request of the max size.
	 *
	 * AIC200 is the XBL implementation, and so a single buffer will work.
	 */
	for (i = 0; i < SAHARA_NUM_TX_BUF; ++i) {
		context->tx[i] = devm_kzalloc(&mhi_dev->dev,
					      SAHARA_PACKET_MAX_SIZE,
					      GFP_KERNEL);
		if (!context->tx[i])
			return -ENOMEM;
		if (is_streaming(context))
			break;
	}

	context->mhi_dev = mhi_dev;
	INIT_WORK(&context->fw_work, sahara_processing);
	INIT_WORK(&context->dump_work, sahara_dump_processing);
	INIT_WORK(&context->read_data_work, sahara_read_data_processing);
	INIT_WORK(&context->cmd_work, sahara_command_processing);

	for (i = 0; i < SAHARA_NUM_CMD_BUF; i++) {
		context->cmd_buff[i] = devm_kzalloc(&mhi_dev->dev,
						    SAHARA_PACKET_MAX_SIZE, GFP_KERNEL);
		if (!context->cmd_buff[i])
			return -ENOMEM;
	}

	context->is_cmd_mode = false;
	context->receiving_training_data = false;
	context->training_size = 0;
	context->training_rcvd = 0;
	context->training_nbuf = 0;

	context->active_image_id = SAHARA_IMAGE_ID_NONE;
	dev_set_drvdata(&mhi_dev->dev, context);

	ret = mhi_prepare_for_transfer(mhi_dev);
	if (ret)
		return ret;

	ret = mhi_queue_buf(mhi_dev, DMA_FROM_DEVICE, context->rx, SAHARA_PACKET_MAX_SIZE, MHI_EOT);
	if (ret) {
		mhi_unprepare_from_transfer(mhi_dev);
		return ret;
	}

	sahara_sysfs_create(mhi_dev);

	return 0;
}

static void sahara_mhi_remove(struct mhi_device *mhi_dev)
{
	struct sahara_context *context = dev_get_drvdata(&mhi_dev->dev);

	cancel_work_sync(&context->fw_work);
	cancel_work_sync(&context->dump_work);
	cancel_work_sync(&context->cmd_work);
	vfree(context->mem_dump);
	sahara_release_image(context);
	mhi_unprepare_from_transfer(mhi_dev);
}

static void sahara_mhi_ul_xfer_cb(struct mhi_device *mhi_dev, struct mhi_result *mhi_result)
{
	struct sahara_context *context = dev_get_drvdata(&mhi_dev->dev);

	if (!mhi_result->transaction_status && context->read_data_length &&
	    (is_streaming(context) || mhi_result->buf_addr == context->read_data_group_end))
		schedule_work(&context->read_data_work);
}

static void sahara_mhi_dl_xfer_cb(struct mhi_device *mhi_dev, struct mhi_result *mhi_result)
{
	struct sahara_context *context = dev_get_drvdata(&mhi_dev->dev);
	struct sahara_cntrl_training_data *ct;
	struct device *dev;
	size_t copy;
	int ret;
	u32 i;

	if (mhi_result->transaction_status)
		return;

	/*
	 * Raw training payload completions arrive for cmd_buff[] buffers.
	 * Do not schedule cmd_work for those.
	 */
	if (context->is_cmd_mode && context->receiving_training_data &&
	    mhi_result->buf_addr != context->rx) {
		dev = &context->mhi_dev->mhi_cntrl->mhi_dev->dev;
		ct = sahara_cntrl_training_get(dev);
		if (!ct)
			return;

		for (i = 0; i < context->training_nbuf; i++) {
			if (mhi_result->buf_addr == context->cmd_buff[i]) {
				mutex_lock(&ct->lock);
				copy = min_t(size_t, mhi_result->bytes_xferd,
					     ct->size - ct->copied);
				memcpy((u8 *)ct->data + ct->copied,
				       mhi_result->buf_addr, copy);
				ct->copied += copy;
				mutex_unlock(&ct->lock);

				context->training_rcvd += copy;

				if (context->training_rcvd >= context->training_size) {
					mutex_lock(&ct->lock);
					ct->receiving = false;
					mutex_unlock(&ct->lock);

					context->receiving_training_data = false;
					context->is_cmd_mode = false;

					sahara_switch_mode_to_img_tx(context);
					ret = mhi_queue_buf(context->mhi_dev,
							    DMA_FROM_DEVICE,
							    context->rx,
							    SAHARA_PACKET_MAX_SIZE,
							    MHI_EOT);
					if (ret)
						dev_err(&context->mhi_dev->dev,
							"Unable to requeue rx buf %d\n", ret);
				}
				return;
			}
		}
		return;
	}

	/* Normal Rx completion */
	context->rx_size = mhi_result->bytes_xferd;
	if (context->is_mem_dump_mode)
		schedule_work(&context->dump_work);
	else if (context->is_cmd_mode)
		schedule_work(&context->cmd_work);
	else
		schedule_work(&context->fw_work);

}

static const struct mhi_device_id sahara_mhi_match_table[] = {
	{ .chan = "QAIC_SAHARA", },
	{ .chan = "SAHARA"},
	{},
};
MODULE_DEVICE_TABLE(mhi, sahara_mhi_match_table);

static struct mhi_driver sahara_mhi_driver = {
	.id_table = sahara_mhi_match_table,
	.remove = sahara_mhi_remove,
	.probe = sahara_mhi_probe,
	.ul_xfer_cb = sahara_mhi_ul_xfer_cb,
	.dl_xfer_cb = sahara_mhi_dl_xfer_cb,
	.driver = {
		.name = "sahara",
	},
};
module_mhi_driver(sahara_mhi_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Qualcomm Sahara MHI protocol driver");
