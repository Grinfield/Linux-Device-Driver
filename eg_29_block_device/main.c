#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/genhd.h>
#include <linux/vmalloc.h>
#include <linux/blk-mq.h>

#include "main.h"

#define INVALIDATE_DELAY (30 * HZ)
#define	SECTOR_SHIFT	 9	/* 512 bytes */
#define SECTOR_SIZE	 (1 << SECTOR_SHIFT)

static struct ldd_dev *ldd_dev;
static int nsectors = 1024 * 1024;
module_param(nsectors, int, 0);
static int hardsect_size = 512;
module_param(hardsect_size, int, 0);

enum
{
	RM_SIMPLE = 0,	/* The extra-simple request function */
	RM_FULL = 1,	/* The full-blown version */
	RM_NOQUEUE = 2, /* Use make_request */
};
static int request_mode = RM_SIMPLE;
module_param(request_mode, int, 0);

static
int block_open(struct block_device *bdev, fmode_t mode)
{
	struct ldd_dev *ldd_dev = bdev->bd_disk->private_data;

	del_timer_sync(&ldd_dev->timer);
	spin_lock(&ldd_dev->lock);
	if (!ldd_dev->users)
		check_disk_change(bdev);
	ldd_dev->users++;
	spin_unlock(&ldd_dev->lock);

	return 0;
}

static
void block_release(struct gendisk *gdisk, fmode_t mode)
{
	struct ldd_dev *ldd_dev = gdisk->private_data;

	spin_lock(&ldd_dev->lock);
	ldd_dev->users--;

	if (!ldd_dev->users) {
		ldd_dev->timer.expires = jiffies + INVALIDATE_DELAY;
		add_timer(&ldd_dev->timer);
	}
	spin_unlock(&ldd_dev->lock);
}

static
int block_media_changed(struct gendisk *gdisk)
{
	struct ldd_dev *ldd_dev = gdisk->private_data;

	return (ldd_dev->media_change) ? 1 : 0;
}

static
int block_revalidate(struct gendisk *gdisk)
{
	struct ldd_dev *ldd_dev = gdisk->private_data;

	if (ldd_dev->media_change) {
		ldd_dev->media_change = false;
		memset(ldd_dev->data, 0, ldd_dev->size);
	}

	return 0;
}

static struct block_device_operations block_ops = {
	.owner = THIS_MODULE,
	.open = block_open,
	.release = block_release,
	.media_changed = block_media_changed,
	.revalidate_disk = block_revalidate,
	// .ioctl	         = sbull_ioctl
};

static
void transfer(struct ldd_dev *ldd_dev, unsigned long sector,
					 unsigned long nsect, char *buffer, int dir)
{
	unsigned long offset = sector << SECTOR_SHIFT;
	unsigned long nbytes = nsect << SECTOR_SHIFT;

	if ((offset + nbytes) > ldd_dev->size) {
		pr_notice("Write out of size: (%ld, %ld)\n", offset, nbytes);
		return;
	}

	if (dir == WRITE)
		memcpy(ldd_dev->data + offset, buffer, nbytes);
	else
		memcpy(buffer, ldd_dev->data + offset, nbytes);
}

static void sbull_request(struct request_queue *q)
{
	struct request *req;

	while ((req = blk_fetch_request(q)) != NULL) {
		struct ldd_dev *dev = req->rq_disk->private_data;

		if (req->cmd_type != REQ_TYPE_FS) {
			pr_notice("Skip non-fs request\n");
			blk_end_request_cur(req, -EIO);
			continue;
		}

		pr_notice("Req dir %ld sec %ld, nr %d\n",
				  rq_data_dir(req),
				  blk_rq_pos(req),
				  blk_rq_cur_sectors(req));
		transfer(dev, blk_rq_pos(req), blk_rq_cur_sectors(req),
				 req->buffer, rq_data_dir(req));
		blk_end_request_cur(req, 0);
	}
}

#if 0
static
blk_status_t ldd_block_request_simple(struct blk_mq_hw_ctx *hctx,
			       const struct blk_mq_queue_data *qd)
{
	struct request *req = qd->rq;
	struct ldd_dev *dev = req->rq_disk->private_data;
	struct bio_vec bvec;
	struct req_iterator iter;
	sector_t pos_sector = blk_rq_pos(req);
	void *buffer;
	blk_status_t ret = BLK_STS_OK;

	blk_mq_start_request(req);

	if (blk_rq_is_passthrough(req)) {
		pr_notice("Skip non-fs request\n");
		ret = BLK_STS_IOERR;
		goto done;
	}

	rq_for_each_segment(bvec, req, iter) {
		size_t num_sector = blk_rq_cur_sectors(req);
		bool dir = rq_data_dir(req);
		pr_notice("Req dir: %d, sec %lld, nr %ld\n",
			  dir, pos_sector, num_sector);
		buffer = page_address(bvec.bv_page) + bvec.bv_offset;
		transfer(dev, pos_sector, num_sector, buffer, dir);
		pos_sector += num_sector;
	}


done:
	blk_mq_end_request(req, ret);
	return ret;
}

static struct blk_mq_ops mq_ops_simple = {
	.queue_rq = ldd_block_request_simple,
};
#endif

static
int block_xfer_bio(struct ldd_dev *ldd_dev, struct bio *bio)
{
	struct bio_vec *bvec;
	int iter;
	char *buffer;
	sector_t sector = bio->bi_sector;
	pr_notice("bio sector: %ld\n", sector);

	bio_for_each_segment(bvec, bio, iter) {
		pr_notice("iter: %d\n", iter);
		buffer = __bio_kmap_atomic(bio, iter, KM_USER0);
		pr_notice("bio_cur_bytes(bio) = %d\n", bio_cur_bytes(bio));
		transfer(ldd_dev, sector, (bio_cur_bytes(bio) >> SECTOR_SHIFT),
				 buffer, bio_data_dir(bio));

		sector += (bio_cur_bytes(bio) >> SECTOR_SHIFT);
		pr_notice("In iteration: bio sector: %ld\n", sector);

		__bio_kunmap_atomic(buffer, KM_USER0);
	}

	return 0;
}

static
int block_xfer_request(struct ldd_dev *ldd_dev, struct request *req)
{
	struct bio *bio;
	int xfer_bytes = 0;

	__rq_for_each_bio(bio, req) {
		block_xfer_bio(ldd_dev, bio);
		xfer_bytes += bio->bi_size;
	}
	return xfer_bytes;
}

static 
void sbull_full_request(struct request_queue *q)
{
	struct request *req;
	int bytes_xferred;
	struct ldd_dev *dev = q->queuedata;

	while ((req = blk_fetch_request(q)) != NULL) {
		if (req->cmd_type != REQ_TYPE_FS) {
			printk (KERN_NOTICE "Skip non-fs request\n");
			__blk_end_request(req, -EIO, blk_rq_cur_bytes(req));
			continue;
		}
		bytes_xferred = block_xfer_request(dev, req);
		__blk_end_request(req, 0, bytes_xferred);
	}
}

#if 0
static blk_status_t ldd_block_request_full(struct blk_mq_hw_ctx *hctx,
										   const struct blk_mq_queue_data *qd)
{
	blk_status_t rv = BLK_STS_OK;
	int sectors_xferred;
	struct request *req = qd->rq;
	struct ldd_dev *ldd_dev = req->q->queuedata;

	blk_mq_start_request(req);


	if (blk_rq_is_passthrough(req)) {
		pr_notice("Skip non-fs request\n");
		rv = BLK_STS_IOERR;
		goto done;
	}

	sectors_xferred = block_xfer_request(ldd_dev, req);

done:
	blk_mq_end_request(req, rv);

	return rv;
}

static struct blk_mq_ops mq_ops_full = {
	.queue_rq = ldd_block_request_full,
};
#endif

void timeout_cb(struct timer_list *timer)
{
	struct ldd_dev *ldd_dev = from_timer(ldd_dev, timer, timer);

	spin_lock(&ldd_dev->lock);
	pr_warn("timeout!!\n");
	spin_unlock(&ldd_dev->lock);
}

static
void mk_request(struct request_queue *q, struct bio *bio)
{
	int status;
	struct ldd_dev *ldd_dev = q->queuedata;

	status = block_xfer_bio(ldd_dev, bio);
	bio_endio(bio, status);
}

static int setup_device(struct ldd_dev *ldd_dev)
{
	int rv = 0;

	ldd_dev->size = nsectors * hardsect_size;
	ldd_dev->users = 0;
	ldd_dev->media_change = false;
	ldd_dev->data = vmalloc(ldd_dev->size);
	if (!ldd_dev->data) {
		pr_err("Allocat vm space failed\n");
		return -ENOMEM;
	}
	spin_lock_init(&ldd_dev->lock);
	timer_setup(&ldd_dev->timer, timeout_cb, 0);

	pr_err("REQUEST_MODE = %d\n", request_mode);
	switch (request_mode) {
	case RM_NOQUEUE:
		ldd_dev->queue = blk_alloc_queue(GFP_KERNEL);
		if (!ldd_dev->queue) {
			rv = -ENOMEM;
			goto out_vfree;
		}
		blk_queue_make_request(ldd_dev->queue, mk_request);
		break;
	case RM_FULL:
		ldd_dev->queue = blk_init_queue(sbull_full_request, &ldd_dev->lock);
		// ldd_dev->queue = blk_mq_init_sq_queue(&ldd_dev->tag_set,
		// 				      &mq_ops_full, 256,
		// 				      BLK_MQ_F_SHOULD_MERGE);
		if (!ldd_dev->queue)
		{
			rv = -ENOMEM;
			goto out_vfree;
		}
		break;
	default:
		pr_notice("fallbackk to simple!\n");
	case RM_SIMPLE:
		ldd_dev->queue = blk_init_queue(sbull_request, &ldd_dev->lock);
		// ldd_dev->queue = blk_mq_init_sq_queue(&ldd_dev->tag_set,
		// 				      &mq_ops_simple, 256,
		// 				      BLK_MQ_F_SHOULD_MERGE);
		if (!ldd_dev->queue) {
			rv = -ENOMEM;
			goto out_vfree;
		}
		break;
	}

	blk_queue_logical_block_size(ldd_dev->queue, hardsect_size);
	ldd_dev->queue->queuedata = ldd_dev;

	ldd_dev->gd = alloc_disk(16);
	if (!ldd_dev->gd) {
		pr_err("Alloc disk failure\n");
		rv = -ENOMEM;
		goto out_vfree;
	}

	ldd_dev->gd->major = ldd_dev->major;
	ldd_dev->gd->first_minor = 0;
	ldd_dev->gd->fops = &block_ops;
	ldd_dev->gd->queue = ldd_dev->queue;
	ldd_dev->gd->private_data = ldd_dev;
	snprintf(ldd_dev->gd->disk_name, DISK_NAME_LEN, "memdisk");
	set_capacity(ldd_dev->gd, nsectors * (hardsect_size / SECTOR_SIZE));

	// Activate this block device
	add_disk(ldd_dev->gd);

	return 0;

out_vfree:
	if (ldd_dev->data)
		vfree(ldd_dev->data);

	return rv;
}

static
int __init m_init(void)
{
	ldd_dev = kzalloc(sizeof(struct ldd_dev), GFP_KERNEL);
	if (!ldd_dev)
		return -ENOMEM;

	ldd_dev->major = register_blkdev(0, MODULE_NAME);

	setup_device(ldd_dev);

	return 0;
}

static
void __exit m_exit(void)
{
	if (ldd_dev->gd)
		del_gendisk(ldd_dev->gd);

	unregister_blkdev(ldd_dev->major, MODULE_NAME);
}

module_init(m_init);
module_exit(m_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("d0u9");
MODULE_DESCRIPTION("PCI Driver skel");

