#include <crypto/internal/skcipher.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <linux/version.h>

#include "mtk-aes-engine.h"

static void aes_engine_start(struct mtk_dev *mtk)
{
	u32 regVal;
	u32 AES_glo_cfg = 0;

	AES_glo_cfg = (AES_TX_DMA_EN | AES_RX_DMA_EN | AES_TX_WB_DDONE
		| AES_DESC_5DW_INFO_EN | AES_RX_ANYBYTE_ALIGN);

	writel(AES_DLY_INIT_VALUE, mtk->base + AES_DLY_INT_CFG);
	writel(AES_MASK_INT_ALL, mtk->base + AES_INT_STATUS);
	regVal = readl(mtk->base + AES_INT_STATUS);
	writel(AES_MASK_INT_ALL, mtk->base + AES_INT_MASK);

	AES_glo_cfg |= AES_BT_SIZE_16DWORDS;
	writel(AES_glo_cfg, mtk->base + AES_GLO_CFG);
}

static void aes_engine_reset(void)
{
	u32 val;

	val = readl(REG_CLKCTRL);
	val |= RALINK_CRYPTO_CLK_EN;
	writel(val, REG_CLKCTRL);

	udelay(10);

	val = readl(REG_RSTCTRL);
	val |= RALINK_CRYPTO_RST;
	writel(val, REG_RSTCTRL);

	udelay(10);

	val &= ~(RALINK_CRYPTO_RST);
	writel(val, REG_RSTCTRL);

	udelay(100);
}

static void aes_engine_stop(struct mtk_dev *mtk)
{
	int i;
	u32 regVal;

	regVal = readl(mtk->base + AES_GLO_CFG);
	regVal &= ~(AES_TX_WB_DDONE | AES_RX_DMA_EN | AES_TX_DMA_EN);
	writel(regVal, mtk->base + AES_GLO_CFG);

	/* wait AES stopped */
	for (i = 0; i < 50; i++) {
		msleep(1);
		regVal = readl(mtk->base + AES_GLO_CFG);
		if (!(regVal & (AES_RX_DMA_BUSY | AES_TX_DMA_BUSY)))
			break;
	}
	/* disable AES interrupt */
	writel(0, mtk->base + AES_INT_MASK);
}

/* Allocate Descriptor rings */
static int aes_engine_desc_init(struct mtk_dev *mtk)
{
	u32 regVal;
	int i;
	size_t size;

	size = (MTK_RING_SIZE * sizeof(struct aes_txdesc));

	mtk->tx = dma_zalloc_coherent(mtk->dev, size,
					&mtk->phy_tx, GFP_KERNEL);
	if (!mtk->tx)
		goto err_cleanup;

	dev_info(mtk->dev, "TX Ring : %08X\n", mtk->phy_tx);

	size = (MTK_RING_SIZE * sizeof(struct aes_rxdesc));

	mtk->rx = dma_zalloc_coherent(mtk->dev, size,
					&mtk->phy_rx, GFP_KERNEL);
	if (!mtk->rx)
		goto err_cleanup;

	dev_info(mtk->dev, "RX Ring : %08X\n", mtk->phy_rx);

	size = (MTK_RING_SIZE * sizeof(struct mtk_dma_rec));

	mtk->rec = dma_zalloc_coherent(mtk->dev, size,
					&mtk->phy_rec,  GFP_KERNEL);

	if (!mtk->rec)
		goto err_cleanup;

	dev_info(mtk->dev, "Rec Ring : %08X\n", mtk->phy_rec);

	for (i = 0; i < MTK_RING_SIZE; i++)
		mtk->tx[i].txd_info2 |= TX2_DMA_DONE;

	regVal = readl(mtk->base + AES_GLO_CFG);
	regVal &= 0x00000ff0;
	writel(regVal, mtk->base + AES_GLO_CFG);
	regVal = readl(mtk->base + AES_GLO_CFG);

	writel((u32)mtk->phy_tx, mtk->base + AES_TX_BASE_PTR0);
	writel((u32)MTK_RING_SIZE, mtk->base + AES_TX_MAX_CNT0);
	writel(0, mtk->base + AES_TX_CTX_IDX0);

	regVal = readl(mtk->base + AES_TX_CTX_IDX0);

	writel(AES_PST_DTX_IDX0, mtk->base + AES_RST_CFG);

	writel((u32)mtk->phy_rx, mtk->base + AES_RX_BASE_PTR0);
	writel((u32)MTK_RING_SIZE, mtk->base + AES_RX_MAX_CNT0);
	writel((u32)(MTK_RING_SIZE - 1), mtk->base + AES_RX_CALC_IDX0);
	regVal = readl(mtk->base + AES_RX_CALC_IDX0);

	mtk->rec_rear_idx = MTK_RING_SIZE - 1;
	mtk->rec_front_idx = 0;
	mtk->count = 0;

	writel(AES_PST_DRX_IDX0, mtk->base + AES_RST_CFG);

	return 0;
err_cleanup:
	return -ENOMEM;
}

/* Free Descriptor Rings */
static void aes_engine_desc_free(struct mtk_dev *mtk)
{
	size_t	size;

	writel(0, mtk->base + AES_TX_BASE_PTR0);
	writel(0, mtk->base + AES_RX_BASE_PTR0);

	size = MTK_RING_SIZE * sizeof(struct aes_txdesc);

	if (mtk->tx) {
		dma_free_coherent(mtk->dev, size, mtk->tx, mtk->phy_tx);
		mtk->tx = NULL;
		mtk->phy_tx = 0;
	}

	size = MTK_RING_SIZE * sizeof(struct aes_rxdesc);

	if (mtk->rx) {
		dma_free_coherent(mtk->dev, size, mtk->rx, mtk->phy_rx);
		mtk->rx = NULL;
		mtk->phy_rx = 0;
	}

	size = MTK_RING_SIZE * sizeof(struct mtk_dma_rec);

	if (mtk->rec) {
		dma_free_coherent(mtk->dev, size, mtk->rec, mtk->phy_rec);
		mtk->rec = NULL;
		mtk->phy_rec = 0;
	}
}

static int mtk_combine_scatter(struct mtk_dev *mtk, struct scatterlist *sgsrc,
			struct scatterlist *sgdst, int total)
{
	struct mtk_dma_rec *rec;
	unsigned int remainin, remainout;
	int offsetin = 0;
	int offsetout = 0;
	struct scatterlist *sgin, *sgout;
	int ctr;
	unsigned int len;
	int count = 0;
	bool nextin = false;
	bool nextout = false;

	sgin = sgsrc;
	sgout = sgdst;
	remainin = sgin->length;
	remainout = sgout->length;
	ctr = mtk->rec_rear_idx;

	while (total > 0) {
		if (nextin) {
			sgin = sg_next(sgin);
			remainin = sgin->length;
			if (remainin == 0)
				continue;
			offsetin = 0;
			nextin = false;
		}
		if (nextout) {
			sgout = sg_next(sgout);
			remainout = sgout->length;
			if (remainout == 0)
				continue;
			offsetout = 0;
			nextout = false;
		}
		count++;
		ctr = (ctr + 1) % MTK_RING_SIZE;
		rec = &mtk->rec[ctr];
		rec->src = (unsigned int)(sg_virt(sgin) + offsetin);
		rec->dst = (unsigned int)(sg_virt(sgout) + offsetout);
		if (remainin == remainout) {
			len = remainin;
			nextin = true;
			nextout = true;
		} else if (remainin < remainout) {
			len = remainin;
			offsetout += len;
			remainout -= len;
			nextin = true;
		} else {
			len = remainout;
			offsetin += len;
			remainin -= len;
			nextout = true;
		}
		total -= len;
		rec->len = len;
	}
	return count;
}

int mtk_aes_xmit(struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct mtk_aes_reqctx *rctx = ablkcipher_request_ctx(req);
	struct mtk_dev *mtk = ctx->mtk;
	struct aes_txdesc *txdesc;
	struct aes_rxdesc *rxdesc;
	struct mtk_dma_rec *rec;
	u32 aes_txd_info4, info;
	u32 ctr = 0, count, i;
	unsigned long flags;

	if (!mtk)
		return -ENODEV;

	spin_lock_irqsave(&mtk->lock, flags);

	if (ctx->keylen == AES_KEYSIZE_256)
		aes_txd_info4 = TX4_DMA_AES_256;
	else if (ctx->keylen == AES_KEYSIZE_192)
		aes_txd_info4 = TX4_DMA_AES_192;
	else
		aes_txd_info4 = TX4_DMA_AES_128;

	if (rctx->mode & CRYPTO_MODE_ENC)
		aes_txd_info4 |= TX4_DMA_ENC;

	if (rctx->mode & CRYPTO_MODE_CBC)
		aes_txd_info4 |= TX4_DMA_CBC | TX4_DMA_IVR;

	count = mtk_combine_scatter(mtk, req->src, req->dst, req->nbytes);

	for (i = 0; i < count; i++) {
		ctr = (mtk->rec_rear_idx + i + 1) % MTK_RING_SIZE;
		txdesc = &mtk->tx[ctr];
		rxdesc = &mtk->rx[ctr];
		rec = &mtk->rec[ctr];
		rec->req = (void *)req;
		info = aes_txd_info4;

		if ((rctx->mode & CRYPTO_MODE_CBC) && (i == 0)) {
			if (!req->info)
				memset((void *)txdesc->IV, 0xFF, 16);
			else
				memcpy((void *)txdesc->IV, (void *)req->info, 16);

			info |= TX4_DMA_KIU;
		}
		txdesc->txd_info4 = info;

		if (i == 0) {
			txdesc->SDP0 = (u32)(void *)ctx->phy_key;
			txdesc->txd_info2 = TX2_DMA_SDL0_SET(ctx->keylen);
		} else {
			txdesc->txd_info2 = 0;
		}

		txdesc->SDP1 = (u32)dma_map_single(mtk->dev, (void *)rec->src,
				rec->len, DMA_BIDIRECTIONAL);

		txdesc->txd_info2 |= TX2_DMA_SDL1_SET(rec->len);

		rxdesc->SDP0 = (u32)dma_map_single(mtk->dev, (void *)rec->dst,
				rec->len, DMA_BIDIRECTIONAL);

		rxdesc->rxd_info2 = RX2_DMA_SDL0_SET(rec->len);
	}
	txdesc->txd_info2 |= TX2_DMA_LS1;
	rxdesc->rxd_info2 |= RX2_DMA_LS0;
	mtk->rec_rear_idx = (mtk->rec_rear_idx + count) % MTK_RING_SIZE;
	ctr = (mtk->rec_rear_idx + 1) % MTK_RING_SIZE;
	spin_unlock_irqrestore(&mtk->lock, flags);
	/*
	 * Make sure all data is updated before starting engine.
	 */
	wmb();
	/* Writing new scattercount starts PDMA action */
	writel(ctr, mtk->base + AES_TX_CTX_IDX0);
	return 0;
}

int mtk_handle_request(struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct mtk_dev *mtk = ctx->mtk;
	int ret = 0;

	if (!mtk)
		return -ENODEV;

	/* assign new request to device */
	ret = sg_nents_for_len(req->dst, req->nbytes);
	if (ret < 0) {
		dev_info(mtk->dev, "Invalid Dst SG\n");
		return ret;
	}

	ret = sg_nents_for_len(req->src, req->nbytes);

	if (ret < 0) {
		dev_info(mtk->dev, "Invalid Src SG\n");
		return ret;
	}

	ret = mtk_aes_xmit(req);

	return ret;
}

int mtk_handle_queue(struct mtk_dev *mtk,
			    struct ablkcipher_request *req)
{
	unsigned long flags;
	int ret = 0, err;

	spin_lock_irqsave(&mtk->lock, flags);

	if (mtk->count > MTK_QUEUE_LENGTH) {
		spin_unlock_irqrestore(&mtk->lock, flags);
		return -EBUSY;
	}
	ret = -EINPROGRESS;
	if (req)
		mtk->count = mtk->count + 1;

	spin_unlock_irqrestore(&mtk->lock, flags);

	if (!req)
		return 0;

	err = mtk_handle_request(req);

	if (err)
		printk("Error: %d\n", err);

	return ret;
}

static void mtk_tasklet_req_done(unsigned long data)
{
	struct mtk_dev *mtk = (struct mtk_dev *)data;
	struct ablkcipher_request *req;
	struct aes_txdesc *txdesc;
	struct aes_rxdesc *rxdesc;
	struct mtk_dma_rec *rec;
	int ctr = 0;
	u32 regVal;
	int try_count;

	if (mtk->count == 0)
		return;

get_next:
	try_count = 0;
	mtk->count = mtk->count - 1;

	do {
		regVal = readl(mtk->base + AES_GLO_CFG);

		if (!(regVal & (AES_RX_DMA_BUSY | AES_TX_DMA_BUSY)))
			break;
		try_count++;
		if (try_count > 1000000) {
			dev_info(mtk->dev, "PDMA time-out: %d", try_count);
			mtk->count = mtk->count + 1;
			return; // -ETIMEDOUT;
		}
	} while (1);

	ctr = mtk->rec_front_idx;

	do {
		rxdesc = &mtk->rx[ctr];
		txdesc = &mtk->tx[ctr];
		rec = &mtk->rec[ctr];

		if (!(rxdesc->rxd_info2 & RX2_DMA_DONE)) {
			mtk->count = mtk->count + 1;
			tasklet_schedule(&mtk->done_tasklet);
			return;
		}

		rxdesc->rxd_info2 &= ~RX2_DMA_DONE;

		dma_unmap_single(mtk->dev, (dma_addr_t)txdesc->SDP1, rec->len,
				DMA_TO_DEVICE);

		dma_unmap_single(mtk->dev, (dma_addr_t)rxdesc->SDP0, rec->len,
				DMA_FROM_DEVICE);

		txdesc->txd_info2 = 0;

		if (rxdesc->rxd_info2 & RX2_DMA_LS0)
			break;

		ctr = (ctr + 1) % MTK_RING_SIZE;

	} while (1);

	mtk->rec_front_idx = (ctr + 1) % MTK_RING_SIZE;
	req = (struct ablkcipher_request *)rec->req;
	writel(ctr, mtk->base + AES_RX_CALC_IDX0);
	req->base.complete(&req->base, 0);

	if (mtk->count > 0) {
		goto get_next;
	}

	return;
}

static irqreturn_t mtk_aes_irq(int irq, void *arg)
{
	struct mtk_dev *mtk = arg;
	u32 regVal;

	regVal = readl(mtk->base + AES_GLO_CFG);

	if ((regVal & (AES_RX_DMA_EN | AES_TX_DMA_EN))
		!= (AES_RX_DMA_EN | AES_TX_DMA_EN)) {
		dev_err(mtk->dev, "No active DMA on interrupt!");
		return IRQ_NONE;
	}
	tasklet_schedule(&mtk->done_tasklet);

	writel(AES_MASK_INT_ALL, mtk->base + AES_INT_STATUS);

	return IRQ_HANDLED;
}

static struct mtk_dev *mtk_aes_find_dev(struct mtk_aes_ctx *ctx)
{
	struct mtk_dev *mtk = NULL;
	struct mtk_dev *tmp;

	spin_lock_bh(&mtk_aes.lock);
	if (!ctx->mtk) {
		list_for_each_entry(tmp, &mtk_aes.dev_list, aes_list) {
			mtk = tmp;
			break;
		}
		ctx->mtk = mtk;
	} else {
		mtk = ctx->mtk;
	}
	spin_unlock_bh(&mtk_aes.lock);

	return mtk;
}

static int mtk_aes_crypt(struct ablkcipher_request *req, unsigned int mode)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct mtk_aes_reqctx *rctx = ablkcipher_request_ctx(req);
	struct mtk_dev *mtk;
	int ret;

	if (req->nbytes < NUM_AES_BYPASS) {
		SKCIPHER_REQUEST_ON_STACK(subreq, ctx->fallback);

		skcipher_request_set_tfm(subreq, ctx->fallback);
		skcipher_request_set_callback(subreq, req->base.flags, NULL,
					      NULL);
		skcipher_request_set_crypt(subreq, req->src, req->dst,
					   req->nbytes, req->info);

		if (mode & CRYPTO_MODE_ENC)
			ret = crypto_skcipher_encrypt(subreq);
		else
			ret = crypto_skcipher_decrypt(subreq);

		skcipher_request_zero(subreq);
		return ret;
	}

	mtk = mtk_aes_find_dev(ctx);

	if (!mtk)
		return -ENODEV;

	rctx->mode = mode;

	return mtk_handle_queue(mtk, req);
}

/* ********************** ALG API ************************************ */

static int mtk_aes_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	int ret;

	if (keylen != AES_KEYSIZE_128 &&
	    keylen != AES_KEYSIZE_192 &&
	    keylen != AES_KEYSIZE_256) {
		crypto_ablkcipher_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
		}

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;

	ctx->phy_key = dma_map_single(NULL, (void *)ctx->key, ctx->keylen,
			 DMA_BIDIRECTIONAL);

	dma_unmap_single(NULL, (dma_addr_t)ctx->phy_key, ctx->keylen,
			 DMA_TO_DEVICE);

	crypto_skcipher_clear_flags(ctx->fallback, CRYPTO_TFM_REQ_MASK);
	crypto_skcipher_set_flags(ctx->fallback, tfm->base.crt_flags &
						 CRYPTO_TFM_REQ_MASK);

	ret = crypto_skcipher_setkey(ctx->fallback, key, keylen);

	return 0;
}

static int mtk_aes_ecb_encrypt(struct ablkcipher_request *req)
{
	return mtk_aes_crypt(req, CRYPTO_MODE_ENC);
}

static int mtk_aes_ecb_decrypt(struct ablkcipher_request *req)
{
	return mtk_aes_crypt(req, 0);
}

static int mtk_aes_cbc_encrypt(struct ablkcipher_request *req)
{
	return mtk_aes_crypt(req, CRYPTO_MODE_ENC | CRYPTO_MODE_CBC);
}

static int mtk_aes_cbc_decrypt(struct ablkcipher_request *req)
{
	return mtk_aes_crypt(req, CRYPTO_MODE_CBC);
}

static int mtk_aes_cra_init(struct crypto_tfm *tfm)
{
	const char *name = crypto_tfm_alg_name(tfm);
	const u32 flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK;
	struct mtk_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	struct crypto_skcipher *blk;

	blk = crypto_alloc_skcipher(name, 0, flags);

	if (IS_ERR(blk))
		return PTR_ERR(blk);

	ctx->fallback = blk;

	tfm->crt_ablkcipher.reqsize = sizeof(struct mtk_aes_reqctx);

	return 0;
}

static void mtk_aes_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	if (ctx->fallback)
		crypto_free_skcipher(ctx->fallback);

	ctx->fallback = NULL;
}

/* ********************** ALGS ************************************ */

static struct crypto_alg aes_algs[] = {
{
	.cra_name		= "cbc(aes)",
	.cra_driver_name	= "cbc-aes-mt7628",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK |
				  CRYPTO_ALG_TYPE_ABLKCIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct mtk_aes_ctx),
	.cra_alignmask		= 0xf,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= mtk_aes_cra_init,
	.cra_exit		= mtk_aes_cra_exit,
	.cra_u.ablkcipher = {
		.setkey		= mtk_aes_setkey,
		.encrypt	= mtk_aes_cbc_encrypt,
		.decrypt	= mtk_aes_cbc_decrypt,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		}
},
{
	.cra_name		= "ecb(aes)",
	.cra_driver_name	= "ecb-aes-mt7628",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK |
				  CRYPTO_ALG_TYPE_ABLKCIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct mtk_aes_ctx),
	.cra_alignmask		= 0xf,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= mtk_aes_cra_init,
	.cra_exit		= mtk_aes_cra_exit,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_u.ablkcipher = {
		.setkey		= mtk_aes_setkey,
		.encrypt	= mtk_aes_ecb_encrypt,
		.decrypt	= mtk_aes_ecb_decrypt,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
		}
},
};

int mtk_cipher_alg_register(struct mtk_dev *mtk)
{
	int err, i;

	INIT_LIST_HEAD(&mtk->aes_list);
	spin_lock_init(&mtk->lock);
	spin_lock(&mtk_aes.lock);
	list_add_tail(&mtk->aes_list, &mtk_aes.dev_list);
	spin_unlock(&mtk_aes.lock);

	for (i = 0; i < ARRAY_SIZE(aes_algs); i++) {
		dev_info(mtk->dev, "Register: %s\n", aes_algs[i].cra_name);
		err = crypto_register_alg(&aes_algs[i]);
		if (err)
			goto err_aes_algs;
	}
	return 0;

err_aes_algs:
	for (; i--; )
		crypto_unregister_alg(&aes_algs[i]);

	return err;
}

void mtk_cipher_alg_release(struct mtk_dev *mtk)
{
	int i;

	spin_lock(&mtk_aes.lock);
	list_del(&mtk->aes_list);
	spin_unlock(&mtk_aes.lock);

	for (i = 0; i < ARRAY_SIZE(aes_algs); i++)
		crypto_unregister_alg(&aes_algs[i]);
}

/* Probe using Device Tree; needs helper for loading on earlier DTS firmware */

static int mtk_aes_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mtk_dev *mtk;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	int ret;

	mtk = devm_kzalloc(dev, sizeof(*mtk), GFP_KERNEL);
	if (!mtk)
		return -ENOMEM;

	mtk->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(mtk->base))
		return PTR_ERR(mtk->base);

	mtk->dev = dev;

	aes_engine_reset(); // force reset and clk enable

	dev_info(dev, "HW verson: %02X\n", readl(mtk->base + AES_INFO) >> 28);

	mtk->irq = platform_get_irq(pdev, 0);
	if (mtk->irq < 0) {
		dev_err(dev, "Cannot get IRQ resource\n");
		return mtk->irq;
	}

	ret = devm_request_threaded_irq(mtk->dev, mtk->irq, mtk_aes_irq,
					NULL, IRQF_ONESHOT,
					dev_name(mtk->dev), mtk);

	if (ret) {
		dev_err(mtk->dev, "Cannot grab IRQ\n");
		return ret;
	}
	dev_info(mtk->dev, "IRQ %d assigned to handler", mtk->irq);

	/* Hardcoded Clk at the moment
	mtk->clk = devm_clk_get(dev, "crypto");
			if (IS_ERR(mtk->clk)) {
				mtk->clk = NULL;
				dev_err(dev, "Could not find clock\n");
			}
	*/
	mtk->clk = NULL;

	tasklet_init(&mtk->done_tasklet, mtk_tasklet_req_done,
		     (unsigned long)mtk);

	/* Allocate descriptor rings */

	ret = aes_engine_desc_init(mtk);

	/* Register Ciphers */

	ret = mtk_cipher_alg_register(mtk);

	aes_engine_start(mtk); // Start hw engine

	platform_set_drvdata(pdev, mtk);

	dev_info(dev, "Initialized.\n");

	return 0;
}

static int __exit mtk_aes_remove(struct platform_device *pdev)
{
	struct mtk_dev *mtk = platform_get_drvdata(pdev);

	if (!mtk)
		return -ENODEV;

	tasklet_kill(&mtk->done_tasklet);
	aes_engine_stop(mtk);
	mtk_cipher_alg_release(mtk);
	aes_engine_desc_free(mtk);
	dev_info(mtk->dev, "Unloaded.\n");
	platform_set_drvdata(pdev, NULL);

	return 0;
}

static const struct of_device_id of_crypto_id[] = {
	{ .compatible = "mediatek,mtk-aes" },
	{},
};

MODULE_DEVICE_TABLE(of, of_crypto_id);

static struct platform_driver mt76x8_aes_driver = {
	.probe  = mtk_aes_probe,
	.remove = mtk_aes_remove,
	.driver = {
		.name           = "mtk-aes",
		.of_match_table = of_crypto_id,
	},
};

module_platform_driver(mt76x8_aes_driver);

MODULE_AUTHOR("Richard van Schagen <vschagen@cs.com>");
MODULE_DESCRIPTION("Mediatek AES Crypto hardware driver");
MODULE_LICENSE("GPL");

