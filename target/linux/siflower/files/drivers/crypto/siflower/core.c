#define pr_fmt(fmt)	"siflower-ce: " fmt

#include "common.h"
#include "aes.h"
#include "rsa.h"
#include "hash.h"

struct sf_ce_dev *g_dev;

static void
sf_ce_irq_bh(unsigned long data)
{
	struct sf_ce_chan *ch = (struct sf_ce_chan *)data;
	struct sf_ce_dev *priv = container_of(ch, struct sf_ce_dev, chan[ch->ch_num]);
	struct device *dev = priv->dev;
	unsigned int i;

	for (i = ch->dirty_rx; i != READ_ONCE(ch->cur_rx); i = (i + 1) % DMA_RING_SIZE) {
		struct crypto_async_request *areq;
		enum crypt_algo alg;
		int ret = 0;
		u32 rdes3;

		// TODO: load pipelining, or read DMA current rx register instead
		rdes3 = le32_to_cpu(READ_ONCE(ch->dma_rx[i].des3));
		if (unlikely(rdes3 & CE_RDES3_OWN))
			break;

		areq = ch->areqs[i];
		if (unlikely(!areq))
			continue;

		ch->areqs[i] = NULL;
		if (WARN(!(rdes3 & CE_RDES3_WB_LD),
			 "expected RX last descriptor but it's not!\n")) {
			ret = -EBADMSG;
			goto areq_complete;
		}

		alg = FIELD_GET(CE_RDES3_WB_CT, rdes3);
		switch (alg)
		{
		case CE_MD5:
		case CE_SHA1:
		case CE_SHA256: {
			/* rx handler for md5/sha1/sha256/sha224 */
			struct ahash_request *req;
			struct sf_ce_ahash_reqctx *reqctx;
			unsigned int new_partial_offset;
			unsigned int digest_size;

			req = ahash_request_cast(areq);
			reqctx = ahash_request_ctx(req);
			digest_size = crypto_ahash_digestsize(crypto_ahash_reqtfm(req));

			dma_unmap_sg(dev, req->src, reqctx->nents,
				     DMA_TO_DEVICE);

			if (reqctx->final) {
				dma_unmap_single(dev, reqctx->hash_phys,
						 sizeof(reqctx->hash),
						 DMA_BIDIRECTIONAL);
				dma_unmap_single(dev, reqctx->block_phys,
						 sizeof(reqctx->block),
						 DMA_TO_DEVICE);

				/* sha1 special case for its dma offset */
				if (alg == CE_SHA1)
					memcpy(req->result,
					       reqctx->hash + SHA1_DMA_OFFSET,
					       digest_size);
				else
					memcpy(req->result, reqctx->hash,
					       digest_size);
			} else {
				reqctx->length += req->nbytes;
				/* new_partial_offset: new partial data offset after update */
				new_partial_offset = reqctx->length & 0x3f;
				scatterwalk_map_and_copy(
					reqctx->block, req->src,
					req->nbytes - new_partial_offset,
					new_partial_offset, 0);
			}
			break;
		}
		case CE_SHA512: {
			/* rx handler for sha512/sha384 */
			struct ahash_request *req;
			struct sf_ce_ahash512_reqctx *reqctx;
			unsigned int new_partial_offset;
			unsigned int digest_size;

			req = ahash_request_cast(areq);
			reqctx = ahash_request_ctx(req);
			digest_size = crypto_ahash_digestsize(crypto_ahash_reqtfm(req));

			dma_unmap_sg(dev, req->src, reqctx->nents,
				     DMA_TO_DEVICE);

			if (reqctx->final) {
				dma_unmap_single(dev, reqctx->hash_phys,
						 sizeof(reqctx->hash),
						 DMA_BIDIRECTIONAL);
				dma_unmap_single(dev, reqctx->block_phys,
						 sizeof(reqctx->block),
						 DMA_TO_DEVICE);
				memcpy(req->result, reqctx->hash, digest_size);
			} else {
				reqctx->length += req->nbytes;
				/* new_partial_offset: new partial data offset after update */
				new_partial_offset = reqctx->length & 0x7f;
				scatterwalk_map_and_copy(
					reqctx->block, req->src,
					req->nbytes - new_partial_offset,
					new_partial_offset, 0);
			}
			break;
		}
		case CE_AES_CTR: {
			struct skcipher_request *req;
			struct sf_ce_aes_reqctx *reqctx;
			struct sf_ce_aes_ctx *ctx;

			req = skcipher_request_cast(areq);
			reqctx = skcipher_request_ctx(req);
			ctx = crypto_tfm_ctx(req->base.tfm);

			if (reqctx->tmp_buf) {
				dma_unmap_single(dev, reqctx->tmp_buf_phys, req->cryptlen, DMA_FROM_DEVICE);
				scatterwalk_map_and_copy(reqctx->tmp_buf, req->dst, 0, req->cryptlen, 1);
				kfree(reqctx->tmp_buf);
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_TO_DEVICE);
			} else if (req->src == req->dst) {
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_BIDIRECTIONAL);
			} else {
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_TO_DEVICE);
				dma_unmap_sg(dev, req->dst, reqctx->dsg_len, DMA_FROM_DEVICE);
			}
			dma_unmap_single(dev, reqctx->iv_phys, AES_BLOCK_SIZE, DMA_TO_DEVICE);

			/* increase iv by blocks */
			{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && defined(CONFIG_CC_HAS_INT128)
				__uint128_t iv128;

				iv128 = *(__uint128_t *)req->iv;
				iv128 = bswap128(iv128);
				iv128 += DIV_ROUND_UP(req->cryptlen, AES_BLOCK_SIZE);
				iv128 = bswap128(iv128);
				*(__uint128_t *)req->iv = iv128;
#else
				crypto_inc(req->iv,
					   DIV_ROUND_UP(req->cryptlen, AES_BLOCK_SIZE));
#endif
			}

#if 0
			if (unlikely(reqctx->misalign_count)) {
				struct scatterlist *sg;
				int misalign_count;
				int i;

				dma_unmap_single(dev, reqctx->misal_phys, sizeof(reqctx->misalign_buffer), DMA_FROM_DEVICE);

				for_each_sg(req->dst, sg, reqctx->dsg_len, i) {
					dma_addr_t buf_phys, buf_phys_align_start, buf_phys_align_end;
					unsigned int buf_len;
					unsigned long start_offset, end_offset;
					void *buf;

					buf = sg_virt(sg);
					buf_phys = sg_dma_address(sg);
					buf_len =  sg_dma_len(sg);
					buf_phys_align_start = ALIGN(buf_phys, DMA_RX_ALIGN);
					buf_phys_align_end = ALIGN_DOWN(buf_phys + buf_len, DMA_RX_ALIGN);

					start_offset = buf_phys_align_start - buf_phys;
					end_offset = buf_phys + buf_len - buf_phys_align_end;

					if (likely(buf_phys_align_start < buf_phys_align_end)) {
						if (start_offset) {
							/* handle start address misalignment */
							memcpy(buf, reqctx->misalign_buffer[misalign_count] + DMA_RX_ALIGN - start_offset, start_offset);
							misalign_count++;
						}
					}

					if (end_offset) {
						/* handle end address misalignment */
						memcpy(buf + buf_len - end_offset, reqctx->misalign_buffer[misalign_count] + DMA_RX_ALIGN - end_offset, end_offset);
						misalign_count++;
					}
				}
				print_hex_dump(
					KERN_INFO,
					"misalign_buffer: ", DUMP_PREFIX_OFFSET,
					16, 1, reqctx->misalign_buffer,
					sizeof(reqctx->misalign_buffer), false);
			}
#endif
			break;
		}
		case CE_AES_GCM: {
			struct aead_request *req = aead_request_cast(areq);
			struct sf_ce_aes_gcm_reqctx *reqctx = aead_request_ctx(req);
			struct sf_ce_aes_gcm_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
			bool is_decrypt = rdes3 & CE_RDES3_WB_CM;
			ret = (rdes3 & CE_RDES3_WB_AEAD_VERIFY) ? 0 : -EBADMSG;
			unsigned int nbytes = is_decrypt ? req->cryptlen : req->cryptlen + ctx->taglen;

			if (reqctx->tmp_buf) {
				dma_unmap_single(dev, reqctx->tmp_buf_phys, nbytes, DMA_FROM_DEVICE);
				scatterwalk_map_and_copy(reqctx->tmp_buf,
							 req->dst, 0, nbytes,
							 1);
				kfree(reqctx->tmp_buf);
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_TO_DEVICE);
			} else if (req->src == req->dst) {
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_BIDIRECTIONAL);
			} else {
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_TO_DEVICE);
				dma_unmap_sg(dev, req->dst, reqctx->dsg_len, DMA_FROM_DEVICE);
			}
			dma_unmap_single(dev, reqctx->iv_extra_phys,
					 sizeof(reqctx->iv) +
						 sizeof(reqctx->alen_dma) +
						 sizeof(reqctx->plen_dma) +
						 sizeof(reqctx->tag),
					 DMA_TO_DEVICE);

#if 0
			if (unlikely(reqctx->misalign_count)) {
				struct scatterlist *sg;
				int misalign_count;
				int i;

				dma_unmap_single(dev, reqctx->misal_phys, sizeof(reqctx->misalign_buffer), DMA_FROM_DEVICE);

				for_each_sg(req->dst, sg, reqctx->dsg_len, i) {
					dma_addr_t buf_phys, buf_phys_align_start, buf_phys_align_end;
					unsigned int buf_len;
					unsigned long start_offset, end_offset;
					void *buf;

					buf = sg_virt(sg);
					buf_phys = sg_dma_address(sg);
					buf_len =  sg_dma_len(sg);
					buf_phys_align_start = ALIGN(buf_phys, DMA_RX_ALIGN);
					buf_phys_align_end = ALIGN_DOWN(buf_phys + buf_len, DMA_RX_ALIGN);

					start_offset = buf_phys_align_start - buf_phys;
					end_offset = buf_phys + buf_len - buf_phys_align_end;

					if (likely(buf_phys_align_start < buf_phys_align_end)) {
						if (start_offset) {
							/* handle start address misalignment */
							memcpy(buf, reqctx->misalign_buffer[misalign_count] + DMA_RX_ALIGN - start_offset, start_offset);
							misalign_count++;
						}
					}

					if (end_offset) {
						/* handle end address misalignment */
						memcpy(buf + buf_len - end_offset, reqctx->misalign_buffer[misalign_count] + DMA_RX_ALIGN - end_offset, end_offset);
						misalign_count++;
					}
				}
				print_hex_dump(
					KERN_INFO,
					"misalign_buffer: ", DUMP_PREFIX_OFFSET,
					16, 1, reqctx->misalign_buffer,
					sizeof(reqctx->misalign_buffer), false);
			}
#endif
			break;
		}
		case CE_AES_CCM: {
			struct aead_request *req = aead_request_cast(areq);
			struct sf_ce_aes_ccm_reqctx *reqctx = aead_request_ctx(req);
			struct sf_ce_aes_ccm_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
			bool is_decrypt = rdes3 & CE_RDES3_WB_CM;
			ret = (rdes3 & CE_RDES3_WB_AEAD_VERIFY) ? 0 : -EBADMSG;
			unsigned int nbytes = is_decrypt ? req->cryptlen : req->cryptlen + ctx->taglen;

			if (reqctx->tmp_buf) {
				dma_unmap_single(dev, reqctx->tmp_buf_phys, nbytes, DMA_FROM_DEVICE);
				scatterwalk_map_and_copy(reqctx->tmp_buf,
							 req->dst, 0, nbytes,
							 1);
				kfree(reqctx->tmp_buf);
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_TO_DEVICE);
			} else if (req->src == req->dst) {
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_BIDIRECTIONAL);
			} else {
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_TO_DEVICE);
				dma_unmap_sg(dev, req->dst, reqctx->dsg_len, DMA_FROM_DEVICE);
			}
			dma_unmap_single(dev, reqctx->iv_extra_phys,
					 sizeof(reqctx->iv) +
						 sizeof(reqctx->b0) +
						 sizeof(reqctx->alen_dma) + sizeof(reqctx->tag),
					 DMA_TO_DEVICE);

#if 0
			if (unlikely(reqctx->misalign_count)) {
				struct scatterlist *sg;
				int misalign_count;
				int i;

				dma_unmap_single(dev, reqctx->misal_phys, sizeof(reqctx->misalign_buffer), DMA_FROM_DEVICE);

				for_each_sg(req->dst, sg, reqctx->dsg_len, i) {
					dma_addr_t buf_phys, buf_phys_align_start, buf_phys_align_end;
					unsigned int buf_len;
					unsigned long start_offset, end_offset;
					void *buf;

					buf = sg_virt(sg);
					buf_phys = sg_dma_address(sg);
					buf_len =  sg_dma_len(sg);
					buf_phys_align_start = ALIGN(buf_phys, DMA_RX_ALIGN);
					buf_phys_align_end = ALIGN_DOWN(buf_phys + buf_len, DMA_RX_ALIGN);

					start_offset = buf_phys_align_start - buf_phys;
					end_offset = buf_phys + buf_len - buf_phys_align_end;

					if (likely(buf_phys_align_start < buf_phys_align_end)) {
						if (start_offset) {
							/* handle start address misalignment */
							memcpy(buf, reqctx->misalign_buffer[misalign_count] + DMA_RX_ALIGN - start_offset, start_offset);
							misalign_count++;
						}
					}

					if (end_offset) {
						/* handle end address misalignment */
						memcpy(buf + buf_len - end_offset, reqctx->misalign_buffer[misalign_count] + DMA_RX_ALIGN - end_offset, end_offset);
						misalign_count++;
					}
				}
				print_hex_dump(
					KERN_INFO,
					"misalign_buffer: ", DUMP_PREFIX_OFFSET,
					16, 1, reqctx->misalign_buffer,
					sizeof(reqctx->misalign_buffer), false);
			}
#endif
			break;
		}
		case CE_RSA1024:
		case CE_RSA2048:
		case CE_RSA4096: {
			struct crypto_akcipher *tfm;
			struct akcipher_request *req;
			struct sf_ce_rsa_reqctx *reqctx;
			struct sf_ce_rsa_ctx *ctx;

			req = container_of(areq, struct akcipher_request, base);
			tfm = crypto_akcipher_reqtfm(req);
			reqctx = akcipher_request_ctx(req);
			ctx = akcipher_tfm_ctx(tfm);

			if (reqctx->tmp_buf) {
				dma_unmap_single(dev, reqctx->tmp_buf_phys, req->dst_len, DMA_FROM_DEVICE);
				scatterwalk_map_and_copy(reqctx->tmp_buf,
							 req->dst, 0, req->dst_len,
							 1);
				kfree(reqctx->tmp_buf);
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_TO_DEVICE);
			} else if (req->src == req->dst) {
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_BIDIRECTIONAL);
			} else {
				dma_unmap_sg(dev, req->src, reqctx->ssg_len, DMA_TO_DEVICE);
				dma_unmap_sg(dev, req->dst, reqctx->dsg_len, DMA_FROM_DEVICE);
			}

			break;
		}
		default:
			break;
		}
areq_complete:
		crypto_request_complete(areq, ret);
	}
	ch->dirty_rx = i;

	reg_write(priv, CE_DMA_CH_INT_EN(ch->ch_num), CE_DMA_INT_DEFAULT_EN);
}

static irqreturn_t
sf_ce_rx_irq(int irq, void *dev_id)
{
	struct sf_ce_chan *ch = dev_id;
	struct sf_ce_dev *priv = container_of(ch, struct sf_ce_dev, chan[ch->ch_num]);
	u32 status;

	status = reg_read(priv, CE_DMA_CH_STATUS(ch->ch_num));
	pr_debug("ch %u interrupt status: %#x\n", ch->ch_num, status);
	if (unlikely(!(status & CE_RI)))
		return IRQ_NONE;

	reg_write(priv, CE_DMA_CH_STATUS(ch->ch_num), CE_RI | CE_RBU);

	reg_write(priv, CE_DMA_CH_INT_EN(ch->ch_num), 0);
	tasklet_schedule(&ch->bh);

	return IRQ_HANDLED;
}

#if 0
static irqreturn_t
sf_ce_tx_irq(int irq, void *dev_id)
{
	struct sf_ce_chan *ch = dev_id;
	struct sf_ce_dev *priv = container_of(ch, struct sf_ce_dev, chan[ch->ch_num]);
	struct crypto_async_request *areq = ch->engine->cur_req;

	reg_write(priv, CE_DMA_CH_STATUS(ch->ch_num), CE_DMA_INT_DEFAULT_TX);

	switch (ch->ch_num) {
	case DMA_CH_SHA: {
		struct ahash_request *req = ahash_request_cast(areq);
		struct sf_ce_ahash_reqctx *reqctx = ahash_request_ctx(req);

		dma_unmap_sg(priv->dev, req->src, sg_nents(req->src),
			     DMA_TO_DEVICE);
		dma_unmap_single(priv->dev, dma_unmap_addr(reqctx, pad_phys),
				 dma_unmap_addr(reqctx, pad_len),
				 DMA_TO_DEVICE);
		break;
	}
	case DMA_CH_AES: {
		struct skcipher_request *req = skcipher_request_cast(areq);
		struct sf_ce_aes_reqctx *reqctx = skcipher_request_ctx(req);

		dma_unmap_sg(priv->dev, req->src, reqctx->ssg_len,
			     DMA_TO_DEVICE);
		break;
	}
	}

	pr_debug("TX irq done\n");
	return IRQ_HANDLED;
}
#endif

static irqreturn_t
sf_ce_misc_irq(int irq, void *dev_id)
{
	// TBD
	pr_debug("in misc irq done\n");
	return IRQ_HANDLED;
}

static int
sf_ce_dma_sw_reset(struct sf_ce_dev *priv)
{
	unsigned long timeout = jiffies + HZ;

	reg_write(priv, CE_DMA_MODE, CE_SWR);
	do {
		if (!(reg_read(priv, CE_DMA_MODE) & CE_SWR))
			return 0;

		cond_resched();
	} while (time_after(timeout, jiffies));

	dev_err(priv->dev, "DMA reset timed out\n");
	return -ETIMEDOUT;
}

static int
sf_ce_hw_init(struct sf_ce_dev *priv)
{
	int ret;
	int i;

#if 0
	ret = sf_ce_dma_sw_reset(priv);
	if (ret)
		return ret;
#endif

	/* DMA Configuration */
	reg_write(priv, CE_US_ENDIAN_CFG, FIELD_PREP(CE_US_ENDIAN_CFG_0, CE_ENDIAN_BIG));

	reg_write(priv, CE_DMA_SYSBUS_MODE, FIELD_PREP(CE_WR_OSR_LMT, 1) | FIELD_PREP(CE_RD_OSR_LMT, 1) | CE_BLEN8 | CE_BLEN4);
	reg_write(priv, CE_TX_EDMA_CTRL, CE_TEDM);
	reg_write(priv, CE_RX_EDMA_CTRL, CE_REDM);

	for (i = 0; i < DMA_CH_NUM; i++) {		
		reg_rmw(priv, CE_DMA_CH_RX_CONTROL(i), CE_RxPBL | CE_RBSZ,
			FIELD_PREP(CE_RxPBL, 8));
		reg_rmw(priv, CE_DMA_CH_TX_CONTROL(i), CE_TxPBL,
			FIELD_PREP(CE_TxPBL, 8));
	}

	return 0;
}

static int
sf_ce_desc_init(struct sf_ce_dev *priv)
{
	int i;

	for (i = 0; i < DMA_CH_NUM; i++) {
		struct sf_ce_chan *ch = &priv->chan[i];
		ch->dma_rx =
			dmam_alloc_coherent(priv->dev,
					    sizeof(*ch->dma_rx) * DMA_RING_SIZE,
					    &ch->dma_rx_phy, GFP_KERNEL);
		if (!ch->dma_rx)
			return -ENOMEM;

		ch->dma_tx =
			dmam_alloc_coherent(priv->dev,
					    sizeof(*ch->dma_tx) * DMA_RING_SIZE,
					    &ch->dma_tx_phy, GFP_KERNEL);
		if (!ch->dma_tx)
			return -ENOMEM;

		ch->areqs = devm_kcalloc(priv->dev, DMA_RING_SIZE, sizeof(*ch->areqs), GFP_KERNEL);
		if (!ch->areqs)
			return -ENOMEM;

		reg_write(priv, CE_DMA_CH_RxDESC_LADDR(i), ch->dma_rx_phy);
		reg_write(priv, CE_DMA_CH_RxDESC_TAIL_LPTR(i),
			  ch->dma_rx_phy + sizeof(*ch->dma_rx) * DMA_RING_SIZE);
		reg_write(priv, CE_DMA_CH_RxDESC_RING_LEN(i),
			  DMA_RING_SIZE - 1);
		reg_write(priv, CE_DMA_CH_TxDESC_LADDR(i), ch->dma_tx_phy);
		reg_write(priv, CE_DMA_CH_TxDESC_TAIL_LPTR(i),
			  ch->dma_tx_phy + sizeof(*ch->dma_tx) * DMA_RING_SIZE);
		reg_write(priv, CE_DMA_CH_TxDESC_RING_LEN(i),
			  DMA_RING_SIZE - 1);

		dev_info(
			priv->dev,
			"TX ptr: %px, TX phy: %pad, RX ptr: %px, RX phy: %pad\n",
			ch->dma_tx, &ch->dma_tx_phy, ch->dma_rx,
			&ch->dma_rx_phy);
	}
	return 0;
}

static void
sf_ce_start(struct sf_ce_dev *priv)
{
	int i;

	for (i = 0; i < DMA_CH_NUM; i++) {
		reg_set(priv, CE_DMA_CH_RX_CONTROL(i), CE_RXST);
		reg_set(priv, CE_DMA_CH_TX_CONTROL(i), CE_TXST);
		reg_write(priv, CE_DMA_CH_INT_EN(i), CE_DMA_INT_DEFAULT_EN);
	}
}

static void
sf_ce_stop(struct sf_ce_dev *priv)
{
	int i;

	for (i = 0; i < DMA_CH_NUM; i++) {
		reg_write(priv, CE_DMA_CH_INT_EN(i), 0);
		reg_clear(priv, CE_DMA_CH_TX_CONTROL(i), CE_TXST);
		reg_clear(priv, CE_DMA_CH_RX_CONTROL(i), CE_RXST);
	}
}


static int
sf_ce_probe(struct platform_device *pdev)
{
	struct sf_ce_dev *priv;
	int i, ret, index = 0;

	pr_debug("%d\n", __LINE__);
	if (g_dev)
		return -EEXIST;

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	pr_debug("%d\n", __LINE__);
	priv->dev = &pdev->dev;
	priv->zero_pad_phys = dma_map_single(priv->dev, priv->zero_pad, sizeof(priv->zero_pad), DMA_TO_DEVICE);
	for (i = 0; i < DMA_CH_NUM; i++) {
		priv->chan[i].ch_num = i;
		tasklet_init(&priv->chan[i].bh, sf_ce_irq_bh, (unsigned long)&priv->chan[i]);
	}

	pr_debug("%d\n", __LINE__);
	platform_set_drvdata(pdev, priv);
	g_dev = priv;
	priv->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->base))
		return PTR_ERR(priv->base);

	pr_debug("%d\n", __LINE__);
	priv->csr_clk = devm_clk_get(&pdev->dev, "csr");
	if (IS_ERR(priv->csr_clk))
		return PTR_ERR(priv->csr_clk);

	pr_debug("%d\n", __LINE__);
	priv->app_clk = devm_clk_get(&pdev->dev, "app");
	if (IS_ERR(priv->app_clk))
		return PTR_ERR(priv->app_clk);
#if 0
	// TX IRQ
	for (i = 0; i < DMA_CH_NUM; i++, index++) {
		int irq = platform_get_irq(pdev, index);
		if (irq < 0)
			return irq;

		ret = devm_request_threaded_irq(&pdev->dev, irq, NULL,
						sf_ce_tx_irq, IRQF_ONESHOT,
						sf_ce_names[i], &priv->chan[i]);
		if (ret)
			return ret;

		irq_set_affinity_hint(irq, cpumask_of(cpumask_local_spread(i, NUMA_NO_NODE)));
		priv->chan[i].tx_irq = irq;
	}
#else
	index = 4;
#endif
	// RX IRQ
	for (i = 0; i < DMA_CH_NUM; i++, index++) {
		int irq = platform_get_irq(pdev, index);
		if (irq < 0)
			return irq;

		ret = devm_request_irq(&pdev->dev, irq, sf_ce_rx_irq, 0,
				       sf_ce_names[i], &priv->chan[i]);
		if (ret)
			return ret;

		irq_set_affinity_hint(irq, cpumask_of(cpumask_local_spread(i, NUMA_NO_NODE)));
		priv->chan[i].rx_irq = irq;
	}

	pr_debug("%d\n", __LINE__);
#if 0
	// Misc IRQ
	ret = platform_get_irq(pdev, index);
	if (ret < 0)
		return ret;

	pr_debug("%d\n", __LINE__);
	ret = devm_request_irq(&pdev->dev, ret, sf_ce_misc_irq, 0,
			       "sf-ce-misc", priv);
	if (ret)
		return ret;

#endif
	pr_debug("%d\n", __LINE__);
	ret = clk_prepare_enable(priv->csr_clk);
	if (ret)
		return ret;

	pr_debug("%d\n", __LINE__);
	ret = clk_prepare_enable(priv->app_clk);
	if (ret)
		goto err_app_clk;

	priv->topsys = syscon_regmap_lookup_by_phandle(pdev->dev.of_node, "topsys");
	if (IS_ERR(priv->topsys)) {
		ret = PTR_ERR(priv->topsys);
		goto err_app_clk;
	}
	regmap_set_bits(priv->topsys, 0xc0, BIT(28) | BIT(29));

	pr_debug("%d\n", __LINE__);
	ret = sf_ce_hw_init(priv);
	if (ret)
		goto err_app_clk;

	pr_debug("%d\n", __LINE__);
	ret = sf_ce_desc_init(priv);
	if (ret)
		goto err_app_clk;

	pr_debug("%d\n", __LINE__);
	sf_ce_start(priv);

#ifdef CONFIG_CRYPTO_DEV_SIFLOWER_AES
	ret = crypto_register_skcipher(&sf_ce_aes_ctr);
	if (ret) {
		dev_err(&pdev->dev, "cannot register aes-ctr: %d\n", ret);
	}
	ret = crypto_register_aead(&sf_ce_aes_gcm);
	if (ret) {
		dev_err(&pdev->dev, "cannot register aes-gcm: %d\n", ret);
	}
	ret = crypto_register_aead(&sf_ce_aes_ccm);
	if (ret) {
		dev_err(&pdev->dev, "cannot register aes-ccm: %d\n", ret);
	}
#endif

#ifdef CONFIG_CRYPTO_DEV_SIFLOWER_RSA
	ret = crypto_register_akcipher(&sf_ce_rsa);
	if (ret) {
		dev_err(&pdev->dev, "cannot register akcipher: %d\n", ret);
	}
#endif

#ifdef CONFIG_CRYPTO_DEV_SIFLOWER_SHA
	ret = crypto_register_ahash(&sf_ce_sha1);
	if (ret) {
		dev_err(&pdev->dev, "cannot register sha1: %d\n", ret);
	}
	ret = crypto_register_ahash(&sf_ce_sha256);
	if (ret) {
		dev_err(&pdev->dev, "cannot register sha256: %d\n", ret);
	}
	ret = crypto_register_ahash(&sf_ce_sha224);
	if (ret) {
		dev_err(&pdev->dev, "cannot register sha224: %d\n", ret);
	}
	ret = crypto_register_ahash(&sf_ce_sha512);
	if (ret) {
		dev_err(&pdev->dev, "cannot register sha512: %d\n", ret);
	}
	ret = crypto_register_ahash(&sf_ce_sha384);
	if (ret) {
		dev_err(&pdev->dev, "cannot register sha384: %d\n", ret);
	}
#endif

#ifdef CONFIG_CRYPTO_DEV_SIFLOWER_MD5
	ret = crypto_register_ahash(&sf_ce_md5);
	if (ret) {
		dev_err(&pdev->dev, "cannot register md5: %d\n", ret);
	}
#endif

	return 0;
err_register_hash:
#if 0
	crypto_unregister_aeads(sf_ce_aeads, ARRAY_SIZE(sf_ce_aeads));
#endif
err_register_aead:
	i = DMA_CH_NUM - 1;
err_app_clk:
	clk_disable_unprepare(priv->app_clk);
	return ret;
}

static int
sf_ce_remove(struct platform_device *pdev)
{
	struct sf_ce_dev *priv;
	int i;

	priv = platform_get_drvdata(pdev);
	WARN_ON(priv != g_dev);

//	crypto_unregister_ahashes(sf_ce_hashes, ARRAY_SIZE(sf_ce_hashes));

	sf_ce_stop(priv);

	for (i = 0; i < DMA_CH_NUM; i++) {
		tasklet_kill(&priv->chan[i].bh);
		irq_set_affinity_hint(priv->chan[i].tx_irq, NULL);
		irq_set_affinity_hint(priv->chan[i].rx_irq, NULL);
//		crypto_engine_exit(priv->chan[i].engine);
	}

	dma_unmap_single(priv->dev, priv->zero_pad_phys, sizeof(priv->zero_pad), DMA_TO_DEVICE);
#if 0
	crypto_unregister_skcipher(&sf_ce_aes_ctr);
	crypto_unregister_aeads(sf_ce_aeads, ARRAY_SIZE(sf_ce_aeads));
#endif
	clk_disable_unprepare(priv->app_clk);
	clk_disable_unprepare(priv->csr_clk);
	g_dev = NULL;

	regmap_clear_bits(priv->topsys, 0xc0, BIT(28) | BIT(29));
	return 0;
}

static const struct of_device_id sf_ce_match[] = {
	{ .compatible = "siflower,sf21a6826p-crypto", },
	{},
};
MODULE_DEVICE_TABLE(of, sf_ce_match);

static struct platform_driver sf_ce_driver = {
	.driver = {
		.name		= "siflower_ce",
		.of_match_table	= of_match_ptr(sf_ce_match),
	},
	.probe = sf_ce_probe,
	.remove = sf_ce_remove,
};
module_platform_driver(sf_ce_driver);

MODULE_LICENSE("GPL");
