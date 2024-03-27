#include "common.h"

static bool sf_ce_need_temp_buffer(struct scatterlist *dst, int nents)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(dst, sg, nents, i) {
		if (!IS_ALIGNED(sg->offset, DMA_RX_ALIGN) || !IS_ALIGNED(sg->length, DMA_RX_ALIGN))
			return true;
	}

	return false;
}

static inline bool sf_ce_rsa_need_fallback(unsigned int keylen)
{
	return keylen != 128 && keylen != 256 && keylen != 512;
}

static enum crypt_algo inline sf_ce_rsa_type(unsigned int len)
{
	switch (len)
	{
	case 128:
		return CE_RSA1024;
	case 256:
		return CE_RSA2048;
	case 512:
		return CE_RSA4096;
	default:
		unreachable();
	}
}

static int sf_ce_rsa_core(struct akcipher_request *req, bool privkey)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct sf_ce_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct sf_ce_dev *priv = ctx->priv;
	struct device *dev = priv->dev;
	struct sf_ce_rsa_reqctx *reqctx = akcipher_request_ctx(req);
	struct sf_ce_chan *ch = &priv->chan[DMA_CH_RSA];	
	struct sf_ce_desc *rx, *tx;
	struct scatterlist *sg;
	enum crypt_algo rsa_type;
	unsigned int cur_rx, cur_tx, buf1len, pl;
	int ret, i, ssg_len, dsg_len;
	reqctx->tmp_buf = NULL;
	reqctx->tmp_buf_phys = 0;

	reqctx->ssg_len = sg_nents_for_len(req->src, req->src_len);
	reqctx->dsg_len = sg_nents_for_len(req->dst, req->dst_len);
	ssg_len = reqctx->ssg_len;
	dsg_len = reqctx->dsg_len;

	if (sf_ce_need_temp_buffer(req->dst, reqctx->dsg_len)) {
		void *tmp_buf;
		gfp_t flags;

		if (unlikely(!dma_map_sg(dev, req->src,
							   reqctx->ssg_len,
							   DMA_TO_DEVICE))) {
			pr_err("dma_map_sg failed, line %d\n", __LINE__);
			return -ENOMEM;
		}

		flags = (req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP) ?
			GFP_KERNEL : GFP_ATOMIC;
		tmp_buf = kmalloc(req->dst_len, flags);
		if (!tmp_buf)
			return -ENOMEM;

		reqctx->tmp_buf = tmp_buf;
		reqctx->tmp_buf_phys = dma_map_single(dev, tmp_buf, req->dst_len, DMA_FROM_DEVICE);
	} else if (req->src == req->dst) {
		if (unlikely(!dma_map_sg(dev, req->src, reqctx->ssg_len,
					 DMA_BIDIRECTIONAL))) {
			pr_err("dma_map_sg failed, line %d\n", __LINE__);
			return -ENOMEM;
		}
	} else {
		if (unlikely(!dma_map_sg(dev, req->src, reqctx->ssg_len,
					 DMA_TO_DEVICE))) {
			pr_err("dma_map_sg failed, line %d\n", __LINE__);
			return -ENOMEM;
		}

		if (unlikely(!dma_map_sg(dev, req->dst, reqctx->dsg_len,
					 DMA_FROM_DEVICE))) {
			pr_err("dma_map_sg failed, line %d\n", __LINE__);
			return -ENOMEM;
		}
	}
	pl = min(req->src_len, 16u);

	rsa_type = sf_ce_rsa_type(ctx->keylen);
	tx = ch->dma_tx;
	cur_tx = ch->cur_tx;
	tx[cur_tx].des0 = ctx->n_phys + sizeof(ctx->n) - ctx->keylen; // buffer1: n
	tx[cur_tx].des1 = ctx->n_phys + sizeof(ctx->n) + (privkey ? sizeof(ctx->e) : 0) + sizeof(ctx->e) - ctx->keylen; // buffer2: e
	tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
		   FIELD_PREP(CE_TDES2_B1L, ctx->keylen) |
		   FIELD_PREP(CE_TDES2_B2L, ctx->keylen) |
		   FIELD_PREP(CE_TDES2_B2T, CE_BUF_RSA_E);
	tx[cur_tx].des3 = CE_TDES3_OWN | CE_TDES3_FD |
		   FIELD_PREP(CE_TDES3_B1T, CE_BUF_RSA_N) |
		   FIELD_PREP(CE_TDES3_CT, rsa_type) |
		   FIELD_PREP(CE_TDES3_PL, pl);
	pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
	pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
	pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
	pr_debug("tdes3: %08X\n", tx[cur_tx].des3);

	cur_tx = (cur_tx + 1) % DMA_RING_SIZE;

	if (unlikely(req->src_len < 16)) {
		/* insert zero padding for len < 16 */
		tx[cur_tx].des0 = priv->zero_pad_phys;
		tx[cur_tx].des1 = 0;
		tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
				  FIELD_PREP(CE_TDES2_B1L, 16 - req->src_len);
		tx[cur_tx].des3 = CE_TDES3_OWN |
				  FIELD_PREP(CE_TDES3_B1T, CE_BUF_PAYLOAD) |
				  FIELD_PREP(CE_TDES3_CT, rsa_type) |
				  FIELD_PREP(CE_TDES3_PL, pl);
		pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
		pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
		pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
		pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
		cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
	}

	for_each_sg(req->src, sg, ssg_len, i) {
		int ld = (i + 1 == ssg_len);
		if (i % 2 == 0) { /* buffer at des0 */
			tx[cur_tx].des0 = cpu_to_le32(sg_dma_address(sg));
			buf1len = sg_dma_len(sg);
			pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
		} else { /* buffer at des1 */
			tx[cur_tx].des1 = cpu_to_le32(sg_dma_address(sg));
			tx[cur_tx].des2 = cpu_to_le32(FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
						      FIELD_PREP(CE_TDES2_B1L, buf1len) |
						      FIELD_PREP(CE_TDES2_B2L, sg_dma_len(sg)) |
						      FIELD_PREP(CE_TDES2_B2T, CE_BUF_PAYLOAD));
			tx[cur_tx].des3 = cpu_to_le32(CE_TDES3_OWN | FIELD_PREP(CE_TDES3_LD, ld) | FIELD_PREP(CE_TDES3_B1T, CE_BUF_PAYLOAD) |
						      FIELD_PREP(CE_TDES3_CT, rsa_type) |
						      FIELD_PREP(CE_TDES3_PL, pl));
			pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
			pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
			pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
			cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
		}
	}

	/* fix up the last descriptor */
	if (i % 2 != 0) {
		tx[cur_tx].des1 = cpu_to_le32(0);
		tx[cur_tx].des2 =
			cpu_to_le32(FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
				    FIELD_PREP(CE_TDES2_B1L, buf1len));
		tx[cur_tx].des3 =
			cpu_to_le32(CE_TDES3_OWN | CE_TDES3_LD |
				    FIELD_PREP(CE_TDES3_B1T, CE_BUF_PAYLOAD) |
				    FIELD_PREP(CE_TDES3_CT, rsa_type) |
				    FIELD_PREP(CE_TDES3_PL, pl));
		pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
		pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
		pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
		cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
	}
	ch->cur_tx = cur_tx;

	rx = ch->dma_rx;
	cur_rx = ch->cur_rx;
	// prepare rx desc

	if (reqctx->tmp_buf_phys) {
		/* one large rx buffer for tmp buffer */
		rx[cur_rx].des0 = reqctx->tmp_buf_phys;
		rx[cur_rx].des1 = 0;
		rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, req->dst_len);
		rx[cur_rx].des3 = CE_RDES3_OWN | CE_RDES3_IOC;
		pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
		pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
		pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
		pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
		/* link this request to the rx descriptor */
		ch->areqs[cur_rx] = &req->base;
		cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
	} else {
		// merge every two buffers into one dma desc list
		for_each_sg (req->dst, sg, reqctx->dsg_len, i) {
			int ld = (i == reqctx->dsg_len - 1);

			if (i % 2 == 0) {
				rx[cur_rx].des0 = sg_dma_address(sg);
				buf1len = sg_dma_len(sg);
				pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
			} else {
				rx[cur_rx].des1 = sg_dma_address(sg);
				rx[cur_rx].des2 =
					FIELD_PREP(CE_RDES2_B1L, buf1len) |
					FIELD_PREP(CE_RDES2_B2L,
						   sg_dma_len(sg));
				rx[cur_rx].des3 = CE_RDES3_OWN |
						  FIELD_PREP(CE_RDES3_IOC, ld);
				if (ld) {
					/* link this request to the rx descriptor */
					ch->areqs[cur_rx] = &req->base;
				}
				pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
				pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
				pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
				cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
			}
		}
		if (i % 2) {
			rx[cur_rx].des1 = 0;
			rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, buf1len);
			rx[cur_rx].des3 = CE_RDES3_OWN | CE_RDES3_IOC;
			/* link this request to the rx descriptor */
			ch->areqs[cur_rx] = &req->base;
			pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
			pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
			pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
			cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
		}
	}

	ch->cur_rx = cur_rx;

	/* inform the DMA for the new data */
	dma_wmb();
	reg_write(priv, CE_DMA_CH_RxDESC_TAIL_LPTR(ch->ch_num), ch->dma_rx_phy + sizeof(struct sf_ce_desc) * cur_rx);
	reg_write(priv, CE_DMA_CH_TxDESC_TAIL_LPTR(ch->ch_num), ch->dma_tx_phy + sizeof(struct sf_ce_desc) * cur_tx);

	return -EINPROGRESS;
}

static int sf_ce_rsa_enc(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct sf_ce_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret;

	if (sf_ce_rsa_need_fallback(ctx->keylen)) {
		akcipher_request_set_tfm(req, ctx->rsa_sw);
		ret = crypto_akcipher_encrypt(req);
		akcipher_request_set_tfm(req, tfm);
		return ret;
	}

	return sf_ce_rsa_core(req, false);
}

static int sf_ce_rsa_dec(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct sf_ce_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret;

	if (sf_ce_rsa_need_fallback(ctx->keylen)) {
		akcipher_request_set_tfm(req, ctx->rsa_sw);
		ret = crypto_akcipher_decrypt(req);
		akcipher_request_set_tfm(req, tfm);
		return ret;
	}

	return sf_ce_rsa_core(req, true);
}

static int
sf_ce_rsa_set_priv_key(struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	struct sf_ce_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct rsa_key rsa_key = {};
	int ret;

	ret = rsa_parse_priv_key(&rsa_key, key, keylen);
	if (ret)
		return ret;

	/* n may contain an extra leading zero */
	ctx->keylen = rsa_key.n_sz & ~1UL;
	if (sf_ce_rsa_need_fallback(ctx->keylen))
		return crypto_akcipher_set_priv_key(ctx->rsa_sw, key, keylen);

	/* n may contain an extra leading zero */
	if (rsa_key.n_sz & 1UL) {
		memset(ctx->n, 0, sizeof(ctx->n) - (rsa_key.n_sz & ~1UL));
		memcpy(ctx->n + sizeof(ctx->n) - (rsa_key.n_sz & ~1UL), rsa_key.n + 1,
		       (rsa_key.n_sz & ~1UL));
	} else {
		memset(ctx->n, 0, sizeof(ctx->n) - rsa_key.n_sz);
		memcpy(ctx->n + sizeof(ctx->n) - rsa_key.n_sz, rsa_key.n,
		       rsa_key.n_sz);
	}
	memset(ctx->e, 0, sizeof(ctx->e) - rsa_key.e_sz);
	memcpy(ctx->e + sizeof(ctx->e) - rsa_key.e_sz, rsa_key.e, rsa_key.e_sz);
	memset(ctx->d, 0, sizeof(ctx->d) - rsa_key.d_sz);
	memcpy(ctx->d + sizeof(ctx->d) - rsa_key.d_sz, rsa_key.d, rsa_key.d_sz);
	dma_sync_single_for_device(ctx->priv->dev, ctx->n_phys, sizeof(ctx->n) + sizeof(ctx->d) + sizeof(ctx->e), DMA_TO_DEVICE);
	memzero_explicit(&rsa_key, sizeof(rsa_key));
	pr_debug("keylen: %u\n", ctx->keylen);
	print_hex_dump(KERN_INFO, "n ", DUMP_PREFIX_OFFSET, 16, 1, ctx->n,
		       sizeof(ctx->n), false);
	print_hex_dump(KERN_INFO, "e ", DUMP_PREFIX_OFFSET, 16, 1, ctx->e,
		       sizeof(ctx->e), false);
	print_hex_dump(KERN_INFO, "d ", DUMP_PREFIX_OFFSET, 16, 1, ctx->d,
		       sizeof(ctx->d), false);
	return 0;
}

static int
sf_ce_rsa_set_pub_key(struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	struct sf_ce_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct rsa_key rsa_key = {};
	int ret;

	ret = rsa_parse_pub_key(&rsa_key, key, keylen);
	if (ret)
		return ret;

	/* n may contain an extra leading zero */
	ctx->keylen = rsa_key.n_sz & ~1UL;
	if (sf_ce_rsa_need_fallback(ctx->keylen))
		return crypto_akcipher_set_priv_key(ctx->rsa_sw, key, keylen);

	/* n may contain an extra leading zero */
	if (rsa_key.n_sz & 1UL) {
		memset(ctx->n, 0, sizeof(ctx->n) - (rsa_key.n_sz & ~1UL));
		memcpy(ctx->n + sizeof(ctx->n) - (rsa_key.n_sz & ~1UL), rsa_key.n + 1,
		       (rsa_key.n_sz & ~1UL));
	} else {
		memset(ctx->n, 0, sizeof(ctx->n) - rsa_key.n_sz);
		memcpy(ctx->n + sizeof(ctx->n) - rsa_key.n_sz, rsa_key.n,
		       rsa_key.n_sz);
	}
	memset(ctx->e, 0, sizeof(ctx->e) - rsa_key.e_sz);
	memcpy(ctx->e + sizeof(ctx->e) - rsa_key.e_sz, rsa_key.e, rsa_key.e_sz);
	dma_sync_single_for_device(ctx->priv->dev, ctx->n_phys, sizeof(ctx->n) + sizeof(ctx->d) + sizeof(ctx->e), DMA_TO_DEVICE);
	memzero_explicit(&rsa_key, sizeof(rsa_key));
	pr_debug("keylen: %u\n", ctx->keylen);
	print_hex_dump(KERN_INFO, "n ", DUMP_PREFIX_OFFSET, 16, 1, ctx->n,
		       sizeof(ctx->n), false);
	print_hex_dump(KERN_INFO, "e ", DUMP_PREFIX_OFFSET, 16, 1, ctx->e,
		       sizeof(ctx->e), false);
	return 0;
}

static unsigned int sf_ce_rsa_max_size(struct crypto_akcipher *tfm)
{
	struct sf_ce_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);

	if (sf_ce_rsa_need_fallback(ctx->keylen))
		return crypto_akcipher_maxsize(ctx->rsa_sw);

	return ctx->keylen;
}

static int sf_ce_rsa_init_tfm(struct crypto_akcipher *tfm)
{
	struct sf_ce_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct device *dev;
	int ret;

	ctx->rsa_sw = crypto_alloc_akcipher("rsa-generic", 0, 0);
	if (IS_ERR(ctx->rsa_sw))
		return PTR_ERR(ctx->rsa_sw);

	ctx->priv = g_dev;
	dev = ctx->priv->dev;
	ctx->n_phys = dma_map_single_attrs(dev, ctx->n, sizeof(ctx->n) + sizeof(ctx->d) + sizeof(ctx->e), DMA_TO_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);

	ret = dma_mapping_error(dev, ctx->n_phys);
	if (ret)
		crypto_free_akcipher(ctx->rsa_sw);

	return ret;
}

static void sf_ce_rsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct sf_ce_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct device *dev = ctx->priv->dev;

	crypto_free_akcipher(ctx->rsa_sw);
	dma_unmap_single_attrs(dev, ctx->n_phys, sizeof(ctx->n) + sizeof(ctx->d) + sizeof(ctx->e), DMA_TO_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
	memzero_explicit(ctx, sizeof(*ctx));
}

struct akcipher_alg sf_ce_rsa __read_mostly = {
	.encrypt = sf_ce_rsa_enc,
	.decrypt = sf_ce_rsa_dec,
	.set_priv_key = sf_ce_rsa_set_priv_key,
	.set_pub_key = sf_ce_rsa_set_pub_key,
	.max_size = sf_ce_rsa_max_size,
	.init = sf_ce_rsa_init_tfm,
	.exit = sf_ce_rsa_exit_tfm,
	.reqsize = sizeof(struct sf_ce_rsa_reqctx),
	.base = {
		.cra_name		= "rsa",
		.cra_driver_name	= "siflower-ce-rsa",
		.cra_priority		= 300,
		.cra_ctxsize		= sizeof(struct sf_ce_rsa_ctx),
		.cra_flags		= CRYPTO_ALG_ASYNC |
					  CRYPTO_ALG_NEED_FALLBACK |
					  CRYPTO_ALG_KERN_DRIVER_ONLY,
		.cra_module		= THIS_MODULE,
	}
};
