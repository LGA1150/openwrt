#include "common.h"

/***
 * Buffer alignment requirements:
 *
 * Tx:
 * No address alignment for Tx buffers. But some buffer type requires a total
 * length of multiple of 8 or 16 bytes.
 *
 * Rx:
 * Both Start Address and End Address (Start Address + length) must be 8-byte
 * aligned.
 */

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

/**
 * sf_ce_sg_nents_for_len - return total count of entries in scatterlist
 *                    needed to satisfy the supplied length
 * @sg:		The scatterlist
 * @len:	The total required length
 * @extra:	The extra bytes at the last entry
 *
 * Description:
 * Determines the number of entries in sg that are required to meet
 * the supplied length, taking into acount chaining as well
 *
 * Returns:
 *   the number of sg entries needed, negative error on failure
 *
 **/
static int sf_ce_sg_nents_for_len(struct scatterlist *sg, u64 len, unsigned int *extra)
{
	int nents;
	u64 total;

	if (!len)
		return 0;

	for (nents = 0, total = 0; sg; sg = sg_next(sg)) {
		nents++;
		total += sg->length;
		if (total >= len) {
			*extra = total - len;
			return nents;
		}
	}

	return -EINVAL;
}

static int
sf_ce_aes_ctr_op(struct skcipher_request *req, bool is_decrypt)
{
	struct sf_ce_aes_reqctx *reqctx = skcipher_request_ctx(req);
	struct sf_ce_aes_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct sf_ce_dev *priv = ctx->priv;
	struct device *dev = priv->dev;
	struct sf_ce_chan *ch = &priv->chan[DMA_CH_AES];
	dma_addr_t iv_phys;
	int ret;
	struct sf_ce_desc *rx, *tx;
	unsigned int cur_tx, cur_rx;
	struct scatterlist *sg;
	unsigned int i, nbytes, buf1len;

	reqctx->tmp_buf = NULL;
	reqctx->tmp_buf_phys = 0;
//	reqctx->misalign_count = 0;
//	memset(reqctx->misalign_buffer, 0xcc, sizeof(reqctx->misalign_buffer));
	/* req->iv may not be physically contiguous, so copy it to reqctx,
	 * which is contiguous and can be used for DMA.
	 */
	memcpy(reqctx->iv, req->iv, AES_BLOCK_SIZE);
	reqctx->ssg_len = sg_nents(req->src);
	reqctx->dsg_len = sg_nents(req->dst);
	if (sf_ce_need_temp_buffer(req->dst, reqctx->dsg_len)) {
		void *tmp_buf;
		gfp_t flags;

		if (unlikely(!dma_map_sg(dev, req->src, reqctx->ssg_len,
					 DMA_TO_DEVICE)))
			return -ENOMEM;

		flags = (req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP) ?
			GFP_KERNEL : GFP_ATOMIC;
		tmp_buf = kmalloc(ALIGN(req->cryptlen, AES_BLOCK_SIZE), flags);
		if (unlikely(!tmp_buf))
			return -ENOMEM;

		reqctx->tmp_buf = tmp_buf;
		reqctx->tmp_buf_phys = dma_map_single(dev, tmp_buf, req->cryptlen, DMA_FROM_DEVICE);
	} else if (req->src == req->dst) {
		if (unlikely(!dma_map_sg(dev, req->src,
							   reqctx->ssg_len,
							   DMA_BIDIRECTIONAL)))
			return -ENOMEM;
	} else {
		if (unlikely(!dma_map_sg(dev, req->src,
							   reqctx->ssg_len,
							   DMA_TO_DEVICE)))
			return -ENOMEM;

		if (unlikely(!dma_map_sg(dev, req->dst,
							   reqctx->dsg_len,
							   DMA_FROM_DEVICE)))
			return -ENOMEM;
	}

	iv_phys = dma_map_single(dev, reqctx->iv, AES_BLOCK_SIZE, DMA_TO_DEVICE);
	if (unlikely((ret = dma_mapping_error(dev, iv_phys))))
		return ret;

	reqctx->iv_phys = iv_phys;
//	reqctx->misal_phys = dma_map_single(priv->dev, reqctx->misalign_buffer, sizeof(reqctx->misalign_buffer), DMA_FROM_DEVICE);
	nbytes = req->cryptlen;

	spin_lock_bh(&ch->ring_lock);
	tx = ch->dma_tx;
	cur_tx = ch->cur_tx;

	// eval free tx desc count
	if (READ_ONCE(tx[(cur_tx + 1 + DIV_ROUND_UP(reqctx->ssg_len, 2)) % DMA_RING_SIZE].des3) & CE_RDES3_OWN)
		goto cleanup;

	//1: key and iv
	tx[cur_tx].des0 = ctx->key_phys; // buffer1: key
	tx[cur_tx].des1 = reqctx->iv_phys; // buffer2: iv
	tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
		 FIELD_PREP(CE_TDES2_B1L, ctx->keylen) |
		 FIELD_PREP(CE_TDES2_B2L, AES_BLOCK_SIZE) |
		 FIELD_PREP(CE_TDES2_B2T, CE_BUF_AES_IV);
	tx[cur_tx].des3 = CE_TDES3_OWN | CE_TDES3_FD |
		 FIELD_PREP(CE_TDES3_B1T, CE_BUF_AES_KEY) |
		 FIELD_PREP(CE_TDES3_CM, is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
		 FIELD_PREP(CE_TDES3_CT, CE_AES_CTR) |
		 FIELD_PREP(CE_TDES3_PL, nbytes);
	pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
	pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
	pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
	pr_debug("tdes3: %08X\n", tx[cur_tx].des3);

	cur_tx = (cur_tx + 1) % DMA_RING_SIZE;

	for_each_sg(req->src, sg, reqctx->ssg_len, i) {
		int ld = (i == reqctx->ssg_len - 1);
		if (i % 2 == 0) { /* buffer at des0 */
			tx[cur_tx].des0 = sg_dma_address(sg);
			buf1len = sg_dma_len(sg);
			pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
		} else { /* buffer at des1 */
			tx[cur_tx].des1 = sg_dma_address(sg);
			tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
				FIELD_PREP(CE_TDES2_B2L, sg_dma_len(sg)) |
				FIELD_PREP(CE_TDES2_B2T, CE_BUF_PAYLOAD) |
				FIELD_PREP(CE_TDES2_B1L, buf1len);
			tx[cur_tx].des3 =
				CE_TDES3_OWN | FIELD_PREP(CE_TDES3_LD, ld) |
				FIELD_PREP(CE_TDES3_B1T, CE_BUF_PAYLOAD) |
				FIELD_PREP(CE_TDES3_CM, is_decrypt ?
								CM_DECRYPT :
								CM_ENCRYPT) |
				FIELD_PREP(CE_TDES3_CT, CE_AES_CTR) |
				FIELD_PREP(CE_TDES3_PL, nbytes);
			pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
			pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
			pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
			cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
		}
	}

	/* fix up the last desc */
	if (i % 2) {
		tx[cur_tx].des1 = 0;
		tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) | FIELD_PREP(CE_TDES2_B2T, CE_BUF_PAYLOAD) | FIELD_PREP(CE_TDES2_B1L, buf1len);
		tx[cur_tx].des3 =
			CE_TDES3_OWN | CE_TDES3_LD |
			FIELD_PREP(CE_TDES3_B1T, CE_BUF_PAYLOAD) |
			FIELD_PREP(CE_TDES3_CM,
				   is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
			FIELD_PREP(CE_TDES3_CT, CE_AES_CTR) |
			FIELD_PREP(CE_TDES3_PL, nbytes);
		pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
		pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
		pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
		cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
	}
	ch->cur_tx = cur_tx;

	rx = ch->dma_rx;
	cur_rx = READ_ONCE(ch->cur_rx);
	// prepare rx desc

	if (reqctx->tmp_buf_phys) {
		/* one large rx buffer for tmp buffer */
		rx[cur_rx].des0 = reqctx->tmp_buf_phys;
		rx[cur_rx].des1 = 0;
		rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, ALIGN(nbytes, AES_BLOCK_SIZE));
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

#if 0
	for_each_sg(req->dst, sg, reqctx->dsg_len, i) {
		dma_addr_t buf_phys, buf_phys_align_start, buf_phys_align_end;
		unsigned int buf_len;
		unsigned long start_offset, end_offset;
		int ld = (i == reqctx->dsg_len - 1);

		buf_phys = sg_dma_address(sg);
		buf_len =  sg_dma_len(sg);
		buf_phys_align_start = ALIGN(buf_phys, DMA_RX_ALIGN);
		buf_phys_align_end = ALIGN_DOWN(buf_phys + buf_len, DMA_RX_ALIGN);

		start_offset = buf_phys_align_start - buf_phys;
		end_offset = buf_phys + buf_len - buf_phys_align_end;

		if (likely(buf_phys_align_start < buf_phys_align_end)) {
			if (start_offset) {
				/* handle start address misalignment */
				rx[cur_rx].des0 = reqctx->misal_phys + DMA_RX_ALIGN * reqctx->misalign_count + DMA_RX_ALIGN - start_offset;
				rx[cur_rx].des1 = 0;
				rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, start_offset);
				rx[cur_rx].des3 = CE_RDES3_OWN;
				pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
				pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
				pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
				pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
				cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
				reqctx->misalign_count++;
			}

			rx[cur_rx].des0 = buf_phys_align_start;
			rx[cur_rx].des1 = 0;
			rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, buf_phys_align_end - buf_phys_align_start);
			rx[cur_rx].des3 = CE_RDES3_OWN | FIELD_PREP(CE_RDES3_IOC, ld && !end_offset);
				pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
				pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
				pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
				pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
			/* link the request to the last rx descriptor */
			if (ld && !end_offset)
				ch->areqs[cur_rx] = &req->base;

			cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
		}

		if (end_offset) {
			/* handle end address misalignment */
			rx[cur_rx].des0 = reqctx->misal_phys + DMA_RX_ALIGN * reqctx->misalign_count + DMA_RX_ALIGN - end_offset;
			rx[cur_rx].des1 = 0;
			rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, end_offset);
			rx[cur_rx].des3 = CE_RDES3_OWN | FIELD_PREP(CE_RDES3_IOC, ld);
			pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
			pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
			pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
			pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
			/* link the request to the last rx descriptor */
			if (ld)
				ch->areqs[cur_rx] = &req->base;

			cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
			reqctx->misalign_count++;
		}
		WARN_ON(reqctx->misalign_count > ARRAY_SIZE(reqctx->misalign_buffer));
	}
#endif
	WRITE_ONCE(ch->cur_rx, cur_rx);
	spin_unlock_bh(&ch->ring_lock);
	/* inform the DMA for the new data */
	dma_wmb();
	reg_write(priv, CE_DMA_CH_RxDESC_TAIL_LPTR(ch->ch_num), ch->dma_rx_phy + sizeof(struct sf_ce_desc) * cur_rx);
	reg_write(priv, CE_DMA_CH_TxDESC_TAIL_LPTR(ch->ch_num), ch->dma_tx_phy + sizeof(struct sf_ce_desc) * cur_tx);

	return -EINPROGRESS;
cleanup:
	// TODO: handle CRYPTO_TFM_REQ_MAY_BACKLOG
	spin_unlock_bh(&ch->ring_lock);
	kfree(reqctx->tmp_buf);
	return -EBUSY;
}

static int
sf_ce_aes_cra_init(struct crypto_tfm *tfm)
{
	struct sf_ce_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	struct sf_ce_dev *priv = g_dev;
	struct device *dev = priv->dev;

	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
				    sizeof(struct sf_ce_aes_reqctx));
	ctx->priv = priv;
	ctx->key_phys = dma_map_single_attrs(dev, ctx->key, sizeof(ctx->key),
					     DMA_TO_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);

	return dma_mapping_error(dev, ctx->key_phys);
}

static void
sf_ce_aes_cra_exit(struct crypto_tfm *tfm)
{
	struct sf_ce_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	struct device *dev = ctx->priv->dev;

	dma_unmap_single(dev, ctx->key_phys, sizeof(ctx->key), DMA_TO_DEVICE);
}

static int
sf_ce_aes_ctr_setkey(struct crypto_skcipher *tfm, const u8 *key,
		     unsigned int keylen)
{
	struct sf_ce_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct device *dev = ctx->priv->dev;
	int ret;

	ret = aes_check_keylen(keylen);
	if (ret)
		return ret;

	ctx->keylen = keylen;
	memcpy(ctx->key, key, keylen);
	dma_sync_single_for_device(dev, ctx->key_phys, keylen, DMA_TO_DEVICE);
	return 0;
}

static int
sf_ce_aes_ctr_enc(struct skcipher_request *req)
{
	return sf_ce_aes_ctr_op(req, false);
}

static int
sf_ce_aes_ctr_dec(struct skcipher_request *req)
{
	return sf_ce_aes_ctr_op(req, true);
}

struct skcipher_alg sf_ce_aes_ctr __read_mostly = {
	.setkey = sf_ce_aes_ctr_setkey,
	.encrypt = sf_ce_aes_ctr_enc,
	.decrypt = sf_ce_aes_ctr_dec,
	.ivsize = AES_BLOCK_SIZE,
	.min_keysize = AES_MIN_KEY_SIZE,
	.max_keysize = AES_MAX_KEY_SIZE,
	.base = {
		.cra_name		= "ctr(aes)",
		.cra_driver_name	= "siflower-ce-aes-ctr",
		.cra_priority		= 300,
		.cra_blocksize		= 1,
		.cra_ctxsize		= sizeof(struct sf_ce_aes_ctx),
		.cra_flags		= CRYPTO_ALG_ASYNC |
					  CRYPTO_ALG_KERN_DRIVER_ONLY,
		.cra_module		= THIS_MODULE,
		.cra_init		= sf_ce_aes_cra_init,
		.cra_exit		= sf_ce_aes_cra_exit,
	},
};


static int sf_ce_aes_gcm_cra_init(struct crypto_tfm *tfm)
{
	struct sf_ce_aes_gcm_ctx *ctx = crypto_tfm_ctx(tfm);
	struct sf_ce_dev *priv = g_dev;
	struct device *dev = priv->dev;

	BUILD_BUG_ON(&ctx->key[sizeof(ctx->key)] != &ctx->k0[0]);
	BUILD_BUG_ON(&ctx->k0[sizeof(ctx->k0)] != (u8 *)&ctx->taglen_dma);

	crypto_aead_set_reqsize(__crypto_aead_cast(tfm),
				sizeof(struct sf_ce_aes_gcm_reqctx));
	ctx->priv = g_dev;
	ctx->key_0_phys = dma_map_single_attrs(dev, ctx->key, sizeof(ctx->key) + sizeof(ctx->k0) + sizeof(ctx->taglen_dma),
					       DMA_TO_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
	return dma_mapping_error(dev, ctx->key_0_phys);
}

static void
sf_ce_aes_gcm_cra_exit(struct crypto_tfm *tfm)
{
	struct sf_ce_aes_gcm_ctx *ctx = crypto_tfm_ctx(tfm);
	struct device *dev = ctx->priv->dev;

	dma_unmap_single(dev, ctx->key_0_phys, sizeof(ctx->key) + sizeof(ctx->k0) + sizeof(ctx->taglen_dma), DMA_TO_DEVICE);
}

static int
sf_ce_aes_gcm_setkey(struct crypto_aead *tfm, const u8 *key,
		     unsigned int keylen)
{
	struct sf_ce_aes_gcm_ctx *ctx = crypto_aead_ctx(tfm);
	struct sf_ce_dev *priv = ctx->priv;
	struct crypto_aes_ctx aes;
	int ret;

	ret = aes_expandkey(&aes, key, keylen);
	if (ret)
		return ret;

	ctx->keylen = keylen;
	memcpy(ctx->key, key, keylen);
	aes_encrypt(&aes, ctx->k0, priv->zero_pad);
	dma_sync_single_for_device(priv->dev, ctx->key_0_phys, sizeof(ctx->key) + sizeof(ctx->k0), DMA_TO_DEVICE);
	memzero_explicit(&aes, sizeof(aes));
	return 0;
}

static int
sf_ce_aes_gcm_setauthsize(struct crypto_aead *tfm, unsigned int authsize)
{
	struct sf_ce_aes_gcm_ctx *ctx = crypto_aead_ctx(tfm);
	struct device *dev = ctx->priv->dev;
	int ret;

	ret = crypto_gcm_check_authsize(authsize);
	if (ret)
		return ret;

	ctx->taglen = authsize;
	ctx->taglen_dma = cpu_to_be64(authsize);
	dma_sync_single_for_device(dev, ctx->key_0_phys + sizeof(ctx->key) + sizeof(ctx->k0),
				   sizeof(ctx->taglen_dma), DMA_TO_DEVICE);
	return 0;
}


static int
sf_ce_aes_gcm_op(struct aead_request *req, bool is_decrypt)
{
	struct sf_ce_aes_gcm_reqctx *reqctx = aead_request_ctx(req);
	struct sf_ce_aes_gcm_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct sf_ce_dev *priv = ctx->priv;
	struct device *dev = priv->dev;
	struct sf_ce_chan *ch = &priv->chan[DMA_CH_AES];
	dma_addr_t iv_extra_phys;
	int ret;
	struct sf_ce_desc *rx, *tx;
	unsigned int cur_tx, cur_rx;
	struct scatterlist *sg;
	unsigned int i, nbytes, buf1len, adata_sgs, pl, src_extra_bytes, dst_extra_bytes;
	int alen = req->assoclen;

	if (unlikely(!req->cryptlen)) {
		// TODO: software fallback for zero length
		pr_err("error: plen of 0 not supported!\n");
		return 0;
	}

	reqctx->tmp_buf = NULL;
	reqctx->tmp_buf_phys = 0;
	nbytes = is_decrypt ? req->cryptlen : req->cryptlen + 16;
//	reqctx->misalign_count = 0;
	/* req->iv may not be physically contiguous, so copy it to reqctx,
	 * which is contiguous and can be used for DMA.
	 */
	memcpy(reqctx->iv, req->iv, GCM_AES_IV_SIZE);
	memset(reqctx->iv + GCM_AES_IV_SIZE, 0, sizeof(reqctx->iv) - GCM_AES_IV_SIZE);
	reqctx->alen_dma = cpu_to_be64(req->assoclen);
	reqctx->plen_dma = cpu_to_be64(req->cryptlen);

	if (is_decrypt) {
		reqctx->ssg_len =
			sf_ce_sg_nents_for_len(req->src,
					       req->cryptlen + ctx->taglen,
					       &src_extra_bytes);
		reqctx->dsg_len = sf_ce_sg_nents_for_len(
			req->dst, req->cryptlen, &dst_extra_bytes);
	} else {
		reqctx->ssg_len = sf_ce_sg_nents_for_len(
			req->src, req->cryptlen, &src_extra_bytes);
		reqctx->dsg_len =
			sf_ce_sg_nents_for_len(req->dst,
					       req->cryptlen + ctx->taglen,
					       &dst_extra_bytes);
	}

	if (is_decrypt)
		scatterwalk_map_and_copy(reqctx->tag, req->src, req->cryptlen, ctx->taglen, 0);

	if (sf_ce_need_temp_buffer(req->dst, reqctx->dsg_len)) {
		void *tmp_buf;
		gfp_t flags;

		if (unlikely(reqctx->ssg_len != dma_map_sg(dev, req->src,
							   reqctx->ssg_len,
							   DMA_TO_DEVICE)))
			return -ENOMEM;

		flags = (req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP) ?
			GFP_KERNEL : GFP_ATOMIC;
		tmp_buf = kmalloc(ALIGN(nbytes, DMA_RX_ALIGN), flags);
		if (!tmp_buf)
			return -ENOMEM;

		reqctx->tmp_buf = tmp_buf;
		reqctx->tmp_buf_phys = dma_map_single(dev, tmp_buf, nbytes, DMA_FROM_DEVICE);
	} else if (req->src == req->dst) {
		reqctx->dsg_len = reqctx->ssg_len;

		if (unlikely(reqctx->ssg_len != dma_map_sg(dev, req->src,
							   reqctx->ssg_len,
							   DMA_BIDIRECTIONAL)))
			return -ENOMEM;
	} else {
		reqctx->dsg_len = sg_nents(req->dst);

		if (unlikely(reqctx->ssg_len != dma_map_sg(dev, req->src,
							   reqctx->ssg_len,
							   DMA_TO_DEVICE)))
			return -ENOMEM;

		if (unlikely(reqctx->dsg_len != dma_map_sg(dev, req->dst,
							   reqctx->dsg_len,
							   DMA_FROM_DEVICE)))
			return -ENOMEM;
	}

	iv_extra_phys = dma_map_single(dev, reqctx->iv, sizeof(reqctx->iv) + sizeof(reqctx->alen_dma) + sizeof(reqctx->plen_dma) + sizeof(reqctx->tag), DMA_TO_DEVICE);
	if (unlikely((ret = dma_mapping_error(dev, iv_extra_phys))))
		return ret;

	reqctx->iv_extra_phys = iv_extra_phys;
//	reqctx->misal_phys = dma_map_single(priv->dev, reqctx->misalign_buffer, sizeof(reqctx->misalign_buffer), DMA_FROM_DEVICE);
	pl = req->cryptlen + ALIGN(req->assoclen, AES_BLOCK_SIZE);

	tx = ch->dma_tx;
	cur_tx = ch->cur_tx;

	//1: key and iv
	tx[cur_tx].des0 = ctx->key_0_phys; // buffer1: key
	tx[cur_tx].des1 = reqctx->iv_extra_phys; // buffer2: iv
	tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
		 FIELD_PREP(CE_TDES2_B1L, ctx->keylen) |
		 FIELD_PREP(CE_TDES2_B2L, AES_BLOCK_SIZE) |
		 FIELD_PREP(CE_TDES2_B2T, CE_BUF_AES_IV);
	tx[cur_tx].des3 = CE_TDES3_OWN | CE_TDES3_FD |
		 FIELD_PREP(CE_TDES3_B1T, CE_BUF_AES_KEY) |
		 FIELD_PREP(CE_TDES3_CM, is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
		 FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
		 FIELD_PREP(CE_TDES3_PL, pl);

	pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
	pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
	pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
	pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
	cur_tx = (cur_tx + 1) % DMA_RING_SIZE;

	if (is_decrypt) {
		// prepare tagparams
		tx[cur_tx].des0 =
			ctx->key_0_phys + sizeof(ctx->key) + sizeof(ctx->k0);
		tx[cur_tx].des1 = reqctx->iv_extra_phys + sizeof(reqctx->iv) +
				  sizeof(reqctx->alen_dma) +
				  sizeof(reqctx->plen_dma);
		tx[cur_tx].des2 =
			FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
			FIELD_PREP(CE_TDES2_B1L, sizeof(ctx->taglen_dma)) |
			FIELD_PREP(CE_TDES2_B2L, sizeof(reqctx->tag)) |
			FIELD_PREP(CE_TDES2_B2T, CE_BUF_AES_AEAD_TAG);
		tx[cur_tx].des3 =
			CE_TDES3_OWN |
			FIELD_PREP(CE_TDES3_B1T, CE_BUF_AES_AEAD_TAG) |
			FIELD_PREP(CE_TDES3_CM,
				   is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
			FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
			FIELD_PREP(CE_TDES3_PL, pl);
		pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
		pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
		pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
		pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
		cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
	}
	//2: k0 and extra
	tx[cur_tx].des0 = ctx->key_0_phys + sizeof(ctx->key); // buffer1: k0
	tx[cur_tx].des1 = reqctx->iv_extra_phys + sizeof(reqctx->iv); // buffer2: extra
	tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
		 FIELD_PREP(CE_TDES2_B1L, sizeof(ctx->k0)) |
		 FIELD_PREP(CE_TDES2_B2L, sizeof(reqctx->alen_dma) + sizeof(reqctx->plen_dma)) |
		 FIELD_PREP(CE_TDES2_B2T, CE_BUF_AES_AEAD_EXTRA);
	tx[cur_tx].des3 = CE_TDES3_OWN |
		 FIELD_PREP(CE_TDES3_B1T, CE_BUF_AES_AEAD_K0) |
		 FIELD_PREP(CE_TDES3_CM, is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
		 FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
		 FIELD_PREP(CE_TDES3_PL, pl);
	pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
	pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
	pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
	pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
	cur_tx = (cur_tx + 1) % DMA_RING_SIZE;

	// 3: assoc
	if (req->assoclen) {
		/* adata is typically in the first buffer, but may scatter */
		adata_sgs = sg_nents_for_len(req->src, req->assoclen);
		const unsigned int adata_pad_sg = adata_sgs;

		for_each_sg (req->src, sg, adata_sgs, i) {
			if (i % 2 == 0) { /* buffer at des0 */
				tx[cur_tx].des0 = sg_dma_address(sg);

				if (sg_dma_len(sg) > alen) {
					/* this buffer contains adata and pltext */
					buf1len = alen;
				} else {
					/* this buffer contains only adata */
					buf1len = sg_dma_len(sg);
				}
				alen -= sg_dma_len(sg);
				pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
			} else { /* buffer at des1 */
				unsigned int buf2len;
				if (sg_dma_len(sg) > alen) {
					/* this buffer contains adata and pltext */
					buf2len = alen;
				} else {
					/* this buffer contains only adata */
					buf2len = sg_dma_len(sg);
				}
				alen -= sg_dma_len(sg);
				tx[cur_tx].des1 = sg_dma_address(sg);
				tx[cur_tx].des2 =
					FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
					FIELD_PREP(CE_TDES2_B2L,
						  buf2len) |
					FIELD_PREP(CE_TDES2_B2T,
						   CE_BUF_AES_AEAD_HEADER) |
					FIELD_PREP(CE_TDES2_B1L, buf1len);
				tx[cur_tx].des3 =
					CE_TDES3_OWN |
					FIELD_PREP(CE_TDES3_B1T,
						   CE_BUF_AES_AEAD_HEADER) |
					FIELD_PREP(CE_TDES3_CM,
						   is_decrypt ? CM_DECRYPT :
								CM_ENCRYPT) |
					FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
					FIELD_PREP(CE_TDES3_PL, pl);
				pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
				pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
				pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
				cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
			}
			if (alen < 0) {
				adata_sgs--;
				break;
			}
		}
		/* fix up the last desc */
		if (adata_pad_sg % 2) {
			tx[cur_tx].des1 = priv->zero_pad_phys;
			tx[cur_tx].des2 =
					FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
					FIELD_PREP(CE_TDES2_B2L,
						  ALIGN(req->assoclen, AES_BLOCK_SIZE) - req->assoclen) |
					FIELD_PREP(CE_TDES2_B2T,
						   CE_BUF_AES_AEAD_HEADER) |
					FIELD_PREP(CE_TDES2_B1L, buf1len);
			tx[cur_tx].des3 =
					CE_TDES3_OWN |
					FIELD_PREP(CE_TDES3_B1T,
						   CE_BUF_AES_AEAD_HEADER) |
					FIELD_PREP(CE_TDES3_CM,
						   is_decrypt ? CM_DECRYPT :
								CM_ENCRYPT) |
					FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
					FIELD_PREP(CE_TDES3_PL, pl);
			pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
			pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
			pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
			cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
		} else if (ALIGN(req->assoclen, AES_BLOCK_SIZE) - req->assoclen) {
			tx[cur_tx].des0 = priv->zero_pad_phys;
			tx[cur_tx].des1 = 0;
			tx[cur_tx].des2 =
				FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
				FIELD_PREP(CE_TDES2_B1L, ALIGN(req->assoclen,
							       AES_BLOCK_SIZE) -
								 req->assoclen) |
					FIELD_PREP(CE_TDES2_B2T,
						   CE_BUF_AES_AEAD_HEADER);
			tx[cur_tx].des3 = CE_TDES3_OWN |
					  FIELD_PREP(CE_TDES3_B1T,
						     CE_BUF_AES_AEAD_HEADER) |
					  FIELD_PREP(CE_TDES3_CM,
						     is_decrypt ? CM_DECRYPT :
								  CM_ENCRYPT) |
					  FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
					  FIELD_PREP(CE_TDES3_PL, pl);

			pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
			pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
			pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
			pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
			cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
		}
	} else {
		sg = req->src;
		adata_sgs = 0;
#if 0
		tx[cur_tx].des0 = priv->zero_pad_phys;
		tx[cur_tx].des1 = 0;
		tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
				  FIELD_PREP(CE_TDES2_B1L, 0);
		tx[cur_tx].des3 =
			CE_TDES3_OWN |
			FIELD_PREP(CE_TDES3_B1T, CE_BUF_AES_AEAD_HEADER) |
			FIELD_PREP(CE_TDES3_CM,
				   is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
			FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
			FIELD_PREP(CE_TDES3_PL, pl);

		pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
		pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
		pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
		pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
		cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
#endif
	}

	/* after adata is set, alen may be negative if there is a buffer which contains both adata and plen
	*/
	for_each_sg(sg, sg, reqctx->ssg_len - adata_sgs, i) {
		int ld = (i == reqctx->ssg_len - adata_sgs - 1);
		if (i % 2 == 0) { /* buffer at des0 */
			if (alen < 0) {
				tx[cur_tx].des0 = sg_dma_address(sg)+(ld ? sg_dma_len(sg) - src_extra_bytes : sg_dma_len(sg))+alen;
				buf1len = -alen;
				alen = 0;
			} else {
				tx[cur_tx].des0 = sg_dma_address(sg);
			/* the last buffer may contain more bytes than we want,
			 * make sure to limit it */
			buf1len = ld ? sg_dma_len(sg) - src_extra_bytes : sg_dma_len(sg);
			}
			pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
		} else { /* buffer at des1 */
			tx[cur_tx].des1 = sg_dma_address(sg);
			tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
				FIELD_PREP(CE_TDES2_B2L, ld ? sg_dma_len(sg) - src_extra_bytes : sg_dma_len(sg)) |
				FIELD_PREP(CE_TDES2_B2T, CE_BUF_PAYLOAD) |
				FIELD_PREP(CE_TDES2_B1L, buf1len);
			tx[cur_tx].des3 =
				CE_TDES3_OWN | FIELD_PREP(CE_TDES3_LD, ld) |
				FIELD_PREP(CE_TDES3_B1T, CE_BUF_PAYLOAD) |
				FIELD_PREP(CE_TDES3_CM, is_decrypt ?
								CM_DECRYPT :
								CM_ENCRYPT) |
				FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
				FIELD_PREP(CE_TDES3_PL, pl);
			pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
			pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
			pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
			cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
		}
	}

	/* fix up the last desc */
	if (reqctx->ssg_len % 2) {
		tx[cur_tx].des1 = 0;
		tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) | FIELD_PREP(CE_TDES2_B2T, CE_BUF_PAYLOAD) | FIELD_PREP(CE_TDES2_B1L, buf1len);
		tx[cur_tx].des3 =
			CE_TDES3_OWN | CE_TDES3_LD |
			FIELD_PREP(CE_TDES3_B1T, CE_BUF_PAYLOAD) |
			FIELD_PREP(CE_TDES3_CM,
				   is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
			FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
			FIELD_PREP(CE_TDES3_PL, pl);
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
		rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, ALIGN(nbytes, DMA_RX_ALIGN));
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

#if 0
	for_each_sg(req->dst, sg, reqctx->dsg_len, i) {
		dma_addr_t buf_phys, buf_phys_align_start, buf_phys_align_end;
		unsigned int buf_len;
		unsigned long start_offset, end_offset;
		int ld = (i == reqctx->dsg_len - 1);

		buf_phys = sg_dma_address(sg);
		buf_len =  sg_dma_len(sg);
		buf_phys_align_start = ALIGN(buf_phys, DMA_RX_ALIGN);
		buf_phys_align_end = ALIGN_DOWN(buf_phys + buf_len, DMA_RX_ALIGN);

		start_offset = buf_phys_align_start - buf_phys;
		end_offset = buf_phys + buf_len - buf_phys_align_end;

		if (likely(buf_phys_align_start < buf_phys_align_end)) {
			if (start_offset) {
				/* handle start address misalignment */
				rx[cur_rx].des0 = reqctx->misal_phys + DMA_RX_ALIGN * reqctx->misalign_count + DMA_RX_ALIGN - start_offset;
				rx[cur_rx].des1 = 0;
				rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, start_offset);
				rx[cur_rx].des3 = CE_RDES3_OWN;
				pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
				pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
				pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
				pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
				cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
				reqctx->misalign_count++;
			}

			rx[cur_rx].des0 = buf_phys_align_start;
			rx[cur_rx].des1 = 0;
			rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, buf_phys_align_end - buf_phys_align_start);
			rx[cur_rx].des3 = CE_RDES3_OWN | FIELD_PREP(CE_RDES3_IOC, ld && !end_offset);
				pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
				pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
				pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
				pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
			/* link the request to the last rx descriptor */
			if (ld && !end_offset)
				ch->areqs[cur_rx] = &req->base;

			cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
		}

		if (end_offset) {
			/* handle end address misalignment */
			rx[cur_rx].des0 = reqctx->misal_phys + DMA_RX_ALIGN * reqctx->misalign_count + DMA_RX_ALIGN - end_offset;
			rx[cur_rx].des1 = 0;
			rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, end_offset);
			rx[cur_rx].des3 = CE_RDES3_OWN | FIELD_PREP(CE_RDES3_IOC, ld);
			pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
			pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
			pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
			pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
			/* link the request to the last rx descriptor */
			if (ld)
				ch->areqs[cur_rx] = &req->base;

			cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
			reqctx->misalign_count++;
		}
		WARN_ON(reqctx->misalign_count > ARRAY_SIZE(reqctx->misalign_buffer));
	}
#endif
	ch->cur_rx = cur_rx;
	/* inform the DMA for the new data */
	dma_wmb();
	reg_write(priv, CE_DMA_CH_RxDESC_TAIL_LPTR(ch->ch_num), ch->dma_rx_phy + sizeof(struct sf_ce_desc) * cur_rx);
	reg_write(priv, CE_DMA_CH_TxDESC_TAIL_LPTR(ch->ch_num), ch->dma_tx_phy + sizeof(struct sf_ce_desc) * cur_tx);

	return -EINPROGRESS;
}

static int sf_ce_aes_gcm_enc(struct aead_request *req)
{
	return sf_ce_aes_gcm_op(req, false);
}

static int sf_ce_aes_gcm_dec(struct aead_request *req)
{
	return sf_ce_aes_gcm_op(req, true);
}

/* taken from crypto/ccm.c */
static int set_msg_len(u8 *block, unsigned int msglen, int csize)
{
	__be32 data;

	memset(block, 0, csize);
	block += csize;

	if (csize >= 4)
		csize = 4;
	else if (msglen > (unsigned int)(1 << (8 * csize)))
		return -EOVERFLOW;

	data = cpu_to_be32(msglen);
	memcpy(block - csize, (u8 *)&data + 4 - csize, csize);

	return 0;
}

/* based on code from crypto/ccm.c */
static int generate_b0(const u8 *iv, unsigned int assoclen, unsigned int authsize,
		       unsigned int cryptlen, u8 *b0)
{
	unsigned int l, lp, m = authsize;
	int rc;

	memcpy(b0, iv, AES_BLOCK_SIZE);

	lp = b0[0];
	l = lp + 1;

	/* set m, bits 3-5 */
	*b0 |= (8 * ((m - 2) / 2));

	/* set adata, bit 6, if associated data is used */
	if (assoclen)
		*b0 |= BIT(6);

	rc = set_msg_len(b0 + AES_BLOCK_SIZE - l, cryptlen, l);

	return rc;
}

static int sf_ce_aes_ccm_cra_init(struct crypto_tfm *tfm)
{
	struct sf_ce_aes_ccm_ctx *ctx = crypto_tfm_ctx(tfm);
	struct sf_ce_dev *priv = g_dev;
	struct device *dev = priv->dev;

	BUILD_BUG_ON(&ctx->key[sizeof(ctx->key)] != (u8 *)&ctx->taglen_dma);

	crypto_aead_set_reqsize(__crypto_aead_cast(tfm),
				sizeof(struct sf_ce_aes_ccm_reqctx));
	ctx->priv = g_dev;
	ctx->key_0_phys = dma_map_single_attrs(dev, ctx->key, sizeof(ctx->key) + sizeof(ctx->taglen_dma),
					       DMA_TO_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
	return dma_mapping_error(dev, ctx->key_0_phys);
}

static void
sf_ce_aes_ccm_cra_exit(struct crypto_tfm *tfm)
{
	struct sf_ce_aes_ccm_ctx *ctx = crypto_tfm_ctx(tfm);
	struct device *dev = ctx->priv->dev;

	dma_unmap_single(dev, ctx->key_0_phys, sizeof(ctx->key) + sizeof(ctx->taglen_dma), DMA_TO_DEVICE);
}

static int
sf_ce_aes_ccm_setkey(struct crypto_aead *tfm, const u8 *key,
		     unsigned int keylen)
{
	struct sf_ce_aes_ccm_ctx *ctx = crypto_aead_ctx(tfm);
	struct device *dev = ctx->priv->dev;
	int ret;

	ret = aes_check_keylen(keylen);
	if (ret)
		return ret;

	ctx->keylen = keylen;
	memcpy(ctx->key, key, keylen);
	dma_sync_single_for_device(dev, ctx->key_0_phys, sizeof(ctx->key), DMA_TO_DEVICE);
	return 0;
}

static int
sf_ce_aes_ccm_setauthsize(struct crypto_aead *tfm, unsigned int authsize)
{
	struct sf_ce_aes_ccm_ctx *ctx = crypto_aead_ctx(tfm);
	struct device *dev = ctx->priv->dev;

	switch (authsize) {
	case 4:
	case 6:
	case 8:
	case 10:
	case 12:
	case 14:
	case 16:
		break;
	default:
		return -EINVAL;
	}

	ctx->taglen = authsize;
	ctx->taglen_dma = cpu_to_be64(authsize);
	dma_sync_single_for_device(dev, ctx->key_0_phys + sizeof(ctx->key),
				sizeof(ctx->taglen_dma), DMA_TO_DEVICE);
	return 0;
}

static inline int crypto_ccm_check_iv(const u8 *iv)
{
	/* 2 <= L <= 8, so 1 <= L' <= 7. */
	if (1 > iv[0] || iv[0] > 7)
		return -EINVAL;

	return 0;
}

static int
sf_ce_aes_ccm_op(struct aead_request *req, bool is_decrypt)
{
	struct sf_ce_aes_ccm_reqctx *reqctx = aead_request_ctx(req);
	struct sf_ce_aes_ccm_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct sf_ce_dev *priv = ctx->priv;
	struct device *dev = priv->dev;
	struct sf_ce_chan *ch = &priv->chan[DMA_CH_AES];
	dma_addr_t iv_extra_phys;
	int ret;
	struct sf_ce_desc *rx, *tx;
	unsigned int cur_tx, cur_rx;
	struct scatterlist *sg;
	unsigned int i, nbytes, buf1len, adata_sgs, pl;
	int alen = req->assoclen;

	if (unlikely(!req->cryptlen)) {
		// TODO: software fallback for zero length
		pr_err("error: plen of 0 not supported!\n");
		return 0;
	}
	ret = crypto_ccm_check_iv(req->iv);
	if (ret)
		return ret;

	reqctx->tmp_buf = NULL;
	reqctx->tmp_buf_phys = 0;

	nbytes = is_decrypt ? req->cryptlen : req->cryptlen + ctx->taglen;
//	reqctx->misalign_count = 0;
	/* req->iv may not be physically contiguous, so copy it to reqctx,
	 * which is contiguous and can be used for DMA.
	 */
	memcpy(reqctx->iv, req->iv, AES_BLOCK_SIZE);
	reqctx->alen_dma = cpu_to_be16(req->assoclen);
	BUILD_BUG_ON(&reqctx->b0[AES_BLOCK_SIZE] != (u8*)&reqctx->alen_dma);
	reqctx->ssg_len = sg_nents(req->src);
	reqctx->dsg_len = sg_nents(req->dst);

	if (is_decrypt)
		scatterwalk_map_and_copy(reqctx->tag, req->src, req->cryptlen, ctx->taglen, 0);

	/* Build B0 */
	ret = generate_b0(req->iv, req->assoclen, ctx->taglen, req->cryptlen, reqctx->b0);
	if (ret)
		return ret;

	if (sf_ce_need_temp_buffer(req->dst, reqctx->dsg_len)) {
		void *tmp_buf;
		gfp_t flags;

		if (unlikely(reqctx->ssg_len != dma_map_sg(dev, req->src,
							   reqctx->ssg_len,
							   DMA_TO_DEVICE)))
			return -ENOMEM;

		flags = (req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP) ?
			GFP_KERNEL : GFP_ATOMIC;
		tmp_buf = kmalloc(ALIGN(nbytes, DMA_RX_ALIGN), flags);
		if (!tmp_buf)
			return -ENOMEM;

		reqctx->tmp_buf = tmp_buf;
		reqctx->tmp_buf_phys = dma_map_single(dev, tmp_buf, nbytes, DMA_FROM_DEVICE);
	} else if (req->src == req->dst) {
		reqctx->dsg_len = reqctx->ssg_len;

		if (unlikely(reqctx->ssg_len != dma_map_sg(dev, req->src,
							   reqctx->ssg_len,
							   DMA_BIDIRECTIONAL)))
			return -ENOMEM;
	} else {
		reqctx->dsg_len = sg_nents(req->dst);

		if (unlikely(reqctx->ssg_len != dma_map_sg(dev, req->src,
							   reqctx->ssg_len,
							   DMA_TO_DEVICE)))
			return -ENOMEM;

		if (unlikely(reqctx->dsg_len != dma_map_sg(dev, req->dst,
							   reqctx->dsg_len,
							   DMA_FROM_DEVICE)))
			return -ENOMEM;
	}

	iv_extra_phys = dma_map_single(dev, reqctx->iv, sizeof(reqctx->iv) + sizeof(reqctx->b0) + sizeof(reqctx->alen_dma) + sizeof(reqctx->tag), DMA_TO_DEVICE);
	if (unlikely((ret = dma_mapping_error(dev, iv_extra_phys))))
		return ret;

	reqctx->iv_extra_phys = iv_extra_phys;
//	reqctx->misal_phys = dma_map_single(priv->dev, reqctx->misalign_buffer, sizeof(reqctx->misalign_buffer), DMA_FROM_DEVICE);
	pl = req->cryptlen + req->assoclen;

	tx = ch->dma_tx;
	cur_tx = ch->cur_tx;

	//1: key and iv
	tx[cur_tx].des0 = ctx->key_0_phys; // buffer1: key
	tx[cur_tx].des1 = reqctx->iv_extra_phys; // buffer2: iv
	tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
		 FIELD_PREP(CE_TDES2_B1L, ctx->keylen) |
		 FIELD_PREP(CE_TDES2_B2L, AES_BLOCK_SIZE) |
		 FIELD_PREP(CE_TDES2_B2T, CE_BUF_AES_IV);
	tx[cur_tx].des3 = CE_TDES3_OWN | CE_TDES3_FD |
		 FIELD_PREP(CE_TDES3_B1T, CE_BUF_AES_KEY) |
		 FIELD_PREP(CE_TDES3_CM, is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
		 FIELD_PREP(CE_TDES3_CT, CE_AES_CCM) |
		 FIELD_PREP(CE_TDES3_PL, pl);
				pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
				pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
				pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
				pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
	cur_tx = (cur_tx + 1) % DMA_RING_SIZE;

	if (is_decrypt) {
		// prepare tagparams
		tx[cur_tx].des0 =
			ctx->key_0_phys + sizeof(ctx->key);
		tx[cur_tx].des1 = reqctx->iv_extra_phys + sizeof(reqctx->iv) +
				  sizeof(reqctx->b0) +
				  sizeof(reqctx->alen_dma);
		tx[cur_tx].des2 =
			FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
			FIELD_PREP(CE_TDES2_B1L, sizeof(ctx->taglen_dma)) |
			FIELD_PREP(CE_TDES2_B2L, sizeof(reqctx->tag)) |
			FIELD_PREP(CE_TDES2_B2T, CE_BUF_AES_AEAD_TAG);
		tx[cur_tx].des3 =
			CE_TDES3_OWN |
			FIELD_PREP(CE_TDES3_B1T, CE_BUF_AES_AEAD_TAG) |
			FIELD_PREP(CE_TDES3_CM,
				   is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
			FIELD_PREP(CE_TDES3_CT, CE_AES_GCM) |
			FIELD_PREP(CE_TDES3_PL, pl);
				pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
				pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
				pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
				pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
		cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
	}
	//2: extra
	tx[cur_tx].des0 = reqctx->iv_extra_phys + sizeof(reqctx->iv); // buffer1: extra
	tx[cur_tx].des1 = 0;
	tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
		 FIELD_PREP(CE_TDES2_B1L, sizeof(reqctx->b0) + (req->assoclen ? sizeof(reqctx->alen_dma) : 0)) |
		 FIELD_PREP(CE_TDES2_B2T, CE_BUF_AES_AEAD_EXTRA);
	tx[cur_tx].des3 = CE_TDES3_OWN |
		 FIELD_PREP(CE_TDES3_B1T, CE_BUF_AES_AEAD_EXTRA) |
		 FIELD_PREP(CE_TDES3_CM, is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
		 FIELD_PREP(CE_TDES3_CT, CE_AES_CCM) |
		 FIELD_PREP(CE_TDES3_PL, pl);
				pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
				pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
				pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
				pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
	cur_tx = (cur_tx + 1) % DMA_RING_SIZE;

	// 3: assoc
	if (req->assoclen) {
		/* adata is typically in the first buffer, but may scatter */
		adata_sgs = sg_nents_for_len(req->src, req->assoclen);
		const unsigned int adata_pad_sg = adata_sgs;

		for_each_sg (req->src, sg, adata_sgs, i) {
			if (i % 2 == 0) { /* buffer at des0 */
				tx[cur_tx].des0 = sg_dma_address(sg);

				if (sg_dma_len(sg) > alen) {
					/* this buffer contains adata and pltext */
					buf1len = alen;
				} else {
					/* this buffer contains only adata */
					buf1len = sg_dma_len(sg);
				}
				alen -= sg_dma_len(sg);
				pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
			} else { /* buffer at des1 */
				unsigned int buf2len;
				if (sg_dma_len(sg) > alen) {
					/* this buffer contains adata and pltext */
					buf2len = alen;
				} else {
					/* this buffer contains only adata */
					buf2len = sg_dma_len(sg);
				}
				alen -= sg_dma_len(sg);
				tx[cur_tx].des1 = sg_dma_address(sg);
				tx[cur_tx].des2 =
					FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
					FIELD_PREP(CE_TDES2_B2L,
						  buf2len) |
					FIELD_PREP(CE_TDES2_B2T,
						   CE_BUF_AES_AEAD_HEADER) |
					FIELD_PREP(CE_TDES2_B1L, buf1len);
				tx[cur_tx].des3 =
					CE_TDES3_OWN |
					FIELD_PREP(CE_TDES3_B1T,
						   CE_BUF_AES_AEAD_HEADER) |
					FIELD_PREP(CE_TDES3_CM,
						   is_decrypt ? CM_DECRYPT :
								CM_ENCRYPT) |
					FIELD_PREP(CE_TDES3_CT, CE_AES_CCM) |
					FIELD_PREP(CE_TDES3_PL, pl);
				pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
				pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
				pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
				cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
			}
			if (alen < 0) {
				adata_sgs--;
				break;
			}
		}
		/* fix up the last desc */
		if (adata_pad_sg % 2) {
			tx[cur_tx].des1 = priv->zero_pad_phys;
			tx[cur_tx].des2 =
					FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
					FIELD_PREP(CE_TDES2_B2L,
						  ALIGN(2 + req->assoclen, AES_BLOCK_SIZE) - (2 + req->assoclen)) |
					FIELD_PREP(CE_TDES2_B2T,
						   CE_BUF_AES_AEAD_HEADER) |
					FIELD_PREP(CE_TDES2_B1L, buf1len);
			tx[cur_tx].des3 =
					CE_TDES3_OWN |
					FIELD_PREP(CE_TDES3_B1T,
						   CE_BUF_AES_AEAD_HEADER) |
					FIELD_PREP(CE_TDES3_CM,
						   is_decrypt ? CM_DECRYPT :
								CM_ENCRYPT) |
					FIELD_PREP(CE_TDES3_CT, CE_AES_CCM) |
					FIELD_PREP(CE_TDES3_PL, pl);
			pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
			pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
			pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
			cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
		} else if (ALIGN(2 + req->assoclen, AES_BLOCK_SIZE) - (2 + req->assoclen)) {
			pr_debug("adata_pad_sg: %u\n", adata_pad_sg);
			tx[cur_tx].des0 = priv->zero_pad_phys;
			tx[cur_tx].des1 = 0;
			tx[cur_tx].des2 =
				FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
				FIELD_PREP(CE_TDES2_B1L, ALIGN(2 + req->assoclen, AES_BLOCK_SIZE) - (2 + req->assoclen));
			tx[cur_tx].des3 = CE_TDES3_OWN |
					  FIELD_PREP(CE_TDES3_B1T,
						     CE_BUF_AES_AEAD_HEADER) |
					  FIELD_PREP(CE_TDES3_CM,
						     is_decrypt ? CM_DECRYPT :
								  CM_ENCRYPT) |
					  FIELD_PREP(CE_TDES3_CT, CE_AES_CCM) |
					  FIELD_PREP(CE_TDES3_PL, pl);

			pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
			pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
			pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
			pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
			cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
		}
	} else {
		sg = req->src;
		adata_sgs = 0;
	}

	/* after adata is set, alen may be negative if there is a buffer which contains both adata and plen
	*/
	for_each_sg(sg, sg, reqctx->ssg_len - adata_sgs, i) {
		int ld = (i == reqctx->ssg_len - adata_sgs - 1);
		if (i % 2 == 0) { /* buffer at des0 */
			if (alen < 0) {
				tx[cur_tx].des0 = sg_dma_address(sg)+sg_dma_len(sg)+alen;
				buf1len = -alen;
				alen = 0;
			} else {
				tx[cur_tx].des0 = sg_dma_address(sg);
				buf1len = sg_dma_len(sg);
			}
			pr_debug("tdes0: %08X\n", tx[cur_tx].des0);
		} else { /* buffer at des1 */
			tx[cur_tx].des1 = sg_dma_address(sg);
			tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) |
				FIELD_PREP(CE_TDES2_B2L, sg_dma_len(sg)) |
				FIELD_PREP(CE_TDES2_B2T, CE_BUF_PAYLOAD) |
				FIELD_PREP(CE_TDES2_B1L, buf1len);
			tx[cur_tx].des3 =
				CE_TDES3_OWN | FIELD_PREP(CE_TDES3_LD, ld) |
				FIELD_PREP(CE_TDES3_B1T, CE_BUF_PAYLOAD) |
				FIELD_PREP(CE_TDES3_CM, is_decrypt ?
								CM_DECRYPT :
								CM_ENCRYPT) |
				FIELD_PREP(CE_TDES3_CT, CE_AES_CCM) |
				FIELD_PREP(CE_TDES3_PL, pl);
			pr_debug("tdes1: %08X\n", tx[cur_tx].des1);
			pr_debug("tdes2: %08X\n", tx[cur_tx].des2);
			pr_debug("tdes3: %08X\n", tx[cur_tx].des3);
			cur_tx = (cur_tx + 1) % DMA_RING_SIZE;
		}
	}

	/* fix up the last desc */
	if (reqctx->ssg_len % 2) {
		tx[cur_tx].des1 = 0;
		tx[cur_tx].des2 = FIELD_PREP(CE_TDES2_ED, CE_ENDIAN_BIG) | FIELD_PREP(CE_TDES2_B1L, buf1len);
		tx[cur_tx].des3 =
			CE_TDES3_OWN | CE_TDES3_LD |
			FIELD_PREP(CE_TDES3_B1T, CE_BUF_PAYLOAD) |
			FIELD_PREP(CE_TDES3_CM,
				   is_decrypt ? CM_DECRYPT : CM_ENCRYPT) |
			FIELD_PREP(CE_TDES3_CT, CE_AES_CCM) |
			FIELD_PREP(CE_TDES3_PL, pl);
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
		rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, ALIGN(nbytes, DMA_RX_ALIGN));
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

#if 0
	for_each_sg(req->dst, sg, reqctx->dsg_len, i) {
		dma_addr_t buf_phys, buf_phys_align_start, buf_phys_align_end;
		unsigned int buf_len;
		unsigned long start_offset, end_offset;
		int ld = (i == reqctx->dsg_len - 1);

		buf_phys = sg_dma_address(sg);
		buf_len =  sg_dma_len(sg);
		buf_phys_align_start = ALIGN(buf_phys, DMA_RX_ALIGN);
		buf_phys_align_end = ALIGN_DOWN(buf_phys + buf_len, DMA_RX_ALIGN);

		start_offset = buf_phys_align_start - buf_phys;
		end_offset = buf_phys + buf_len - buf_phys_align_end;

		if (likely(buf_phys_align_start < buf_phys_align_end)) {
			if (start_offset) {
				/* handle start address misalignment */
				rx[cur_rx].des0 = reqctx->misal_phys + DMA_RX_ALIGN * reqctx->misalign_count + DMA_RX_ALIGN - start_offset;
				rx[cur_rx].des1 = 0;
				rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, start_offset);
				rx[cur_rx].des3 = CE_RDES3_OWN;
				pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
				pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
				pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
				pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
				cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
				reqctx->misalign_count++;
			}

			rx[cur_rx].des0 = buf_phys_align_start;
			rx[cur_rx].des1 = 0;
			rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, buf_phys_align_end - buf_phys_align_start);
			rx[cur_rx].des3 = CE_RDES3_OWN | FIELD_PREP(CE_RDES3_IOC, ld && !end_offset);
				pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
				pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
				pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
				pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
			/* link the request to the last rx descriptor */
			if (ld && !end_offset)
				ch->areqs[cur_rx] = &req->base;

			cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
		}

		if (end_offset) {
			/* handle end address misalignment */
			rx[cur_rx].des0 = reqctx->misal_phys + DMA_RX_ALIGN * reqctx->misalign_count + DMA_RX_ALIGN - end_offset;
			rx[cur_rx].des1 = 0;
			rx[cur_rx].des2 = FIELD_PREP(CE_RDES2_B1L, end_offset);
			rx[cur_rx].des3 = CE_RDES3_OWN | FIELD_PREP(CE_RDES3_IOC, ld);
			pr_debug("rdes0: %08X\n", rx[cur_rx].des0);
			pr_debug("rdes1: %08X\n", rx[cur_rx].des1);
			pr_debug("rdes2: %08X\n", rx[cur_rx].des2);
			pr_debug("rdes3: %08X\n", rx[cur_rx].des3);
			/* link the request to the last rx descriptor */
			if (ld)
				ch->areqs[cur_rx] = &req->base;

			cur_rx = (cur_rx + 1) % DMA_RING_SIZE;
			reqctx->misalign_count++;
		}
		WARN_ON(reqctx->misalign_count > ARRAY_SIZE(reqctx->misalign_buffer));
	}
#endif
	ch->cur_rx = cur_rx;
	/* inform the DMA for the new data */
	dma_wmb();
	reg_write(priv, CE_DMA_CH_RxDESC_TAIL_LPTR(ch->ch_num), ch->dma_rx_phy + sizeof(struct sf_ce_desc) * cur_rx);
	reg_write(priv, CE_DMA_CH_TxDESC_TAIL_LPTR(ch->ch_num), ch->dma_tx_phy + sizeof(struct sf_ce_desc) * cur_tx);

	return -EINPROGRESS;
}

static int sf_ce_aes_ccm_enc(struct aead_request *req)
{
	return sf_ce_aes_ccm_op(req, false);
}

static int sf_ce_aes_ccm_dec(struct aead_request *req)
{
	return sf_ce_aes_ccm_op(req, true);
}

struct aead_alg sf_ce_aes_gcm __read_mostly = {
	.setkey	= sf_ce_aes_gcm_setkey,
	.setauthsize = sf_ce_aes_gcm_setauthsize,
	.encrypt = sf_ce_aes_gcm_enc,
	.decrypt = sf_ce_aes_gcm_dec,
	.ivsize	= GCM_AES_IV_SIZE,
	.maxauthsize = AES_BLOCK_SIZE,
	.base = {
		.cra_name		= "gcm(aes)",
		.cra_driver_name	= "siflower-ce-aes-gcm",
		.cra_priority		= 300,
		.cra_blocksize		= 1,
		.cra_ctxsize		= sizeof(struct sf_ce_aes_gcm_ctx),
		.cra_flags		= CRYPTO_ALG_ASYNC |
					  CRYPTO_ALG_KERN_DRIVER_ONLY,
		.cra_module		= THIS_MODULE,
		.cra_init		= sf_ce_aes_gcm_cra_init,
		.cra_exit		= sf_ce_aes_gcm_cra_exit,
	},
};

struct aead_alg sf_ce_aes_ccm __read_mostly = {
	.setkey	= sf_ce_aes_ccm_setkey,
	.setauthsize = sf_ce_aes_ccm_setauthsize,
	.encrypt = sf_ce_aes_ccm_enc,
	.decrypt = sf_ce_aes_ccm_dec,
	.ivsize	= AES_BLOCK_SIZE,
	.maxauthsize = AES_BLOCK_SIZE,
	.base = {
		.cra_name		= "ccm(aes)",
		.cra_driver_name	= "siflower-ce-aes-ccm",
		.cra_priority		= 300,
		.cra_blocksize		= 1,
		.cra_ctxsize		= sizeof(struct sf_ce_aes_ccm_ctx),
		.cra_flags		= CRYPTO_ALG_ASYNC |
					  CRYPTO_ALG_KERN_DRIVER_ONLY,
		.cra_module		= THIS_MODULE,
		.cra_init		= sf_ce_aes_ccm_cra_init,
		.cra_exit		= sf_ce_aes_ccm_cra_exit,
	},
};
