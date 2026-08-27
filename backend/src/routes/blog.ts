import { Router } from 'express';
import { listPublished, getPublishedBySlug, normalizeBlogLang } from '../services/blog.js';
import { getImageBytes } from '../services/blogImages.js';

// PUBLIC blog endpoint'leri (auth YOK). Yalniz status=published makaleler doner; draft'lar
// buradan ASLA gorunmez. Frontend /{bolge}/blog + /{bolge}/blog/[slug] + sitemap bunlari kullanir.
// ?lang=tr|de ile dile gore filtrelenir (varsayilan tr).
export const blogRouter = Router();

blogRouter.get('/posts', async (req, res) => {
  const posts = await listPublished(normalizeBlogLang(req.query.lang));
  res.json(posts);
});

blogRouter.get('/posts/:slug', async (req, res) => {
  const post = await getPublishedBySlug(req.params.slug, normalizeBlogLang(req.query.lang));
  if (!post) return res.status(404).json({ error: 'Yazı bulunamadı.' });
  res.json(post);
});

// PUBLIC kapak görseli — /blog/images/:id. Uzun cache (immutable; id benzersiz → içerik değişmez).
// og:image ve <img> buradan gelir. Bayt DB'de; auth yok (yayınlanan içerik zaten herkese açık).
blogRouter.get('/images/:id', async (req, res) => {
  const img = await getImageBytes(req.params.id);
  if (!img) return res.status(404).end();
  res.setHeader('Content-Type', img.mime);
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  res.send(img.data);
});
