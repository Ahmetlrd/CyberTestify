import { Router } from 'express';
import { listPublished, getPublishedBySlug, normalizeBlogLang } from '../services/blog.js';

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
