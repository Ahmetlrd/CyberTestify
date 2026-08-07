import { Router } from 'express';
import { listPublished, getPublishedBySlug } from '../services/blog.js';

// PUBLIC blog endpoint'leri (auth YOK). Yalniz status=published makaleler doner; draft'lar
// buradan ASLA gorunmez. Frontend /blog + /blog/[slug] + sitemap bunlari kullanir.
export const blogRouter = Router();

blogRouter.get('/posts', async (_req, res) => {
  const posts = await listPublished();
  res.json(posts);
});

blogRouter.get('/posts/:slug', async (req, res) => {
  const post = await getPublishedBySlug(req.params.slug);
  if (!post) return res.status(404).json({ error: 'Yazı bulunamadı.' });
  res.json(post);
});
