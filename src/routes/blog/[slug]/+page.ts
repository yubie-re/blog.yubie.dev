import type IMetadata from '$lib/types/IMetadata';
import type { PageLoad } from './$types';
import { error } from '@sveltejs/kit';

export const load: PageLoad = async ({ params }) => {
    const slugPattern = /^[a-zA-Z0-9_-]+$/;
    if (!slugPattern.test(params.slug)) {
        throw error(400, 'Invalid slug');
    }

    try {
        const post = await import(`../${params.slug}.md`);
        const metadata = post.metadata as IMetadata;
        const content = post.default;

        return {
            metadata,
            content,
            slug: params.slug
        };
    } catch  {
        throw error(404, 'Post not found');
    }
};