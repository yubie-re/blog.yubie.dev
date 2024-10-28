import type IMetadata from '$lib/types/IMetadata';
import type IPost from '$lib/types/IPost';
import type { PageLoad } from './$types';



const fetchMarkdownPosts = async (): Promise<IPost[]> => {
	const allPostFiles = import.meta.glob('/src/routes/blog/*.md');
	const iterablePostFiles = Object.entries(allPostFiles);

	const allPosts = await Promise.all(
		iterablePostFiles.map(async ([path, resolver]) => {
			const { metadata } = (await resolver()) as { metadata: IMetadata };
			const postPath = path.slice(11, -3);

			return {
				meta: metadata,
				path: postPath
			};
		})
	);

	return allPosts;
};


export const load: PageLoad = async () => {
	let posts = await fetchMarkdownPosts()
    posts = posts.sort((a, b)=>{
        const dateA = new Date(a.meta.date);
        const dateB = new Date(b.meta.date);
        return dateB.getTime() - dateA.getTime();
    })
	return {
		posts
	};
};
