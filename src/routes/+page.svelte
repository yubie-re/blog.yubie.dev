<script lang="ts">
    import * as Card from "$lib/components/ui/card/index.js";
    export let data;
    import {
	    blur,
    } from 'svelte/transition';
</script>

<svelte:head>
<title>Yubie-re's blog</title>
<meta name="title" content="Yubie-re's blog" />
<meta name="description" content="A blog of interesting things I've encountered" />

<!-- Open Graph / Facebook -->
<meta property="og:type" content="website" />
<meta property="og:url" content="https://blog.yubie.dev/" />
<meta property="og:title" content="Yubie-re's blog" />
<meta property="og:description" content="A blog of interesting things I've encountered" />
<meta property="og:image" content="https://blog.yubie.dev/meta/og.png" />

<!-- Twitter -->
<meta property="twitter:card" content="summary_large_image" />
<meta property="twitter:url" content="https://blog.yubie.dev/" />
<meta property="twitter:title" content="Yubie-re's blog" />
<meta property="twitter:description" content="A blog of interesting things I've encountered" />
<meta property="twitter:image" content="https://blog.yubie.dev/meta/og.png" />
</svelte:head>


<div class="space-y-3" in:blur>
{#each data.posts as post}
<div class = "px-10">
<a href={post.path}>
    <Card.Root class="w-full pb-5">
        <Card.Header>
        <Card.Title>{post.meta.title}</Card.Title>
        <Card.Description>{post.meta.date} - {post.meta.author}</Card.Description>
        </Card.Header>
    </Card.Root>
</a>
</div>
{/each}
</div>