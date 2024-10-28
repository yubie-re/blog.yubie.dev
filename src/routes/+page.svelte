<script lang="ts">
    import * as Card from "$lib/components/ui/card/index.js";
    export let data;
    import {
	    blur,
    } from 'svelte/transition';
</script>

<svelte:head>
<meta name="title" content="Yubie-re's blog">
<meta name="description" content="A blog of interesting things I've encountered">
<meta name="robots" content="index, follow">
<meta name="language" content="English">
<meta property="og:title" content="Yubie-re's blog" />
<meta property="og:description" content="A blog of interesting things I've encountered" />
<meta property="og:image" content="https://yubie.dev/meta/og.png" />
<meta property="og:type" content="article" />
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