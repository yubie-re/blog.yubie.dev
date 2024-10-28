<script lang="ts">
    import * as Card from "$lib/components/ui/card/index.js";
    export let data;
    import {
	    blur,
    } from 'svelte/transition';
</script>



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