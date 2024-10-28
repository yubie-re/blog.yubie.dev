<script lang="ts">
    export let data;
    import {
	    blur,
    } from 'svelte/transition';
</script>

<svelte:head>
<meta name="title" content={data.metadata.title}>
<meta name="description" content={data.metadata.description}>
<meta name="keywords" content={data.metadata.tags}>
<meta name="robots" content="index, follow">
<meta name="language" content="English">
<meta property="og:title" content={data.metadata.title} />
<meta property="og:description" content={data.metadata.description} />
<meta property="og:image" content="https://yubie.dev/meta/og.png" />
<meta property="og:type" content="article" />
</svelte:head>

<div class="flex justify-center items-start p-5 md:p-0 md:pb-10 w-full" in:blur>
    <article class="prose prose-sm md:prose-lg lg:prose-xl w-full ">
        <div class="text-4xl font-bold">
            {data.metadata.title}
        </div>
        <div class="text-lg pb-10">
            Published {data.metadata.date} - {data.metadata.readingTime.text} - written by {data.metadata.author}
        </div>

        <svelte:component this={data.content} />
    </article>
</div>