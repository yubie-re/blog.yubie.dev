<script lang="ts">
    export let data;
    import {
	    blur,
    } from 'svelte/transition';
</script>

<svelte:head>
<title>{data.metadata.title}</title>
<meta name="title" content={data.metadata.title} />
<meta name="description" content={data.metadata.description} />
<meta name="keywords" content={data.metadata.tags}>


<!-- Open Graph / Facebook -->
<meta property="og:type" content="article" />
<meta property="og:url" content={"https://blog.yubie.dev/blog/" + data.slug} />
<meta property="og:title" content={data.metadata.title} />
<meta property="og:description" content={data.metadata.description} />
<meta property="og:image" content="https://blog.yubie.dev/meta/og.png" />

<!-- Twitter -->
<meta property="twitter:card" content="summary_large_image" />
<meta property="twitter:url" content={"https://blog.yubie.dev/blog/" + data.slug} />
<meta property="twitter:title" content={data.metadata.title} />
<meta property="twitter:description" content={data.metadata.description} />
<meta property="twitter:image" content="https://blog.yubie.dev/meta/og.png" />
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