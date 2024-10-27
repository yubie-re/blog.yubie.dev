<script lang="ts">
    export let data;
</script>
<div class="flex justify-center pb-10">
    <div class="prose prose-lg">
    <div class="text-2xl font-bold">
        {data.title}
    </div>
    <div class="text-lg italic pb-10">
        Published {data.date}
    </div>


        <svelte:component this={data.content} />
    </div>
</div>
