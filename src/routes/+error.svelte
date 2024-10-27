<script>
	import { page } from '$app/stores';
</script>
<div class="px-10">
    <div class="text-2xl font-bold">
        <h1>{$page.status}</h1>
    </div>
    <h1>{$page.error?.message}</h1>
</div>