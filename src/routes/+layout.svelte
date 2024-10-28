<script>
	import '../app.css';
	import GithubIcon from '~icons/mdi/github';
	import Typewriter from 'svelte-typewriter';
</script>

<div class="p-10">
	<div class="flex flex-col items-center text-center">
		<Typewriter>
			<a href="/">
				<h2 class="text-3xl font-bold tracking-tight">blog.yubie.dev</h2>
			</a>
			<h2 class="italic">A blog of interesting things I've encountered</h2>
		</Typewriter>
		<a href="https://github.com/yubie-re" class="text-2xl">
			<GithubIcon/>
		</a>
	</div>
</div>

<div>
	<slot></slot>
</div>
