<template>
<MkStickyContainer>
	<template #header><MkPageHeader v-model:tab="tab" :actions="headerActions" :tabs="headerTabs"/></template>
	<MkSpacer :content-max="700">
		<div v-if="tab === 'my'" class="_gaps">
			<MkButton primary rounded class="add" @click="create"><i class="ti ti-plus"></i> {{ i18n.ts.add }}</MkButton>

			<MkPagination v-slot="{items}" ref="pagingComponent" :pagination="pagination" class="_gaps">
				<MkA v-for="item in items" :key="item.id" :to="`/clips/${item.id}`">
					<MkClipPreview :clip="item"/>
				</MkA>
			</MkPagination>
		</div>
		<div v-else-if="tab === 'favorites'" class="_gaps">
			<MkA v-for="item in favorites" :key="item.id" :to="`/clips/${item.id}`">
				<MkClipPreview :clip="item"/>
			</MkA>
		</div>
	</MkSpacer>
</MkStickyContainer>
</template>

<script lang="ts" setup>
import { watch } from 'vue';
import MkPagination from '@/components/MkPagination.vue';
import MkButton from '@/components/MkButton.vue';
import MkClipPreview from '@/components/MkClipPreview.vue';
import * as os from '@/os';
import { i18n } from '@/i18n';
import { definePageMetadata } from '@/scripts/page-metadata';

const pagination = {
	endpoint: 'clips/list' as const,
	limit: 10,
};

let tab = $ref('my');
let favorites = $ref();

const pagingComponent = $shallowRef<InstanceType<typeof MkPagination>>();

watch($$(tab), async () => {
	favorites = await os.api('clips/my-favorites');
});

async function create() {
	const { canceled, result } = await os.form(i18n.ts.createNewClip, {
		name: {
			type: 'string',
			label: i18n.ts.name,
		},
		description: {
			type: 'string',
			required: false,
			multiline: true,
			label: i18n.ts.description,
		},
		isPublic: {
			type: 'boolean',
			label: i18n.ts.public,
			default: false,
		},
	});
	if (canceled) return;

	os.apiWithDialog('clips/create', result);

	pagingComponent.reload();
}

function onClipCreated() {
	pagingComponent.reload();
}

function onClipDeleted() {
	pagingComponent.reload();
}

const headerActions = $computed(() => []);

const headerTabs = $computed(() => [{
	key: 'my',
	title: i18n.ts.myClips,
	icon: 'ti ti-paperclip',
}, {
	key: 'favorites',
	title: i18n.ts.favorites,
	icon: 'ti ti-heart',
}]);

definePageMetadata({
	title: i18n.ts.clip,
	icon: 'ti ti-paperclip',
	action: {
		icon: 'ti ti-plus',
		handler: create,
	},
});
</script>

<style lang="scss" module>

</style>
