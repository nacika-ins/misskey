<template>
  <MkPagination :pagination="pagination">
    <template #empty>
      <div class="_fullinfo">
        <img src="/assets/error.png" class="_ghost" />
        <div>{{ i18n.ts.noUsers }}</div>
      </div>
    </template>

    <template #default="{ items }">
      <div class="efvhhmdq">
        <MkUserInfo v-for="item in items" :key="item.id" class="user" :user="extractor(item)" />
      </div>
    </template>
  </MkPagination>
</template>

<script lang="ts" setup>
import MkUserInfo from '@/components/MkUserInfo.vue';
import MkPagination, { Paging } from '@/components/MkPagination.vue';
import { i18n } from '@/i18n';

const props = withDefaults(
  defineProps<{
    pagination: Paging;
    noGap?: boolean;
    extractor?: (item: any) => any;
  }>(),
  {
    extractor: (item) => item,
  },
);
</script>

<style lang="scss" scoped>
.efvhhmdq {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  grid-gap: var(--margin);
}
</style>
