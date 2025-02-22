<!--
SPDX-FileCopyrightText: syuilo and other misskey contributors
SPDX-License-Identifier: AGPL-3.0-only
-->

<template>
  <div :class="[$style.root, hideTopRound ? $style.hideTopRound : null]">
    <MkMediaAudio
      v-if="media.type.startsWith('audio') && media.type !== 'audio/midi'"
      :audio="media"
      :hide-top-round="hideTopRound"
      :use-bg="useBg"
    />
    <div v-else-if="media.isSensitive && hide" :class="$style.sensitive" @click="hide = false">
      <span style="font-size: 1.6em"><i class="ti ti-alert-triangle"></i></span>
      <b>{{ i18n.ts.sensitive }}</b>
      <span>{{ i18n.ts.clickToShow }}</span>
    </div>
    <a v-else :class="$style.download" :href="media.url" :title="media.name" :download="media.name">
      <span style="font-size: 1.6em"><i class="ti ti-download"></i></span>
      <b>{{ media.name }}</b>
    </a>
  </div>
</template>

<script lang="ts" setup>
import { shallowRef, watch, ref } from 'vue';
import * as Misskey from 'misskey-js';
import { i18n } from '@/i18n.js';
import MkMediaAudio from '@/components/MkMediaAudio.vue';

const props = withDefaults(
  defineProps<{
    media: Misskey.entities.DriveFile;
    hideTopRound?: boolean;
    useBg?: boolean;
  }>(),
  {},
);

const audioEl = shallowRef<HTMLAudioElement>();
const hide = ref(true);

watch(audioEl, () => {
  if (audioEl.value) {
    audioEl.value.volume = 0.3;
  }
});
</script>

<style lang="scss" module>
.root {
  width: 100%;
  border-radius: 4px;
  margin-top: 4px;
  overflow: clip;
}

.hideTopRound {
  border-top-left-radius: 0;
  border-top-right-radius: 0;
}

.download,
.sensitive {
  display: flex;
  align-items: center;
  font-size: 12px;
  padding: 8px 12px;
  white-space: nowrap;
}

.download {
  background: var(--noteAttachedFile);
}

.sensitive {
  background: #111;
  color: #fff;
}

.audio {
  border-radius: 8px;
  overflow: clip;
}
</style>
