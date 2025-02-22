<template>
  <div :class="$style['root']" @dragover.stop="onDragover" @drop.stop="onDrop">
    <textarea
      ref="textEl"
      v-model="text"
      :class="$style['textarea']"
      class="_acrylic"
      :placeholder="i18n.ts.inputMessageHere"
      @keydown="onKeydown"
      @compositionupdate="onCompositionUpdate"
      @paste="onPaste"
    ></textarea>
    <footer :class="$style['footer']">
      <div v-if="file" :class="$style['file']" @click="file = null">{{ file.name }}</div>
      <div :class="$style['buttons']">
        <button class="_button" :class="$style['button']" @click="chooseFile"><i class="ti ti-photo-plus"></i></button>
        <button class="_button" :class="$style['button']" @click="insertEmoji"><i class="ti ti-mood-happy"></i></button>
        <button
          id="message-post__button"
          class="_button"
          :class="[$style['button'], $style['send']]"
          :disabled="!canSend || sending"
          :title="i18n.ts.send"
          @click="send"
        >
          <template v-if="!sending"><i class="ti ti-send"></i></template
          ><template v-if="sending"><MkLoading :em="true" /></template>
        </button>
      </div>
    </footer>
    <input ref="fileEl" :class="$style['file-input']" type="file" @change="onChangeFile" />
  </div>
</template>

<script lang="ts" setup>
import { nextTick, onActivated, onMounted, watch } from 'vue';
import * as Misskey from 'misskey-js';
//import insertTextAtCursor from 'insert-text-at-cursor';
import { throttle } from 'throttle-debounce';
import { retry } from 'ts-retry-promise';
import { formatTimeString } from '@/scripts/format-time-string';
import { selectFile } from '@/scripts/select-file';
import * as os from '@/os';
import { stream } from '@/stream';
import { defaultStore } from '@/store';
import { i18n } from '@/i18n';
//import { Autocomplete } from '@/scripts/autocomplete';
import { uploadFile } from '@/scripts/upload';
import { miLocalStorage } from '@/local-storage';

const props = defineProps<{
  user?: Misskey.entities.UserDetailed | null;
  group?: Misskey.entities.UserGroup | null;
}>();

let textEl = $shallowRef<HTMLTextAreaElement>();
let fileEl = $shallowRef<HTMLInputElement>();

let text = $ref<string>('');
let file = $ref<Misskey.entities.DriveFile | null>(null);
let sending = $ref(false);
const typing = throttle(3000, () => {
  stream.send('typingOnMessaging', props.user ? { partner: props.user.id } : { group: props.group?.id });
});

let draftKey = $ref<string | null>(null);

// ドラフトキーの更新と下書きの復元
watch([$$(props)], () => {
  draftKey = props.user ? `user-${props.user.id}` : props.group ? `group-${props.group.id}` : null;
  nextTick(() => {
    restoreDraft();
  });
});

let canSend = $computed(() => (text != null && text !== '') || file != null);

// 下書き保存
watch([$$(text), $$(file)], saveDraft);

/**
 * 貼り付け
 */
async function onPaste(ev: ClipboardEvent) {
  if (!ev.clipboardData) return;

  const clipboardData = ev.clipboardData;
  const items = clipboardData.items;

  if (items.length === 1) {
    if (items[0].kind === 'file') {
      const pastedFile = items[0].getAsFile();
      if (!pastedFile) return;
      const lio = pastedFile.name.lastIndexOf('.');
      const ext = lio >= 0 ? pastedFile.name.slice(lio) : '';
      const formatted =
        formatTimeString(new Date(pastedFile.lastModified), defaultStore.state.pastedFileName).replace(
          /{{number}}/g,
          '1',
        ) + ext;
      if (formatted) upload(pastedFile, formatted);
    }
  } else {
    if (items[0].kind === 'file') {
      os.alert({
        type: 'error',
        text: i18n.ts.onlyOneFileCanBeAttached,
      });
    }
  }
}

/**
 * ドラッグオーバー
 */
function onDragover(ev: DragEvent) {
  if (!ev.dataTransfer) return;

  const isFile = ev.dataTransfer.items[0].kind === 'file';
  const isDriveFile = ev.dataTransfer.types[0] === _DATA_TRANSFER_DRIVE_FILE_;
  if (isFile || isDriveFile) {
    ev.preventDefault();
    switch (ev.dataTransfer.effectAllowed) {
      case 'all':
      case 'uninitialized':
      case 'copy':
      case 'copyLink':
      case 'copyMove':
        ev.dataTransfer.dropEffect = 'copy';
        break;
      case 'linkMove':
      case 'move':
        ev.dataTransfer.dropEffect = 'move';
        break;
      default:
        ev.dataTransfer.dropEffect = 'none';
        break;
    }
  }
}

/**
 * ドロップ
 */
function onDrop(ev: DragEvent): void {
  if (!ev.dataTransfer) return;

  // ファイルだったら
  if (ev.dataTransfer.files.length === 1) {
    ev.preventDefault();
    upload(ev.dataTransfer.files[0]);
    return;
  } else if (ev.dataTransfer.files.length > 1) {
    ev.preventDefault();
    os.alert({
      type: 'error',
      text: i18n.ts.onlyOneFileCanBeAttached,
    });
    return;
  }

  //#region ドライブのファイル
  const driveFile = ev.dataTransfer.getData(_DATA_TRANSFER_DRIVE_FILE_);
  if (driveFile != null && driveFile !== '') {
    file = JSON.parse(driveFile);
    ev.preventDefault();
  }
  //#endregion
}

/**
 * キー入力中
 */
function onKeydown(ev: KeyboardEvent) {
  typing();
  if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey) && canSend) {
    send();
  }
}

function onCompositionUpdate() {
  typing();
}

function chooseFile(ev: MouseEvent) {
  selectFile(ev.currentTarget ?? ev.target, i18n.ts.selectFile).then((selectedFile) => {
    file = selectedFile;
  });
}

function onChangeFile() {
  if (fileEl?.files?.[0]) upload(fileEl.files[0]);
}

function upload(fileToUpload: File, name?: string) {
  uploadFile(fileToUpload, defaultStore.state.uploadFolder, name).then((res) => {
    file = res;
  });
}

/**
 * メッセージ送信
 */
function send() {
  sending = true;
  retry(
    () =>
      os
        .api('messaging/messages/create', {
          userId: props.user ? props.user.id : undefined,
          groupId: props.group ? props.group.id : undefined,
          text: text ? text : undefined,
          fileId: file ? file.id : undefined,
        })
        .then(() => {
          clear();
        })
        .catch((err) => {
          console.error(err);
          throw err;
        })
        .finally(() => {
          sending = false;
        }),
    {
      retries: 3,
      backoff: 'LINEAR',
      delay: 1000,
    },
  );
}

/**
 * 中身のクリア
 */
function clear() {
  text = '';
  file = null;
  deleteDraft();
}

/**
 * 下書き保存
 */
function saveDraft() {
  if (!draftKey) return;
  const drafts = JSON.parse(miLocalStorage.getItem('message_drafts') || '{}');

  drafts[draftKey] = {
    updatedAt: new Date(),
    // eslint-disable-next-line id-denylist
    data: {
      text: text,
      file: file,
    },
  };
  miLocalStorage.setItem('message_drafts', JSON.stringify(drafts));
}

/**
 * 下書き削除
 */
function deleteDraft() {
  if (!draftKey) return;
  const drafts = JSON.parse(miLocalStorage.getItem('message_drafts') || '{}');

  delete drafts[draftKey];

  miLocalStorage.setItem('message_drafts', JSON.stringify(drafts));
}

/**
 * 下書きの復旧
 */
function restoreDraft() {
  if (!draftKey) return;
  const draft = JSON.parse(miLocalStorage.getItem('message_drafts') || '{}')[draftKey];
  if (draft) {
    text = draft.data.text;
    file = draft.data.file;
  }
}

async function insertEmoji(ev: MouseEvent) {
  // @ts-ignore
  os.openEmojiPicker(ev.currentTarget ?? ev.target, {}, textEl);
}

let isFirst = $ref(true);

onMounted(() => {
  restoreDraft();
  isFirst = false;
});

onActivated(() => {
  if (isFirst) return;
  restoreDraft();
});

defineExpose({
  file,
  upload,
});
</script>

<style lang="scss" module>
.root {
  position: relative;
}

.textarea {
  cursor: auto;
  display: block;
  width: 100%;
  min-width: 100%;
  max-width: 100%;
  min-height: 80px;
  height: 80px;
  max-height: 80px;
  margin: 0;
  padding: 16px 16px 0 16px;
  resize: none;
  font-size: 1em;
  font-family: inherit;
  outline: none;
  border: none;
  border-radius: 0;
  box-shadow: none;
  box-sizing: border-box;
  color: var(--fg);
  overflow-x: hidden !important;
}

.footer {
  position: sticky;
  bottom: 0;
  background: var(--panel);
}

.file {
  padding: 8px;
  color: var(--fg);
  background: transparent;
  cursor: pointer;
}
/*
.files {
	display: block;
	margin: 0;
	padding: 0 8px;
	list-style: none;

	&:after {
		content: '';
		display: block;
		clear: both;
	}

	> li {
		display: block;
		float: left;
		margin: 4px;
		padding: 0;
		width: 64px;
		height: 64px;
		background-color: #eee;
		background-repeat: no-repeat;
		background-position: center center;
		background-size: cover;
		cursor: move;

		&:hover {
			> .remove {
				display: block;
			}
		}
	}
}

.file-remove {
	display: none;
	position: absolute;
	right: -6px;
	top: -6px;
	margin: 0;
	padding: 0;
	background: transparent;
	outline: none;
	border: none;
	border-radius: 0;
	box-shadow: none;
	cursor: pointer;
}
*/

.buttons {
  display: flex;
}

.button {
  margin: 0;
  padding: 16px;
  font-size: 1em;
  font-weight: normal;
  text-decoration: none;
  transition: color 0.1s ease;

  &:hover {
    color: var(--accent);
  }

  &:active {
    color: var(--accentDarken);
    transition: color 0s ease;
  }
}
.send {
  margin-left: auto;
  color: var(--accent);

  &:hover {
    color: var(--accentLighten);
  }

  &:active {
    color: var(--accentDarken);
    transition: color 0s ease;
  }
}

.file-input {
  display: none;
}
</style>
