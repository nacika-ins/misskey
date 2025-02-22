<template>
  <MkStickyContainer>
    <template #header>
      <XPageHeader
        :online-user-count="onlineUserCount"
        :group-users="groupUsers"
        :group-owner-id="groupOwnerId"
        :is-pinned="isPinned"
        :on-set-pinned="onSetPinned"
      />
    </template>
    <div ref="rootEl" :class="$style['root']" @dragover.prevent.stop="onDragover" @drop.prevent.stop="onDrop">
      <div :class="$style['body']">
        <XPagination
          v-if="pagination"
          ref="pagingComponent"
          :key="userAcct || groupId"
          :pagination="pagination"
          :is-first-fetch="isFirstFetch"
          :display-limit="1000"
          :on-first-fetch="onFirstFetch"
        >
          <template #empty>
            <div class="_fullinfo">
              <img src="/assets/error.png" class="_ghost" />
              <div>{{ i18n.ts.noMessagesYet }}</div>
            </div>
          </template>
          <template #default="{ items: messages, fetching: pFetching }">
            <MkDateSeparatedList
              v-if="messages.length > 0"
              v-slot="{ item: message }"
              :class="{
                [$style['messages']]: true,
                [$style['opacity-0']]: isFirstFetch,
                'deny-move-transition': pFetching,
              }"
              :items="messages"
              direction="up"
              reversed
            >
              <XMessage
                :key="message.id"
                :message="message"
                :is-group="group != null"
                :is-admin="isAdmin"
                :context-disposes="contextDisposes"
                :on-set-context-disposes="onSetContextDisposes"
              />
            </MkDateSeparatedList>
          </template>
        </XPagination>
      </div>
      <footer :class="$style['footer']">
        <div v-if="typers.length > 0" :class="$style['typers']">
          <I18n :src="i18n.ts.typingUsers" text-tag="span">
            <template #users>
              <b v-for="typer in typers" :key="typer.id" :class="$style['user']">
                <MkUserName class="name" :user="typer" />
              </b>
            </template>
          </I18n>
          <MkEllipsis />
        </div>
        <Transition :name="animation ? 'fade' : ''">
          <div v-show="showIndicator" :class="$style['new-message']">
            <button class="_buttonPrimary" :class="$style['new-message-button']" @click="onIndicatorClick">
              <i class="fas ti-fw fa-arrow-circle-down" :class="$style['new-message-icon']"></i
              >{{ i18n.ts.newMessageExists }}
            </button>
          </div>
        </Transition>
        <XForm ref="formEl" :user="user" :group="group" :class="$style['form']" />
      </footer>
    </div>
  </MkStickyContainer>
</template>

<script lang="ts" setup>
import { computed, watch, onMounted, nextTick, onBeforeUnmount, onActivated, onDeactivated } from 'vue';
import * as Misskey from 'misskey-js';
import { acct as Acct } from 'misskey-js';
import debounce from 'lodash/debounce';
import { User } from 'misskey-js/built/dts/autogen/models';
import XMessage from './messaging-room.message.vue';
import XForm from './messaging-room.form.vue';
import XPageHeader from './messaging-room.header.vue';
import XPagination, { Paging } from './messaging-room.pagination.vue';
import MkDateSeparatedList from '@/components/MkDateSeparatedList.vue';
import { onScrollBottom, scrollToBottomForWindow } from '@/scripts/scroll';
import * as os from '@/os';
import { stream } from '@/stream';
import * as sound from '@/scripts/sound';
import { i18n } from '@/i18n';
import { $i } from '@/account';
import { defaultStore } from '@/store';
import { definePageMetadata } from '@/scripts/page-metadata';

const props = defineProps<{
  userAcct?: string;
  groupId?: string;
}>();

// @ts-ignore
let rootEl = $shallowRef<HTMLDivElement>();
// @ts-ignore
let formEl = $shallowRef<InstanceType<typeof XForm>>();
// @ts-ignore
let pagingComponent = $shallowRef<InstanceType<typeof XPagination>>();
// @ts-ignore

let isFirstFetch = $ref(true);
let finishFirstFetch = debounce(() => {
  if (location.href.includes('/my/messaging/')) {
    console.debug('thisScrollToBottom SCROLL008');
    thisScrollToBottom({ behavior: 'instant' });
  }
  console.debug('初回ローディング完了');
  isFirstFetch = false;
}, 500);

let fetching = $ref(true);
// @ts-ignore
let user: Misskey.entities.UserDetailed | null = $ref(null);
// @ts-ignore
let group: Misskey.entities.UserGroup | null = $ref(null);
let isAdmin = $computed(() => {
  return group?.ownerId === $i?.id;
});
// @ts-ignore
let typers: Misskey.entities.User[] = $ref([]);
// @ts-ignore
let connection: Misskey.ChannelConnection<Misskey.Channels['messaging']> | null = $ref(null);
// @ts-ignore
let showIndicator = $ref(false);

let contextDisposes = $ref<Promise<() => void>[]>([]);

let isPinned = $ref(false);
let onlineUserCount = $ref(0);
let groupUsers = $ref([]);
let groupOwnerId = $computed(() => {
  return group?.ownerId;
});

watch(
  () => group,
  async () => {
    if (!group) {
      return 0;
    }
    const userIds: string[] = Array.from(new Set(group.userIds));
    const users: User[] = Array.from(
      new Map(
        (
          await os.api('users/show', {
            userIds,
          })
        ).map((u) => [u.id, u]),
      ).values(),
    ).sort((a, b) => {
      // @ts-ignore
      if (a.id === group?.ownerId || b.id === group?.ownerId) {
        // @ts-ignore
        return a.id === group?.ownerId ? -1 : 1;
      }
      // @ts-ignore
      return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
    }) as User[];
    // @ts-ignore
    groupUsers = users;
    onlineUserCount = users.filter((_user) => _user.onlineStatus === 'online').length;
    return 0;
  },
);

const { animation } = defaultStore.reactiveState;

// @ts-ignore
let pagination: Paging | null = $ref(null);

watch([() => props.userAcct, () => props.groupId], () => {
  if (connection) connection.dispose();
  fetch();
});

watch(
  () => isPinned,
  async () => {
    isFirstFetch = true;
    nextTick(async () => {
      if (connection) connection.dispose();
      await fetch();
      pagingComponent?.reload();
    });
  },
);

async function fetch() {
  console.log('fetch');

  fetching = true;

  if (props.userAcct) {
    const acct = Acct.parse(props.userAcct);
    user = await os.api('users/show', { username: acct.username, host: acct.host || undefined });
    group = null;

    pagination = {
      // @ts-ignore
      endpoint: 'messaging/messages',
      limit: 40,
      params: {
        // @ts-ignore
        userId: user.id,
        isPinned,
      },
      reversed: true,
      // @ts-ignore
      pageEl: $$(rootEl).value,
    };

    if (connection) connection.dispose();

    // @ts-ignore
    connection = stream.useChannel('messaging', {
      // @ts-ignore
      otherparty: user.id,
    });
  } else {
    user = null;
    group = await os.api('users/groups/show', { groupId: props.groupId });

    pagination = {
      // @ts-ignore
      endpoint: 'messaging/messages',
      limit: 40,
      params: {
        groupId: group?.id,
        isPinned,
      },
      reversed: true,
      // @ts-ignore
      pageEl: $$(rootEl).value,
    };

    if (connection) connection.dispose();

    // @ts-ignore
    connection = stream.useChannel('messaging', {
      group: group?.id,
    });
  }
  connection.on('message', onMessage);
  connection.on('updated', onUpdated);
  connection.on('read', onRead);
  connection.on('deleted', onDeleted);
  connection.on('typers', (_typers) => {
    typers = _typers.filter((u) => u.id !== $i?.id);
  });

  document.addEventListener('visibilitychange', onVisibilitychange);
}

/**
 * 初回読み込み完了
 */
const onFirstFetch = () => {
  console.debug('onFirstFetch');

  nextTick(() => {
    const url = new URL(location.href);

    if (
      url.pathname === `/my/messaging/group/${group?.id}` ||
      url.pathname === `/my/messaging/${user?.username}` ||
      url.pathname === `/my/messaging/${user?.username}@${user?.host}`
    ) {
      // @ts-ignore
      pagingComponent.inited.then(() => {
        console.debug('thisScrollToBottom SCROLL009');
        thisScrollToBottom({ behavior: isFirstFetch ? 'instant' : 'smooth' });
      });
    }

    fetching = false;
    if (isFirstFetch) finishFirstFetch();
  });
};

function onDragover(ev: DragEvent) {
  if (!ev.dataTransfer) return;

  const isFile = ev.dataTransfer.items[0].kind === 'file';
  const isDriveFile = ev.dataTransfer.types[0] === _DATA_TRANSFER_DRIVE_FILE_;

  if (isFile || isDriveFile) {
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
  } else {
    ev.dataTransfer.dropEffect = 'none';
  }
}

function onDrop(ev: DragEvent): void {
  if (!ev.dataTransfer) return;

  // ファイルだったら
  if (ev.dataTransfer.files.length === 1) {
    // @ts-ignore
    formEl.upload(ev.dataTransfer.files[0]);
    return;
  } else if (ev.dataTransfer.files.length > 1) {
    os.alert({
      type: 'error',
      text: i18n.ts.onlyOneFileCanBeAttached,
    });
    return;
  }

  //#region ドライブのファイル
  const driveFile = ev.dataTransfer.getData(_DATA_TRANSFER_DRIVE_FILE_);
  if (driveFile != null && driveFile !== '') {
    const file = JSON.parse(driveFile);
    // @ts-ignore
    formEl.file = file;
  }
  //#endregion
}

/**
 * メッセージを受信
 */
function onMessage(message) {
  sound.play('chat');

  console.debug(
    'document.body.scrollHeight - window.innerHeight - window.scrollY =',
    document.body.scrollHeight - window.innerHeight - window.scrollY,
  );
  const _isBottom = document.body.scrollHeight - window.innerHeight - window.scrollY <= 40;
  console.debug('[chat] _isBottom =', _isBottom);

  // ピン留めモードの時は追加しない
  if (!isPinned) {
    // @ts-ignore
    pagingComponent.prepend(message);
    if (message.userId !== $i?.id && !document.hidden) {
      connection?.send('read', {
        id: message.id,
      });
    }
  }

  const url = new URL(location.href);

  console.debug('url.pathname =', url.pathname);
  console.debug('user =', user);

  const isCurrentPage =
    url.pathname === `/my/messaging/group/${group?.id}` ||
    url.pathname === `/my/messaging/${user?.username}` ||
    url.pathname === `/my/messaging/${user?.username}@${user?.host}`;
  console.debug('isCurrentPage =', isCurrentPage);

  if (_isBottom && isCurrentPage) {
    // Scroll to bottom
    nextTick(() => {
      console.debug('thisScrollToBottom SCROLL010');
      thisScrollToBottom({ behavior: 'smooth' });
    });
  } else if (message.userId !== $i?.id) {
    // Notify
    notifyNewMessage();
  } else {
    console.debug('[chat] Not notify');
  }
}

/**
 * メッセージを更新
 */
function onUpdated(message) {
  if (!message) return;
  const id = message.id;

  // @ts-ignore
  if (pagingComponent.items.some((y) => y.id === id)) {
    // @ts-ignore
    const exist = pagingComponent.items.map((y) => y.id).indexOf(id);
    // @ts-ignore
    pagingComponent.items[exist] = {
      // @ts-ignore
      ...pagingComponent.items[exist],
      // @ts-ignore
      isPinned: message.isPinned,
    };
  }
}

function onRead(x) {
  if (user) {
    if (!Array.isArray(x)) x = [x];
    for (const id of x) {
      // @ts-ignore
      if (pagingComponent.items.some((y) => y.id === id)) {
        // @ts-ignore
        const exist = pagingComponent.items.map((y) => y.id).indexOf(id);
        // @ts-ignore
        pagingComponent.items[exist] = {
          // @ts-ignore
          ...pagingComponent.items[exist],
          isRead: true,
        };
      }
    }
  } else if (group) {
    for (const id of x.ids) {
      // @ts-ignore
      if (pagingComponent.items.some((y) => y.id === id)) {
        // @ts-ignore
        const exist = pagingComponent.items.map((y) => y.id).indexOf(id);
        // @ts-ignore
        pagingComponent.items[exist] = {
          // @ts-ignore
          ...pagingComponent.items[exist],
          // @ts-ignore
          reads: [...pagingComponent.items[exist].reads, x.userId],
        };
      }
    }
  }
}

/**
 * メッセージの削除
 */
function onDeleted(id) {
  // @ts-ignore
  const msg = pagingComponent.items.find((m) => m.id === id);
  if (msg) {
    // @ts-ignore
    pagingComponent.items = pagingComponent.items.filter((m) => m.id !== msg.id);
  }
}

function thisScrollToBottom(option: ScrollToOptions = { behavior: 'smooth' }) {
  console.debug('scrollToBottomForWindow SCROLL003');
  scrollToBottomForWindow({
    ...option,
    behavior: option.behavior,
  });
}

function onIndicatorClick() {
  showIndicator = false;
  console.debug('thisScrollToBottom SCROLL012');
  thisScrollToBottom({ behavior: 'smooth' });
}

let scrollRemove: (() => void) | null = $ref(null);

function notifyNewMessage() {
  console.debug('[chat] notifyNewMessage');
  showIndicator = true;

  // @ts-ignore
  scrollRemove = onScrollBottom(rootEl, () => {
    console.debug('[chat] onScrollBottom');

    const url = new URL(location.href);
    const isCurrentPage =
      url.pathname === `/my/messaging/group/${group?.id}` ||
      url.pathname === `/my/messaging/${user?.username}` ||
      url.pathname === `/my/messaging/${user?.username}@${user?.host}`;
    if (!isCurrentPage) return;

    showIndicator = false;
    scrollRemove = null;
  });
}

function onVisibilitychange() {
  if (document.hidden) return;
  // @ts-ignore
  for (const message of pagingComponent.items) {
    if (message.userId !== $i?.id && !message.isRead) {
      connection?.send('read', {
        id: message.id,
      });
    }
  }
}

function onSetPinned(_isPinned: boolean) {
  isPinned = _isPinned;
}

function onSetContextDisposes(disposes: Promise<() => void>[]) {
  contextDisposes = disposes;
}

onMounted(async () => {
  await fetch();
});

onActivated(async () => {
  if (isFirstFetch) return;
  isFirstFetch = true;
  if (pagingComponent) {
    if (connection) connection.dispose();
    await fetch();
    pagingComponent.reload();
  }
});

onDeactivated(() => {
  connection?.dispose();
  document.removeEventListener('visibilitychange', onVisibilitychange);
  if (scrollRemove) scrollRemove();
});

onBeforeUnmount(() => {
  connection?.dispose();
  document.removeEventListener('visibilitychange', onVisibilitychange);
  if (scrollRemove) scrollRemove();
});

definePageMetadata(
  // @ts-ignore
  computed(() =>
    !fetching
      ? user
        ? {
            userName: user,
            avatar: user,
            icon: 'ti ti-user',
          }
        : {
            title: group?.name,
            icon: 'ti ti-messages',
          }
      : null,
  ),
);
</script>

<style lang="scss" module>
.root {
  // @ts-ignore
  display: contents;
}

//noinspection CssOverwrittenProperties
.body {
  min-height: calc(100svh - 275px);
}

.more {
  display: block;
  margin: 16px auto;
  padding: 0 12px;
  line-height: 24px;
  color: #fff;
  background: rgba(#000, 0.3);
  border-radius: 12px;

  &:hover {
    background: rgba(#000, 0.4);
  }

  &:active {
    background: rgba(#000, 0.5);
  }

  > i {
    margin-right: 4px;
  }
}

.fetching {
  cursor: wait;
}

.messages {
  padding: 16px 0 0;

  > * {
    margin-bottom: 16px;
  }
}

.opacity-0 {
  opacity: 0;
}

.footer {
  width: 100%;
  position: sticky;
  z-index: 2;
  padding-top: 8px;
  bottom: var(--minBottomSpacing);
}

.new-message {
  width: 100%;
  padding-bottom: 8px;
  text-align: center;
}

.new-message-button {
  display: inline-block;
  margin: 0;
  padding: 0 12px;
  line-height: 32px;
  font-size: 12px;
  border-radius: 16px;
}

.new-message-icon {
  display: inline-block;
  margin-right: 8px;
}

.typers {
  position: absolute;
  bottom: 100%;
  padding: 0 8px 0 8px;
  font-size: 0.9em;
  color: var(--fgTransparentWeak);
}

.user + .user:before {
  content: ', ';
  font-weight: normal;
}

.user:last-of-type:after {
  content: ' ';
}

.form {
  max-height: 12em;
  overflow-y: scroll;
  border-top: solid 0.5px var(--divider);
  border-bottom-left-radius: 0;
  border-bottom-right-radius: 0;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.1s;
}

.fade-enter-from,
.fade-leave-to {
  transition: opacity 0.5s;
  opacity: 0;
}
</style>
