import * as Misskey from 'misskey-js';
import { markRaw } from 'vue';
import { $i } from '@/account';
import { url } from '@/config';

export const stream = markRaw(new Misskey.Stream(url, $i ? {
	// @ts-ignore
	token: $i.token,
} : null));
