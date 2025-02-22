// test is located in test/extract-mentions

import * as mfm from 'mfm-js';

export function extractMentions(nodes: mfm.MfmNode[]): mfm.MfmMention['props'][] {
	// TODO: 重複を削除
	const mentionNodes = mfm.extract(nodes, (node) => node.type === 'mention') as mfm.MfmMention[];
	const mentions = mentionNodes.map(x => x.props);

	// @ts-ignore
	return mentions;
}
