<template>
  <div>
    <MkStickyContainer>
      <template #header><XHeader :actions="headerActions" :tabs="headerTabs" /></template>
      <MkSpacer :content-max="700">
        <div class="_gaps">
          <MkFolder>
            <template #label>{{ i18n.ts._role.baseRole }}</template>
            <div class="_gaps_s">
              <MkInput v-model="baseRoleQ" type="search">
                <template #prefix><i class="ti ti-search"></i></template>
              </MkInput>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.rateLimitFactor, 'rateLimitFactor'])">
                <template #label>{{ i18n.ts._role._options.rateLimitFactor }}</template>
                <template #suffix>{{ Math.floor(policies.rateLimitFactor * 100) }}%</template>
                <MkRange
                  :model-value="policies.rateLimitFactor * 100"
                  :min="30"
                  :max="300"
                  :step="10"
                  :text-converter="(v) => `${v}%`"
                  @update:model-value="(v) => (policies.rateLimitFactor = v / 100)"
                >
                  <template #caption>{{ i18n.ts._role._options.descriptionOfRateLimitFactor }}</template>
                </MkRange>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.gtlAvailable, 'gtlAvailable'])">
                <template #label>{{ i18n.ts._role._options.gtlAvailable }}</template>
                <template #suffix>{{ policies.gtlAvailable ? i18n.ts.yes : i18n.ts.no }}</template>
                <MkSwitch v-model="policies.gtlAvailable">
                  <template #label>{{ i18n.ts.enable }}</template>
                </MkSwitch>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.ltlAvailable, 'ltlAvailable'])">
                <template #label>{{ i18n.ts._role._options.ltlAvailable }}</template>
                <template #suffix>{{ policies.ltlAvailable ? i18n.ts.yes : i18n.ts.no }}</template>
                <MkSwitch v-model="policies.ltlAvailable">
                  <template #label>{{ i18n.ts.enable }}</template>
                </MkSwitch>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.canNote, 'canNote'])">
                <template #label>{{ i18n.ts._role._options.canNote }}</template>
                <template #suffix>{{ policies.canNote ? i18n.ts.yes : i18n.ts.no }}</template>
                <MkSwitch v-model="policies.canNote">
                  <template #label>{{ i18n.ts.enable }}</template>
                </MkSwitch>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.canPublicNote, 'canPublicNote'])">
                <template #label>{{ i18n.ts._role._options.canPublicNote }}</template>
                <template #suffix>{{ policies.canPublicNote ? i18n.ts.yes : i18n.ts.no }}</template>
                <MkSwitch v-model="policies.canPublicNote">
                  <template #label>{{ i18n.ts.enable }}</template>
                </MkSwitch>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.canInvite, 'canInvite'])">
                <template #label>{{ i18n.ts._role._options.canInvite }}</template>
                <template #suffix>{{ policies.canInvite ? i18n.ts.yes : i18n.ts.no }}</template>
                <MkSwitch v-model="policies.canInvite">
                  <template #label>{{ i18n.ts.enable }}</template>
                </MkSwitch>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.canManageCustomEmojis, 'canManageCustomEmojis'])">
                <template #label>{{ i18n.ts._role._options.canManageCustomEmojis }}</template>
                <template #suffix>{{ policies.canManageCustomEmojis ? i18n.ts.yes : i18n.ts.no }}</template>
                <MkSwitch v-model="policies.canManageCustomEmojis">
                  <template #label>{{ i18n.ts.enable }}</template>
                </MkSwitch>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.canSearchNotes, 'canSearchNotes'])">
                <template #label>{{ i18n.ts._role._options.canSearchNotes }}</template>
                <template #suffix>{{ policies.canSearchNotes ? i18n.ts.yes : i18n.ts.no }}</template>
                <MkSwitch v-model="policies.canSearchNotes">
                  <template #label>{{ i18n.ts.enable }}</template>
                </MkSwitch>
              </MkFolder>

              <MkFolder
                v-if="matchQuery([i18n.ts._role._options.suspendUponAccountDeletion, 'suspendUponAccountDeletion'])"
              >
                <template #label>{{ i18n.ts._role._options.suspendUponAccountDeletion }}</template>
                <template #suffix>{{ policies.suspendUponAccountDeletion ? i18n.ts.yes : i18n.ts.no }}</template>
                <MkSwitch v-model="policies.suspendUponAccountDeletion">
                  <template #label>{{ i18n.ts.enable }}</template>
                </MkSwitch>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.driveCapacity, 'driveCapacityMb'])">
                <template #label>{{ i18n.ts._role._options.driveCapacity }}</template>
                <template #suffix>{{ policies.driveCapacityMb }}MB</template>
                <MkInput v-model="policies.driveCapacityMb" type="number">
                  <template #suffix>MB</template>
                </MkInput>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.pinMax, 'pinLimit'])">
                <template #label>{{ i18n.ts._role._options.pinMax }}</template>
                <template #suffix>{{ policies.pinLimit }}</template>
                <MkInput v-model="policies.pinLimit" type="number"> </MkInput>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.antennaMax, 'antennaLimit'])">
                <template #label>{{ i18n.ts._role._options.antennaMax }}</template>
                <template #suffix>{{ policies.antennaLimit }}</template>
                <MkInput v-model="policies.antennaLimit" type="number"> </MkInput>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.wordMuteMax, 'wordMuteLimit'])">
                <template #label>{{ i18n.ts._role._options.wordMuteMax }}</template>
                <template #suffix>{{ policies.wordMuteLimit }}</template>
                <MkInput v-model="policies.wordMuteLimit" type="number">
                  <template #suffix>chars</template>
                </MkInput>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.webhookMax, 'webhookLimit'])">
                <template #label>{{ i18n.ts._role._options.webhookMax }}</template>
                <template #suffix>{{ policies.webhookLimit }}</template>
                <MkInput v-model="policies.webhookLimit" type="number"> </MkInput>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.clipMax, 'clipLimit'])">
                <template #label>{{ i18n.ts._role._options.clipMax }}</template>
                <template #suffix>{{ policies.clipLimit }}</template>
                <MkInput v-model="policies.clipLimit" type="number"> </MkInput>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.noteEachClipsMax, 'noteEachClipsLimit'])">
                <template #label>{{ i18n.ts._role._options.noteEachClipsMax }}</template>
                <template #suffix>{{ policies.noteEachClipsLimit }}</template>
                <MkInput v-model="policies.noteEachClipsLimit" type="number"> </MkInput>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.userListMax, 'userListLimit'])">
                <template #label>{{ i18n.ts._role._options.userListMax }}</template>
                <template #suffix>{{ policies.userListLimit }}</template>
                <MkInput v-model="policies.userListLimit" type="number"> </MkInput>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.userEachUserListsMax, 'userEachUserListsLimit'])">
                <template #label>{{ i18n.ts._role._options.userEachUserListsMax }}</template>
                <template #suffix>{{ policies.userEachUserListsLimit }}</template>
                <MkInput v-model="policies.userEachUserListsLimit" type="number"> </MkInput>
              </MkFolder>

              <MkFolder v-if="matchQuery([i18n.ts._role._options.canHideAds, 'canHideAds'])">
                <template #label>{{ i18n.ts._role._options.canHideAds }}</template>
                <template #suffix>{{ policies.canHideAds ? i18n.ts.yes : i18n.ts.no }}</template>
                <MkSwitch v-model="policies.canHideAds">
                  <template #label>{{ i18n.ts.enable }}</template>
                </MkSwitch>
              </MkFolder>

              <MkButton primary rounded @click="updateBaseRole">{{ i18n.ts.save }}</MkButton>
            </div>
          </MkFolder>
          <MkButton primary rounded @click="create"><i class="ti ti-plus"></i> {{ i18n.ts._role.new }}</MkButton>
          <div class="_gaps_s">
            <MkFoldableSection>
              <template #header>Manual roles</template>
              <div class="_gaps_s">
                <MkRolePreview
                  v-for="role in roles.filter((x) => x.target === 'manual')"
                  :key="role.id"
                  :role="role"
                  :for-moderation="true"
                />
              </div>
            </MkFoldableSection>
            <MkFoldableSection>
              <template #header>Conditional roles</template>
              <div class="_gaps_s">
                <MkRolePreview
                  v-for="role in roles.filter((x) => x.target === 'conditional')"
                  :key="role.id"
                  :role="role"
                  :for-moderation="true"
                />
              </div>
            </MkFoldableSection>
          </div>
        </div>
      </MkSpacer>
    </MkStickyContainer>
  </div>
</template>

<script lang="ts" setup>
import { computed, reactive, ref } from 'vue';
import XHeader from './_header_.vue';
import MkInput from '@/components/MkInput.vue';
import MkFolder from '@/components/MkFolder.vue';
import MkSwitch from '@/components/MkSwitch.vue';
import MkButton from '@/components/MkButton.vue';
import MkRange from '@/components/MkRange.vue';
import MkRolePreview from '@/components/MkRolePreview.vue';
import * as os from '@/os';
import { i18n } from '@/i18n';
import { definePageMetadata } from '@/scripts/page-metadata';
import { instance } from '@/instance';
import { useRouter } from '@/router';
import MkFoldableSection from '@/components/MkFoldableSection.vue';
import { ROLE_POLICIES } from '@/const';

const router = useRouter();
const baseRoleQ = ref('');

const roles = await os.api('admin/roles/list');

const policies = reactive<Record<(typeof ROLE_POLICIES)[number], any>>({});
for (const ROLE_POLICY of ROLE_POLICIES) {
  policies[ROLE_POLICY] = instance.policies[ROLE_POLICY];
}

function matchQuery(keywords: string[]): boolean {
  if (baseRoleQ.value.trim().length === 0) return true;
  return keywords.some((keyword) => keyword.toLowerCase().includes(baseRoleQ.value.toLowerCase()));
}

async function updateBaseRole() {
  await os.apiWithDialog('admin/roles/update-default-policies', {
    policies,
  });
}

function create() {
  router.push('/admin/roles/new');
}

const headerActions = $computed(() => []);

const headerTabs = $computed(() => []);

definePageMetadata(
  computed(() => ({
    title: i18n.ts.roles,
    icon: 'ti ti-badges',
  })),
);
</script>

<style lang="scss" module></style>
