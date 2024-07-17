<template>
  <NcSettingsSection :name="t('privacyidea', 'privacyIDEA Authenticator')"
                     :description="t('privacyidea', 'This plugin allows adding multi-factor authentication against the privacyIDEA.')"
                     :doc-url="privacyideaDocLink">
    <div id="privacyidea">
      <h1>privacyIDEA Authentication</h1>
    </div>
  </NcSettingsSection>

  <!--<NcAppContent>
		<div id="privacyidea">
			<h1>Hello world!</h1>
		</div>
	</NcAppContent>-->
</template>

<script>
import NcAppContent from '@nextcloud/vue/dist/Components/NcAppContent.js'
import NcSettingsSection from '@nextcloud/vue/dist/Components/NcSettingsSection.js'
import NcButton from '@nextcloud/vue/dist/Components/NcButton.js'
import NcTextField from '@nextcloud/vue/dist/Components/NcTextField.js'

export default {
	name: 'App',
	components: {
		NcAppContent,
    NcSettingsSection,
    NcButton,
    NcTextField,
  },
  data() {
    return {
      privacyideaDocLink: 'https://privacyidea.readthedocs.io/en/latest/',
    }
  },
}
</script>

<style scoped lang="scss">
#privacyidea {
	display: flex;
	justify-content: center;
	margin: 16px;
}
</style>
