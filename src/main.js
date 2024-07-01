import Vue from 'vue'
import App from '../js/App.vue'

console.log("hello src/main.js");

Vue.mixin({ methods: { t, n } })

const View = Vue.extend(App)
new View().$mount('#privacyidea')
