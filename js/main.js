import Vue from 'vue'
import App from './App.vue'

console.log("hello js/main.js");

Vue.mixin({ methods: { t, n } })

const View = Vue.extend(App)
new View().$mount('#privacyidea')
