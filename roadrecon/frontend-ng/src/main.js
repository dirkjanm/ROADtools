import { createApp } from 'vue'
import router from './router'
import App from './App.vue'
import axios from './plugins/axios'
import PrimeVue from 'primevue/config';
import Noir from './presets/Noir.js';
import ToastService from 'primevue/toastservice';
import JsonViewer from "vue3-json-viewer";

import DataTable from 'primevue/datatable';
import Column from 'primevue/column';

import './css/style.css'
import dayjs from 'dayjs'

export const app = createApp(App)
app.use(router)
app.use(axios,{
    baseUrl: 'http://localhost:5000/'
})
app.use(PrimeVue, {
    theme: {
        preset: Noir,
        options: {
            prefix: 'p',
            darkModeSelector: '.p-dark',
            cssLayer: false,
        }
    }
});

//Date conversion
app.config.globalProperties.$dayjs = dayjs

//Notification service
app.use(ToastService)

//JSON Viewer
app.use(JsonViewer);

//Components
app.component("DataTable",DataTable)
app.component("Column",Column)

app.mount('#app')
