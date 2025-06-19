import {app} from '../main';

const lifeTime = 3000;

export function showInfo(title = 'I am title', body = 'I am body') {
    app.config.globalProperties.$toast.add({ severity: 'info', summary: title, detail: body, life: lifeTime });
}

export function showError(title = 'I am title', body = 'I am body') {
    console.log("printing error")
    app.config.globalProperties.$toast.add({ severity: 'error', summary: title, detail: body, life: lifeTime });
}