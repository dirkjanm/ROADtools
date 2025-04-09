import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from './pages/Dashboard.vue'
import Users from './pages/Users.vue'
import Groups from './pages/Groups.vue'
import Devices from './pages/Devices.vue'
import AdministrativeUnits from './pages/AdministrativeUnits.vue'
import DirectoryRoles from './pages/DirectoryRoles.vue'
import Applications from './pages/Applications.vue'
import ServicePrincipals from './pages/ServicePrincipals.vue'
import ApplicationRoles from './pages/ApplicationRoles.vue'
import OAuth2Permissions from './pages/OAuth2Permissions.vue'
import Policies from './pages/Policies.vue'
import RowDetail from './pages/RowDetail.vue'

const routerHistory = createWebHistory()

export const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard,
    props: {name: 'Dashboard'},
    icon: "pi pi-home"
  },
  {
    path: '/Users',
    name: 'Users',
    component: Users,
    props: {name: 'Users'},
    icon: "pi pi-user"
  },
  {
    path: '/Groups',
    name: 'Groups',
    component: Groups,
    props: {name: 'Groups'},
    icon: "pi pi-users"
  },
  {
    path: '/Devices',
    name: 'Devices',
    component: Devices,
    props: {name: 'Devices'},
    icon: "pi pi-desktop"
  },
  {
    path: '/AdministrativeUnits',
    name: 'Administrative Units',
    component: AdministrativeUnits,
    props: {name: 'Administrative Units'},
    icon: "pi pi-stop"
  },
  {
    path: '/DirectoryRoles',
    name: 'Directory Roles',
    component: DirectoryRoles,
    props: {name: 'Directory Roles'},
    icon: "pi pi-stop"
  },
  {
    path: '/Applications',
    name: 'Applications',
    component: Applications,
    props: {name: 'Applications'},
    icon: "pi pi-box"
  },
  {
    path: '/ServicePrincipals',
    name: 'Service Principals',
    component: ServicePrincipals,
    props: {name: 'ServicePrincipals'},
    icon: "pi pi-crown"
  },
  {
    path: '/ApplicationRoles',
    name: 'Application Roles',
    component: ApplicationRoles,
    props: {name: 'Application Roles'},
    icon: "pi pi-stop"
  },
  {
    path: '/OAuth2Permissions',
    name: 'Oauth2 Permissions',
    component: OAuth2Permissions,
    props: {name: 'OAuth2 Permissions'},
    icon: "pi pi-stop"
  },
  {
    path: '/Policies',
    name: 'Policies',
    component: Policies,
    props: {name: 'Policies'},
    icon: "pi pi-list-check"
  },
  {
    path: '/:objectType/:objectId',
    name: 'RowDetail',
    component: RowDetail,
    hideNavbar: true,
  },
  {
    path: '/:catchAll(.*)',
    redirect: '/'
  }
]

const router = createRouter({
  history: routerHistory,
  routes: routes,
  mode: 'history'
})

export default router
