<template>
  <!-- Site header -->
  <main class="grow">
    <div class="px-4 sm:px-6 lg:px-8 py-8 w-full mx-auto">
      <!-- Dashboard actions -->
      <div class="sm:flex sm:justify-between sm:items-center mb-8">

        <!-- Left: Title -->
        <div class="mb-4 sm:mb-0">
          <h1 class="text-2xl md:text-3xl text-gray-800 dark:text-gray-100 font-bold">{{ name }}</h1>
        </div>

        <!-- Right: Actions -->
        <div class="grid grid-flow-col sm:auto-cols-max justify-start sm:justify-end gap-2">
        </div>

      </div>
      <!-- Cards -->
      <div class="grid grid-cols-12 p-4 gap-4">
        <div class="col-span-12">
          <div class="flex gap-4">
            <div v-for="(card, index) in cards" class="w-full md:w-1/2 lg:w-1/3 xl:w-1/6">
              <Card :index @click="goToDetail(index)" class="h-full">
                <template #content>
                  <div
                    class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between h-full !rounded-2xl">
                    <div class="overview-info">
                      <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                        {{ card.title }}
                      </div>
                      <div class="m-0 text-surface-500 dark:text-surface-300 text-4xl font-semibold">
                        {{ card.value.toLocaleString('fr-FR') }}
                      </div>
                    </div>
                    <i :class="[, 'pi', card.icon, '!text-3xl']"></i>
                  </div>
                </template>
              </Card>
            </div>
          </div>
        </div>
        <div class="pt-0 col-span-8">
          <Card>
            <template #title>
              <div class="m-0 text-surface-500 dark:text-surface-300 text-2xl font-semibold">
                Application consent settings
              </div>
            </template>
            <template #content>
              <div class="flex gap-4" v-if="appConsentSettings">
                <div v-for="(setting, index) in appConsentSettings" class="flex m-0! p-2" :class="dynamicWidth">
                  <Tag class="w-full !p-0">
                    <Card class="p-tag-info size-full">
                      <template #content>
                        <div
                          class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between h-full !rounded-2xl">
                          <div v-if="setting == 'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team'" class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              Resource specific consent for Teams: Managed by Microsoft
                            </div>
                          </div>
                          <div v-else-if="setting == 'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat'" class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              Resource specific consent for chats: Managed by Microsoft
                            </div>
                          </div>
                          <div v-else-if="setting == 'ManagePermissionGrantsForSelf.microsoft-user-default-low'" class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              Users can consent to limited permissions only (default)
                            </div>
                          </div>
                          <div v-else-if="setting == 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'" class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              Users can consent to applications (insecure old default)
                            </div>
                          </div>
                          <div v-else class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              Unknown: {{ setting }}
                            </div>
                          </div>
                        </div>
                      </template>
                    </Card>
                  </Tag>
                </div>
              </div>
              <div v-else>
                <div class="flex m-0! p-2">
                  <Tag class="w-full !p-0">
                    <Card class="p-tag-danger size-full">
                      <template #content>
                        <div
                          class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between h-full !rounded-2xl">
                          <div class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              User consent is disabled
                            </div>
                          </div>
                        </div>
                      </template>
                    </Card>
                  </Tag>
                </div>
              </div>
            </template>
          </Card>
        </div>
        <div class="pt-0 col-span-4">
          <Card class="h-full">
            <template #title>
              <div class="m-0 text-surface-500 dark:text-surface-300 text-2xl font-semibold">
                Guest access settings
              </div>
            </template>
            <template #content>
              <div class="flex gap-4">
                <div class="flex m-0! p-2 w-full">
                  <Tag class="w-full !p-0">
                    <Card class="p-tag-info size-full">
                      <template #content>
                        <div
                          class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between h-full !rounded-2xl">
                          <div v-if="guestAccessSettings == 'a0b1b346-4d3e-4e8b-98f8-753987be4970'" class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              Same as member users
                            </div>
                          </div>
                          <div v-else-if="guestAccessSettings == '10dae51f-b6af-4016-8d66-8c2a99b929b3'" class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              Limited access (default)
                            </div>
                          </div>
                          <div v-else-if="guestAccessSettings == '2af84b1e-32c8-42b7-82bc-daa82404023b'" class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              Restricted access
                            </div>
                          </div>
                          <div v-else class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              Unknown: {{ guestAccessSettings }}
                            </div>
                          </div>
                        </div>
                      </template>
                    </Card>
                  </Tag>
                </div>
              </div>
            </template>
          </Card>
        </div>
        <div class="col-span-12 xl:col-span-7 pt-0">
          <Card>
            <template #title>
              <div class="m-0 text-surface-500 dark:text-surface-300 text-2xl font-semibold">
                Default user role permissions
              </div>
            </template>
            <template #content>
              <div class="flex gap-4">
                <div v-for="(userPermissionCard, index) in userPermissionCards" class="flex w-1/3 m-0! p-2">
                  <Tag class="w-full !p-0">
                    <Card :class="[userPermissionCard.value ? 'p-tag-success' : 'p-tag-danger ']" class="size-full">
                      <template #content>
                        <div
                          class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between h-full !rounded-2xl">
                          <div class="overview-info">
                            <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                              {{ userPermissionCard.title }}
                            </div>
                            <div class="m-0 text-surface-500 dark:text-surface-300 text-4xl font-semibold">
                              {{ userPermissionCard.value ? "Yes" : "No" }}
                            </div>
                          </div>
                        </div>
                      </template>
                    </Card>
                  </Tag>
                </div>
              </div>
            </template>
          </Card>
        </div>
        <div class="col-span-12 xl:col-span-5 pt-0">
          <div class="flex gap-4 items-center h-full">
            <div v-for="(card, index) in smallCards" class="basis-1/2 h-full">
              <Card :class="[card.value ? 'p-tag-success' : 'p-tag-danger ']" class="h-full">
                <template #content>
                  <div
                    class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                    <div class="overview-info">
                      <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                        {{ card.title }}
                      </div>
                      <div class="m-0 text-surface-500 dark:text-surface-300 text-4xl font-semibold">
                        {{ card.value ? "Yes" : "No" }}
                      </div>
                    </div>
                  </div>
                </template>
              </Card>
            </div>
          </div>
        </div>
        <div class="col-span-12 xl:col-span-7 pt-0">
          <Card>
            <template #title>
              <div class="m-0 text-surface-500 dark:text-surface-300 text-2xl font-semibold">
                Tenant domains
              </div>
            </template>
            <template #content>
              <ObjectTable :lazy="false" :columns :values="tenantDomains" :filterFields :filters :totalRecords :rowsPerPageOptions="[10,25,50]" />
            </template>
          </Card>
        </div>
        <div class="col-span-12 xl:col-span-5 pt-0 !pl-0">
          <Card>
            <template #title>
              <div class="m-0 text-surface-500 dark:text-surface-300 text-2xl font-semibold">
                Tenant information
              </div>
            </template>
            <template #content>
              <div v-for="(item, index) in overviewItems" class="p-6 gap-4"
                :class="{ 'border-t border-surface-200 dark:border-surface-700': index !== 0 }">
                <div class="flex flex-row justify-items-stretch gap-4">
                  <div class="justify-self-start basis-1/4 gap-2 ">
                    <div class="text-md font-semibold font-medium">{{ item.name }}</div>
                  </div>
                  <div class="justify-self-start gap-4">
                    <span class="text-md">{{ item.value }}</span>
                  </div>
                </div>
              </div>
            </template>
          </Card>
        </div>
      </div>
    </div>
  </main>
</template>

<script>
import Card from 'primevue/card';
import ObjectTable from '../partials/dashboard/ObjectTable.vue'
import DataView from 'primevue/dataview';
import Tag from 'primevue/tag';
import { showError } from '../services/toast';
import { FilterMatchMode } from '@primevue/core/api';
import axios from 'axios'

export default {
  name: 'Dashboard',
  props: {
    name: String
  },
  components: {
    Card,
    ObjectTable,
    DataView,
    Tag
  },
  methods: {
    goToDetail($index) {
      this.$router.push({ name: this.cards[$index].title });
    }
  },
  computed: {
    dynamicWidth() {
      const length = this.guestAccessSettings.length;
      return ` w-1/${length}`;
    }
  },
  data() {
    return {
      cards: [
        {
          "title": "Users",
          "icon": "pi pi-user",
          "value": 0
        },
        {
          "title": "Groups",
          "icon": "pi pi-users",
          "value": 0
        },
        {
          "title": "Applications",
          "icon": "pi pi-box",
          "value": 0
        },
        {
          "title": "Service Principals",
          "icon": "",
          "value": 0
        },
        {
          "title": "Devices",
          "icon": "pi pi-desktop",
          "value": 0
        },
        {
          "title": "Administrative Units",
          "icon": "",
          "value": 0
        }
      ],
      smallCards:[],
      userPermissionCards:[],
      overviewItems: [],
      tenantDomains: [],
      guestAccessSettings: [],
      columns: [
        { field: 'name', header: 'Name' },
        { field: 'type', header: 'Type' },
        { field: 'capabilities', header: 'Capabilities' },
        { field: 'default', header: 'Properties' },
      ],
      filterFields: ["name","type","capabilities","default"],
      filters: {
        global: { value: null, matchMode: FilterMatchMode.CONTAINS },
      },
      totalRecords: 0,
      appConsentSettings: []
    }
  },
  mounted() {
    axios
      .get("/api/stats")
      .then(response => {
        const { countAdministrativeUnits, countApplications, countDevices, countGroups, countServicePrincipals, countUsers } = response.data
        this.cards.filter((o) => { return o.title == "Users" })[0].value = countUsers
        this.cards.filter((o) => { return o.title == "Groups" })[0].value = countGroups
        this.cards.filter((o) => { return o.title == "Applications" })[0].value = countApplications
        this.cards.filter((o) => { return o.title == "Service Principals" })[0].value = countServicePrincipals
        this.cards.filter((o) => { return o.title == "Devices" })[0].value = countDevices
        this.cards.filter((o) => { return o.title == "Administrative Units" })[0].value = countAdministrativeUnits
      })
      .catch(error => {
        showError("Error loading stats from API", error.message)
        console.log(error)
      })

    axios
      .get("/api/tenantdetails")
      .then(response => {
        this.tenantDomains = response.data.verifiedDomains
        this.totalRecords = response.data.verifiedDomains.length

        const tenantInformation = [
          {
            name: "Name", value: response.data.displayName
          },
          {
            name: "Tenant ID", value: response.data.objectId
          },
          {
            name: "Syncs from AD", value: response.data.dirSyncEnabled ? "Yes" : "No"
          },
        ]

        this.overviewItems = tenantInformation
      })
      .catch(error => {
        console.log(error)
      })

      axios
      .get("/api/authorizationpolicies")
      .then(response => {
        const defaultUserRolePermissions = [
          {
            title: "Create Apps", value: response.data[0].defaultUserRolePermissions.allowedToCreateApps
          },
          {
            title: "Create Security Groups", value: response.data[0].defaultUserRolePermissions.allowedToCreateSecurityGroups
          },
          {
            title: "Read Other Users", value: response.data[0].defaultUserRolePermissions.allowedToReadOtherUsers
          },
        ]
        this.userPermissionCards = defaultUserRolePermissions

        this.appConsentSettings = response.data[0].permissionGrantPolicyIdsAssignedToDefaultUserRole

        this.guestAccessSettings = response.data[0].guestUserRoleId

        const smallCardsValues = [
          {
            title:"Self-service password reset",
            value: response.data[0].allowedToUseSSPR
          },
          {
            title:"MSOnline PowerShell blocked",
            value: response.data[0].blockMsolPowerShell
          }
        ]
        this.smallCards = smallCardsValues
      })
      .catch(error => {
        console.log(error)
      })
  }
}
</script>