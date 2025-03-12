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
      </div>
      <!-- Cards -->
      <div class="grid gap-6 overflow-auto rounded-3xl">
        <ObjectTable 
        :columns="columns" 
        :values="serviceprincipals" 
        :filterFields="filterFields" 
        :filters="filters" 
        :totalRecords
        :loading
        multiselect
        paginatorPosition="both"
        @pageChange="fetchData"
        @inputTextUpdated="fetchData"
        @pageSort="fetchData"
        />
      </div>
    </div>
  </main>
</template>

<script>
import { ref } from 'vue'
import ObjectTable from '../partials/dashboard/ObjectTable.vue'
import { FilterMatchMode } from '@primevue/core/api';
import { showError } from '../services/toast';
import axios from 'axios'

const filters = ref();

export default {
  name: 'ServicePrincipals',
  props: {
    name: String
  },
  components: {
    ObjectTable
  },
  data(){
    return {
      serviceprincipals: [],
      columns: [
        { field: 'accountEnabled', header: 'Enabled', isTag: true, tagSuccessValue: "Enabled" },
        { field: 'displayName', header: 'Name' },
        { field: 'servicePrincipalType', header: 'Type' },
        { field: 'publisherName', header: 'Publisher' },
        { field: 'microsoftFirstParty', header: 'Microsoft app', isTag: true },
        { field: 'passwordCredentials', header: 'Passwords', isTag: true },
        { field: 'keyCredentials', header: 'Keys', isTag: true },
        { field: 'appRoles', header: 'Roles defined' },
        { field: 'oauth2Permissions', header: 'OAuth2 Permissions' },
        { field: 'ownerUsers', header: 'Custom owner', isTag: true },
      ],
      filterFields:["accountEnabled","displayName","servicePrincipalType","publisherName","microsoftFirstParty","passwordCredentials","keyCredentials","appRoles","oauth2Permissions","ownerUsers"],
      filters: {
        global: { value: null, matchMode: FilterMatchMode.CONTAINS },
      },
      totalRecords: 0,
      loading: false
    }
  },
  mounted() {
    this.fetchData({page:1,rows:50,sortedField:"displayName",sortOrder:-1})
  },
  methods: {
    fetchData(params) {
      this.loading = true
      axios
        .get(`/api/serviceprincipals`,{params:params})
        .then(response => {
            this.serviceprincipals=response.data.items;
            this.totalRecords=response.data.total;
            
            for(var i=0;i<this.serviceprincipals.length;i++){
              this.serviceprincipals[i].accountEnabled = this.serviceprincipals[i].accountEnabled ? "Enabled" : "Disabled"
              this.serviceprincipals[i].microsoftFirstParty = this.serviceprincipals[i].microsoftFirstParty ? "True" : "False"
              this.serviceprincipals[i].passwordCredentials = this.serviceprincipals[i].passwordCredentials.length > 0 ? "True" : "False"
              this.serviceprincipals[i].keyCredentials = this.serviceprincipals[i].keyCredentials.length > 0 ? "True" : "False"
              this.serviceprincipals[i].appRoles = this.serviceprincipals[i].appRoles.length > 0 ? this.serviceprincipals[i].appRoles.length : ""
              this.serviceprincipals[i].oauth2Permissions = this.serviceprincipals[i].oauth2Permissions.length > 0 ? this.serviceprincipals[i].oauth2Permissions.length : ""
              this.serviceprincipals[i].ownerUsers = this.serviceprincipals[i].ownerUsers.length > 0 ? "True" : "False"
            }
        })
        .catch(error => {
          showError("Error loading service principals from API", error.message)
          console.log(error)
      })
      .finally(() => {
          this.loading = false;
      });
    },
  }
}
</script>