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
        :values="applications" 
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
import { ref, toRaw } from 'vue'
import ObjectTable from '../partials/dashboard/ObjectTable.vue'
import { showError } from '../services/toast';
import { FilterMatchMode } from '@primevue/core/api';
import axios from 'axios'

const filters = ref();

export default {
  name: 'Applications',
  props: {
    name: String
  },
  components: {
    ObjectTable
  },
  data(){
    return {
      applications: [],
      columns: [
        { field: 'displayName', header: 'Name' },
        { field: 'availableToOtherTenants', header: 'Multitenant', isTag: true },
        { field: 'homepage', header: 'Homepage' },
        { field: 'publicClient', header: 'OAuth2 public client', isTag: true },
        { field: 'oauth2AllowImplicitFlow', header: 'OAuth2 implicit flow', isTag: true },
        { field: 'passwordCredentials', header: 'Passwords' },
        { field: 'keyCredentials', header: 'Keys' },
        { field: 'appRoles', header: 'Roles defined' },
        { field: 'oauth2Permissions', header: 'OAuth2 Permissions' },
        { field: 'ownerUsers', header: 'Custom owner', isTag: true },
      ],
      filterFields:["displayName","availableToOtherTenants","homepage","publicClient","oauth2AllowImplicitFlow","passwordCredentials","keyCredentials","appRoles","oauth2Permissions","ownerUsers"],
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
        .get(`/api/applications`,{params:params})
        .then(response => {
            this.applications=response.data.items;
            this.totalRecords=response.data.total;
            
            for(var i=0;i<this.applications.length;i++){
              this.applications[i].availableToOtherTenants = this.applications[i].availableToOtherTenants ? "True" : "False"
              this.applications[i].oauth2AllowImplicitFlow = this.applications[i].oauth2AllowImplicitFlow ? "True" : "False"
              this.applications[i].publicClient = this.applications[i].publicClient ? "True" : "False"
              this.applications[i].passwordCredentials = this.applications[i].passwordCredentials.length
              this.applications[i].keyCredentials = this.applications[i].keyCredentials.length
              this.applications[i].appRoles = this.applications[i].appRoles.length
              this.applications[i].oauth2Permissions = this.applications[i].oauth2Permissions.length
              this.applications[i].ownerUsers = this.applications[i].ownerUsers.length > 0 ? "True" : "False"
            }
        })
        .catch(error => {
            showError("Error loading Applications from API", error.message)
            console.log(error)
      })
      .finally(() => {
          this.loading = false;
      });
    },
  }
}
</script>