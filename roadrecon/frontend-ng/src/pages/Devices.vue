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
        :values="devices" 
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
import ObjectTable from '../partials/dashboard/ObjectTable.vue'
import { FilterMatchMode } from '@primevue/core/api';
import { showError } from '../services/toast';
import axios from 'axios'

export default {
  name: 'Devices',
  props: {
    name: String
  },
  components: {
    ObjectTable
  },
  data(){
    return {
      devices: [],
      columns: [
        { field: 'displayName', header: 'Name' },
        { field: 'deviceManufacturer', header: 'Manufacturer' },
        { field: 'accountEnabled', header: 'Enabled', isTag: true },
        { field: 'deviceModel', header: 'Model' },
        { field: 'deviceOSType', header: 'OS' },
        { field: 'deviceOSVersion', header: 'OS Version' },
        { field: 'deviceTrustType', header: 'Trust type' },
        { field: 'isCompliant', header: 'Compliant', isTag: true },
        { field: 'isManaged', header: 'Managed', isTag: true },
        { field: 'isRooted', header: 'Rooted', isTag: true },
      ],
      filterFields:["displayName","deviceManufacturer","accountEnabled","deviceModel","deviceOSType","deviceOSVersion","deviceTrustType","isCompliant","isManaged","isRooted"],
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
        .get(`/api/devices`,{params:params})
        .then(response => {
            this.devices=response.data.items;
            this.totalRecords=response.data.total;
            
            for(var i=0;i<this.devices.length;i++){
              this.devices[i].accountEnabled = this.devices[i].accountEnabled ? "True" : "False"
              this.devices[i].isCompliant = this.devices[i].isCompliant ? "True" : "False"
              this.devices[i].isManaged = this.devices[i].isManaged ? "True" : "False"
              this.devices[i].isRooted = this.devices[i].isRooted ? "True" : "False"
            }
        })
        .catch(error => {
          showError("Error loading devices from API", error.message)
          console.log(error)
      })
      .finally(() => {
          this.loading = false;
        });
    },
  }
}
</script>