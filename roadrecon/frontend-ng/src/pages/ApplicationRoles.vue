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
        :values="approles" 
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
  name: 'ApplicationRoles',
  props: {
    name: String
  },
  components: {
    ObjectTable
  },
  data(){
    return {
      approles: [],
      columns: [
        { field: 'principalDisplayName', header: 'Principal Name' },
        { field: 'principalType', header: 'Principal Type' },
        { field: 'resourceDisplayName', header: 'Application' },
        { field: 'value', header: 'Role' },
        { field: 'desc', header: 'Description' },
      ],
      filterFields:["principalDisplayName","principalType","resourceDisplayName","value","desc"],
      filters: {
        global: { value: null, matchMode: FilterMatchMode.CONTAINS },
      },
      totalRecords: 0,
      loading: false
    }
  },
  mounted() {
    this.fetchData({page:1,rows:50,sortedField:"principalDisplayName",sortOrder:-1})
  },
  methods: {
    fetchData(params) {
      this.loading = true
      axios
        .get(`/api/approles`,{params:params})
        .then(response => {
            this.approles=response.data.items;
            this.totalRecords=response.data.total;
        })
        .catch(error => {
            showError("Error loading App roles from API", error.message)
            console.log(error)
      })
      .finally(() => {
          this.loading = false;
      });
    },
  }
}
</script>