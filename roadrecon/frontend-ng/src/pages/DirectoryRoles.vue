<template>
  <!-- Site header -->
  <main class="grow">
    <div class="px-4 sm:px-6 lg:px-8 py-8 w-full mx-auto">
      <!-- Dashboard actions -->
      <div class="sm:flex sm:justify-between sm:items-center mb-8">
        <!-- Left: Title -->
        <div class="mb-4 sm:mb-0 flex">
          <h1 class="text-2xl md:text-3xl text-gray-800 dark:text-gray-100 font-bold">{{ name }}</h1>
          <Button @click="toggleAll" class="ml-4 px-4 py-2">Toggle All</Button>
        </div>
      </div>
      <!-- Cards -->
      <div class="grid gap-6 rounded-3xl overflow-auto">
        <Accordion :value="expandedPanels" multiple expandIcon="pi pi-plus" collapseIcon="pi pi-minus">
          <template v-for="(directoryRole, index) in directoryroles">
            <AccordionPanel :value="String(index)" v-if="directoryRole.assignments.length > 0">
                <AccordionHeader>
                  <span class="flex items-center gap-2 w-full">
                    <Tag severity="info" :value="directoryRole.assignments.length"></Tag>
                    <span>{{ directoryRole.displayName }}</span>
                  </span>
                </AccordionHeader>
                <AccordionContent>
                  <ObjectTable multiselect :columns="columns" :values="directoryRole.assignments" :filterFields="filterFields" :filters="filters" :lazy="false" />
                </AccordionContent>
            </AccordionPanel>
          </template>
        </Accordion>
      </div>
    </div>
  </main>
</template>

<script>
import { ref, toRaw } from 'vue'
import ObjectTable from '../partials/dashboard/ObjectTable.vue'
import { FilterMatchMode } from '@primevue/core/api';
import Accordion from 'primevue/accordion';
import AccordionPanel from 'primevue/accordionpanel';
import AccordionHeader from 'primevue/accordionheader';
import AccordionContent from 'primevue/accordioncontent';
import { showError } from '../services/toast';
import Button from 'primevue/button';
import Tag from 'primevue/tag';
import axios from 'axios'

const filters = ref();

export default {
  name: 'DirectoryRoles',
  props: {
    name: String,
  },
  components: {
    ObjectTable,
    Accordion,
    AccordionPanel,
    AccordionHeader,
    AccordionContent,
    Tag,
    Button
  },
  data(){
    return {
      directoryroles: [],
      assignments: [],
      columns: [
        { field: 'principal.displayName', header: 'Principal Name' },
        { field: 'scopeNames', header: 'Scope' },
        { field: 'type', header: 'Assignment Type', isTag: true, tagSuccessValue: "Active" },
        { field: 'principal.objectType', header: 'Principal Type' },
        { field: 'principal.userPrincipalName', header: 'userPrincipalName' },
        { field: 'principal.dirSyncEnabled', header: 'Account type' },
        { field: 'principal.accountEnabled', header: 'Status' },
      ],
      filterFields:["principal.displayName","scopeNames","type","principal.objectType","principal.userPrincipalName","principal.dirSyncEnabled","principal.accountEnabled"],
      filters: {
        global: { value: null, matchMode: FilterMatchMode.CONTAINS },
      },
      expandedPanels: []
    }
  },
  methods: {
    toggleAll() {
      if (this.expandedPanels.length === this.directoryroles.length) {
        this.expandedPanels = [];
      } else {
        this.expandedPanels = this.directoryroles.map((_, index) => String(index));
      }
    }
  },
  mounted() {
    axios
        .get("/api/roledefinitions")
        .then(response => {
            this.directoryroles=response.data;
            for(var i=0;i<this.directoryroles.length;i++){
              for(var j=0;j<this.directoryroles[i].assignments.length;j++){
                this.directoryroles[i].assignments[j].scopeNames = this.directoryroles[i].assignments[j].scopeNames[0]
                this.directoryroles[i].assignments[j].type = this.directoryroles[i].assignments[j].type == "assignment" ? "Active" : "Disabled"
                this.directoryroles[i].assignments[j].principal.dirSyncEnabled = this.directoryroles[i].assignments[j].principal.dirSyncEnabled ? "AD" : "Cloud"
                this.directoryroles[i].assignments[j].principal.accountEnabled = this.directoryroles[i].assignments[j].principal.accountEnabled ? "Enabled" : "Disabled"
              }
            }
        })
        .catch(error => {
            showError("Error loading role definitions from API", error.message)
            console.log(error)
      })
  }
}
</script>