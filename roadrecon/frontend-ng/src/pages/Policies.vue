<template>
  <!-- Site header -->
  <main class="grow">
    <div class="px-4 sm:px-6 lg:px-8 py-8 w-full mx-auto">
      <!-- Dashboard actions -->
      <div class="sm:flex sm:justify-between sm:items-center mb-8">

        <!-- Left: Title -->
        <div class="mb-4 sm:mb-0 flex">
          <h1 class="text-2xl md:text-3xl text-gray-800 dark:text-gray-100 font-bold">{{ name }}</h1>
          <Button @click="toggleAllPolicies" :class="{'p-button-success':showAllPolicies}" class="ml-4 px-4 py-2">Toggle All policies</Button>
          <Button @click="toggleEnabledPolicies" :class="{'p-button-success':showEnabledOnly}" class="ml-4 px-4 py-2">Show Enabled Policies</Button>
        </div>
      </div>
      <!-- Cards -->
      <div class="grid gap-6 rounded-3xl overflow-auto" v-if="!loading">
        <!--Don't know why its 11 -->
        <Accordion :value="expandedPoliciesPanels" multiple expandIcon="pi pi-plus" collapseIcon="pi pi-minus" v-if="policies">
          <template v-for="(policy, index) in filteredPolicies" :key="index">
            <AccordionPanel :value="String(index)">
              <AccordionHeader>
                <span :ref="policy.displayName" class="flex items-center gap-2 w-full">
                  <Tag :severity="policy.policyDetail.State == 'Enabled' ? 'success' :
                    policy.policyDetail.State == 'Disabled' ? 'danger' :
                      'info'" :value="policy.policyDetail.State">
                  </Tag>
                  <span>{{ policy.displayName }}</span>
                </span>
              </AccordionHeader>
              <AccordionContent v-if="policy.policyDetail.Conditions">
                <Tabs value="0" class="rounded">
                  <TabList>
                    <Tab value="0">
                      Overview
                    </Tab>
                    <Tab value="1">
                      Raw
                    </Tab>
                  </TabList>
                  <TabPanels>
                    <TabPanel value="0">
                      <div v-if="policy.policyDetail.Conditions.Users">
                        <span class="pi pi-user"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Users</span>
                        <div class="flex flex-wrap">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.Users.Include">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Including
                                </div>
                                <ul v-for="item in policy.policyDetail.Conditions.Users.Include"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element,index in item">
                                    <template v-if="index == 'GuestsOrExternalUsers'">
                                      <p>{{index}}:</p>
                                      <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                        <p>{{objectType}}</p>
                                      </ul>
                                    </template>
                                    <template v-else-if="index == 'Users'">
                                      <p>{{index}}:</p>
                                      <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                        <a v-if="objectType.displayName != 'All'" class="hover:underline" :href="'/User/'+objectType.objectId">{{ objectType.displayName }}</a>
                                        <p v-else>{{ objectType.displayName }}</p>
                                      </ul>
                                    </template>
                                    <template v-else-if="index == 'Groups'">
                                      <p>{{index}}:</p>
                                      <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                        <a v-if="objectType.displayName != 'All'" class="hover:underline" :href="'/Group/'+objectType.objectId">{{ objectType.displayName }}</a>
                                        <p v-else>{{ objectType.displayName }}</p>
                                      </ul>
                                    </template>
                                    <template v-else>
                                      <p>{{index}}:</p>
                                      <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                        <p>{{ objectType.displayName }}</p>
                                      </ul>
                                    </template>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                          <div class="flex-1 m-4 p-tag-danger p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.Users.Exclude">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Excluding
                                </div>
                                <ul v-for="item in policy.policyDetail.Conditions.Users.Exclude"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element,index in item">
                                    <template v-if="index == 'GuestsOrExternalUsers'">
                                      <p>{{index}}:</p>
                                      <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                        <p>{{ objectType }}</p>
                                      </ul>
                                    </template>
                                    <template v-else-if="index == 'Users'">
                                      <p>{{index}}:</p>
                                      <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                        <a v-if="objectType.displayName != 'All'" class="hover:underline" :href="'/User/'+objectType.objectId">{{ objectType.displayName }}</a>
                                        <p v-else>{{ objectType.displayName }}</p>
                                      </ul>
                                    </template>
                                    <template v-else-if="index == 'Groups'">
                                      <p>{{index}}:</p>
                                      <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                        <a v-if="objectType.displayName != 'All'" class="hover:underline" :href="'/Group/'+objectType.objectId">{{ objectType.displayName }}</a>
                                        <p v-else>{{ objectType.displayName }}</p>
                                      </ul>
                                    </template>
                                    <template v-else>
                                      <p>{{index}}:</p>
                                      <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                        <p>{{ objectType.displayName }}</p>
                                      </ul>
                                    </template>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="policy.policyDetail.Conditions.ServicePrincipals">
                        <span class="pi pi-user"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Service Principals</span>
                        <div class="flex flex-wrap">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.ServicePrincipals.Include">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Including
                                </div>
                                <ul v-for="item in policy.policyDetail.Conditions.ServicePrincipals.Include"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element,index in item">
                                    <p>{{index}}:</p>
                                    <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                      <a v-if="objectType.displayName != 'All'" class="hover:underline" :href="'/ServicePrincipal/'+objectType.objectId">{{ objectType.displayName }}</a>
                                      <p v-else>{{ objectType.displayName }}</p>
                                    </ul>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                          <div class="flex-1 m-4 p-tag-danger p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.ServicePrincipals.Exclude">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Excluding
                                </div>
                                <ul v-for="item in policy.policyDetail.Conditions.ServicePrincipals.Exclude"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element,index in item">
                                    <p>{{index}}:</p>
                                    <ul v-for="objectType in element" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                      <p>{{ objectType.displayName }}</p>
                                    </ul>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="policy.policyDetail.Conditions.Applications">
                        <span class="pi pi-box"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4"
                          v-if="policy.policyDetail.Conditions.Applications">Applications</span>
                        <div class="flex flex-wrap" v-if="policy.policyDetail.Conditions.Applications">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.Applications.Include">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Including
                                </div>
                                <ul v-for="(item, index) in policy.policyDetail.Conditions.Applications.Include[0]"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element in item">
                                    <a v-if="element.displayName != 'All'" class="hover:underline" :href="'/Application/'+element.objectId">{{ element.displayName }}</a>
                                    <p v-else>{{ element.displayName }}</p>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                          <div class="flex-1 m-4 p-tag-danger p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.Applications.Exclude">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Excluding
                                </div>
                                <ul v-for="(item, index) in policy.policyDetail.Conditions.Applications.Exclude[0]"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element in item">
                                    <a v-if="element.displayName != 'All'" class="hover:underline" :href="'/Application/'+element.objectId">{{ element.displayName }}</a>
                                    <p v-else>{{ element.displayName }}</p>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="policy.policyDetail.Conditions.ClientTypes">
                        <span class="pi pi-mobile"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Client
                          types</span>
                        <div class="flex flex-wrap" v-if="policy.policyDetail.Conditions.ClientTypes">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.ClientTypes.Include">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Including
                                </div>
                                <ul v-for="(item, index) in policy.policyDetail.Conditions.ClientTypes.Include[0]"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element in item">
                                    <p v-if="element == 'All'">All ClientTypes</p>
                                    <p v-else>{{ element }}</p>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                          <div class="flex-1 m-4 p-tag-danger p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.ClientTypes.Exclude && policy.policyDetail.Conditions.ClientTypes.Exclude.length > 0">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Excluding
                                </div>
                                <ul v-for="(item, index) in policy.policyDetail.Conditions.ClientTypes.Exclude[0]"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element in item">
                                    <p v-if="element == 'All'">All ClientTypes</p>
                                    <p v-else>{{ element }}</p>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="policy.policyDetail.Conditions.DevicePlatforms">
                        <span class="pi pi-desktop"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Platforms</span>
                        <div class="flex flex-wrap" v-if="policy.policyDetail.Conditions.DevicePlatforms">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.DevicePlatforms.Include && policy.policyDetail.Conditions.DevicePlatforms.Include.length > 0">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Including
                                </div>
                                <ul v-for="(item, index) in policy.policyDetail.Conditions.DevicePlatforms.Include[0]"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element in item">
                                    <p v-if="element == 'All'">All Platforms</p>
                                    <p v-else>{{ element }}</p>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                          <div class="flex-1 m-4 p-tag-danger p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.DevicePlatforms.Exclude && policy.policyDetail.Conditions.DevicePlatforms.Exclude.length > 0">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Excluding
                                </div>
                                <ul v-for="(item, index) in policy.policyDetail.Conditions.DevicePlatforms.Exclude[0]"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="element in item">
                                    <p v-if="element == 'All'">All Platforms</p>
                                    <p v-else>{{ element }}</p>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="policy.policyDetail.Conditions.Devices">
                        <span class="pi pi-desktop"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Devices</span>
                        <div class="flex flex-wrap" v-if="policy.policyDetail.Conditions.Devices">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.Devices.Include && policy.policyDetail.Conditions.Devices.Include.length > 0">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Including
                                </div>
                                <ul v-for="condition in policy.policyDetail.Conditions.Devices.Include" class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="item,index in condition">
                                    <p v-if="index == 'DeviceRule'">Rule : <i>{{item }}</i></p>
                                    <p v-if="index == 'DeviceStates'">Device State: {{ item }}</p>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                          <div class="flex-1 m-4 p-tag-danger p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.Devices.Exclude">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Excluding
                                </div>
                                <ul v-for="condition in policy.policyDetail.Conditions.Devices.Exclude"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li v-for="item,index in condition">
                                    <p v-if="index == 'DeviceRule'">Rule : <i>{{ item }}</i></p>
                                    <p v-if="index == 'DeviceStates'">Device State: {{ item }}</p>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="policy.policyDetail.Conditions.Locations">
                        <span class="pi pi-desktop"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Locations</span>
                        <div class="flex flex-wrap" v-if="policy.policyDetail.Conditions.Locations">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.Locations.Include  && policy.policyDetail.Conditions.Locations.Include.length > 0">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Including
                                </div>
                                <ul v-for="(item, index) in policy.policyDetail.Conditions.Locations.Include"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <a v-if="item.displayName != 'All'" class="hover:underline" @click="goto(item)">{{ item }}</a>
                                  <p v-else>{{ item }}</p>
                                </ul>
                              </div>
                            </div>
                          </div>
                          <div class="flex-1 m-4 p-tag-danger p-4 rounded-2xl"
                            v-if="policy.policyDetail.Conditions.Locations.Exclude && policy.policyDetail.Conditions.Locations.Exclude.length > 0">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <div class="m-0 mb-1 text-surface-500 dark:text-surface-300 text-lg font-semibold">
                                  Excluding
                                </div>
                                <ul v-for="(item, index) in policy.policyDetail.Conditions.Locations.Exclude"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <a class="hover:underline" @click="goto(item)">{{ item }}</a>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="policy.policyDetail.Controls">
                        <span class="pi pi-check-circle"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Controls</span>
                        <div class="flex flex-wrap">
                          <div class="flex-1 m-4 p-tag-info p-4 rounded-2xl">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <template v-if="policy.policyDetail.Controls">
                                  <ul v-for="(item, index) in policy.policyDetail.Controls"
                                    class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                    <li v-for="(control) in item.Control">
                                      <p v-if="control != Block">{{ control }}</p>
                                      <p v-else>Deny logon</p>
                                    </li>
                                    <li v-if="item.AuthStrengthIds">
                                      <p>{{ resolve_authstrength(item.AuthStrengthIds) }}</p>
                                    </li>
                                  </ul>
                                </template>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="policy.policyDetail.SessionControls">
                        <span class="pi pi-check-circle"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Session Controls</span>
                        <div class="flex flex-wrap">
                          <div class="flex-1 m-4 p-tag-info p-4 rounded-2xl">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <template v-if="policy.policyDetail.SessionControls">
                                  <ul v-for="(item, index) in policy.policyDetail.SessionControls"
                                    class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                    <li>
                                      <p>{{ item }}</p>
                                    </li>
                                  </ul>
                                </template>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </TabPanel>
                    <TabPanel value="1">
                      <pre id="code" class="text-gray-300">
                        <code>
                          {{ policy.raw }}
                        </code>
                      </pre>
                    </TabPanel>
                  </TabPanels>
                </Tabs>
              </AccordionContent>
            </AccordionPanel>
          </template>
        </Accordion>
        <Card v-else>
          <template class="flex flex-col" #content>
            <p>No policies</p>
          </template>
        </Card>

        <div class="flex">
          <h1 class="text-2xl md:text-3xl text-gray-800 dark:text-gray-100 font-bold">Named Locations</h1>
          <Button @click="toggleAllLocations" class="ml-4 px-4 py-2">Toggle All policies</Button>
          <Button @click="toggleTrustedLocations" :class="{'p-button-success':showTrustedLocationsOnly}" class="ml-4 px-4 py-2">Show Trusted Locations</Button>
        </div>

        <Accordion  :value="expandedLocationsPanels" multiple expandIcon="pi pi-plus" collapseIcon="pi pi-minus" v-if="filteredLocations">
          <template v-for="(location, index) in filteredLocations">
            <AccordionPanel :value="String(index)">
              <AccordionHeader>
                <span :ref="location.displayName">
                  {{ location.displayName }}
                  <Tag v-if="location.trusted" severity="success" class="mx-1">Trusted</Tag>
                  <Tag v-if="location.appliestounknowncountry" severity="info" class="mx-1">Applies to unknown country</Tag>
                </span>
              </AccordionHeader>
              <AccordionContent v-if="location.policyDetail">
                <Tabs value="0" class="rounded">
                  <TabList>
                    <Tab value="0">
                      Overview
                    </Tab>
                    <Tab value="1">
                      Raw
                    </Tab>
                  </TabList>
                  <TabPanels>
                    <TabPanel value="0">
                      <div v-if="location.ipranges != ''">
                        <span class="pi pi-asterisk"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Ip Ranges</span>
                        <div class="flex flex-wrap">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <ul v-for="item in location.ipranges"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li>
                                    {{ item }}
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="location.associatedpolicies && location.associatedpolicies.length > 1">
                        <span class="pi pi-link"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Associated Policies</span>
                        <div class="flex flex-wrap">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <ul v-for="item in location.associatedpolicies"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li>
                                    <a class="hover:underline" @click="goto(item)">{{ item }}</a>
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div v-if="location.policyDetail.CountryIsoCodes && location.policyDetail.CountryIsoCodes.length > 0">
                        <span class="pi pi-flag"></span>
                        <span class="text-surface-500 dark:text-surface-300 text-lg font-semibold m-4">Country ISO codes</span>
                        <div class="flex flex-wrap">
                          <div class="flex-1 m-4 p-tag-success p-4 rounded-2xl">
                            <div
                              class="card bg-surface-0 dark:bg-surface-900 text-surface-500 dark:text-surface-300 flex justify-between !rounded-2xl">
                              <div class="overview-info">
                                <ul v-for="item in location.policyDetail.CountryIsoCodes"
                                  class="m-0 text-surface-500 dark:text-surface-300 font-semibold ml-4">
                                  <li>
                                    {{ item }}
                                  </li>
                                </ul>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </TabPanel>
                    <TabPanel value="1">
                      <pre id="code" class="text-gray-300">
                        <code>
                          {{ location.raw }}
                        </code>
                      </pre>
                    </TabPanel>
                  </TabPanels>
                </Tabs>
              </AccordionContent>
            </AccordionPanel>
          </template>
        </Accordion>
      </div>
      <div class="grid gap-6 rounded-3xl overflow-auto" v-else>
        <h1 class="text-lg">Loading...</h1>
      </div>
    </div>
  </main>
</template>

<script>
import { ref, toRaw } from 'vue'
import { FilterMatchMode } from '@primevue/core/api';
import Card from 'primevue/card';
import Tag from 'primevue/tag';
import axios from 'axios'
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import ColumnGroup from 'primevue/columngroup';   // optional
import Row from 'primevue/row';                   // optional
import Accordion from 'primevue/accordion';
import AccordionPanel from 'primevue/accordionpanel';
import AccordionHeader from 'primevue/accordionheader';
import AccordionContent from 'primevue/accordioncontent';
import Tabs from 'primevue/tabs';
import TabList from 'primevue/tablist';
import Tab from 'primevue/tab';
import TabPanels from 'primevue/tabpanels';
import TabPanel from 'primevue/tabpanel';
import { showError } from '../services/toast';
import Button from 'primevue/button';

const filters = ref();

export default {
  name: 'Policies',
  props: {
    name: String,
  },
  components: {
    DataTable,
    Tag,
    Card,
    Column,
    ColumnGroup,
    Accordion,
    AccordionPanel,
    AccordionHeader,
    AccordionContent,
    Row,
    Tab,
    Tabs,
    TabList,
    TabPanels,
    TabPanel,
    Button
  },
  data() {
    return {
      policies: [],
      namedLocations: [],
      columns: [
        { field: 'appliesTo', header: 'Applies to' },
        { field: 'applications', header: 'Applications' },
        { field: 'onPlatforms', header: 'On platforms' },
        { field: 'controls', header: 'Controls' },
        { field: 'policyDetail.Version', header: 'Version' },
      ],
      filterFields: ["displayName"],
      filters: {
        global: { value: null, matchMode: FilterMatchMode.CONTAINS },
      },
      loading: true,
      expandedPoliciesPanels: [],
      expandedLocationsPanels: [],
      showEnabledOnly: false,
      showTrustedLocationsOnly: false,
      showAllPolicies: false
    }
  },
  computed: {
    filteredPolicies() {
      if (this.showEnabledOnly) {
        return this.policies.filter(policy => policy.policyDetail.State === 'Enabled');
      }
      return this.policies;
    },
    filteredLocations() {
      if (this.showTrustedLocationsOnly) {
        return this.namedLocations.filter(namedLocation => namedLocation.trusted === true);
      }
      return this.namedLocations;
    }
  },
  mounted() {
    axios
      .get("/api/policies")
      .then(response => {
        for (var i = 0; i < response.data.length; i++) {
          if (response.data[i].policyType == 18) {
            this.policies.push({
              displayName: response.data[i].displayName,
              policyDetail: response.data[i].policyDetail,
              objectId: response.data[i].objectId,
              raw: JSON.parse(JSON.stringify(response.data[i],null,2))
            })
          }
          else if (response.data[i].policyType == 6){
            this.namedLocations.push({
              displayName: response.data[i].displayName,
              policyDetail: response.data[i].policyDetail,
              trusted: response.data[i].trusted,
              appliestounknowncountry: response.data[i].appliestounknowncountry,
              objectId: response.data[i].objectId,
              associatedpolicies: response.data[i].associated_policies.split(","),
              ipranges: response.data[i].ipranges.split(","),
              raw: JSON.parse(JSON.stringify(response.data[i],null,2))
            })
          }
        }
      }).finally(()=>{
        this.loading = false
      })
      .catch(error => {
        showError("Error loading policies from API", error.message)
        console.log(error)
      })
  },
  methods: {
    goToDetail(event) {
      this.$router.push({ name: 'RowDetail', params: { objectId: event.data.objectId, objectType: "Policy" } });
    },
    resolve_authstrength(guid){
      var built_in = {
        '00000000-0000-0000-0000-000000000002': 'Multi-factor authentication',
        '00000000-0000-0000-0000-000000000003': 'Passwordless MFA',
        '00000000-0000-0000-0000-000000000004': 'Phishing-resistant MFA'
      }
      return built_in[guid]
    },
    goto(refName) {
    	var element = this.$refs[refName];
      element[0].scrollIntoView({ behavior: "smooth", block: "center" });
    },
    toggleAllPolicies() {
      if (this.expandedPoliciesPanels.length === this.policies.length) {
        this.expandedPoliciesPanels = [];
        this.showAllPolicies = false;
      } else {
        this.expandedPoliciesPanels = this.policies.map((_, index) => String(index));
        this.showAllPolicies = true;
      }
    },
    toggleAllLocations() {
      if (this.expandedLocationsPanels.length === this.policies.length) {
        this.expandedLocationsPanels = [];
      } else {
        this.expandedLocationsPanels = this.policies.map((_, index) => String(index));
      }
    },
    toggleEnabledPolicies() {
      this.showEnabledOnly = !this.showEnabledOnly;
    },
    toggleTrustedLocations() {
      this.showTrustedLocationsOnly = !this.showTrustedLocationsOnly;
    }
  },
}
</script>