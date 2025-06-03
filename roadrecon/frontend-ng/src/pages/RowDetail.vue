<template>
    <!-- Site header -->
    <main class="grow">
        <div class="px-4 sm:px-6 lg:px-8 py-8 w-full mx-auto">
            <!-- Dashboard actions -->
            <div class="sm:flex sm:justify-between sm:items-center mb-8">
                <!-- Left: Title -->
                <div class="mb-4 sm:mb-0">
                    <h1 v-if="!err" class="text-2xl md:text-3xl text-gray-800 dark:text-gray-100 font-bold">{{ object.displayName }}</h1>
                    <h1 v-else class="text-2xl md:text-3xl text-gray-800 dark:text-gray-100 font-bold">{{ err }}</h1>
                    <Tag v-if="(object.objectType == 'User' || object.objectType == 'Device' || object.objectType == 'ServicePrincipal') && object.accountEnabled === true"
                        severity="success" value="Enabled" />
                    <Tag v-if="(object.objectType == 'User' || object.objectType == 'Device' || object.objectType == 'ServicePrincipal') && object.accountEnabled === false"
                        severity="danger" value="Disabled" />
                </div>
            </div>
            <p v-if="loading">Loading...</p>
            <!-- Cards -->
            <div class="grid grid-cols-2 gap-4 overflow-auto rounded-3xl p-3">
                <Card class="grid grid-cols-2 overflow-auto">
                    <template #content>
                        <p v-if="err">{{ err }}</p>
                        <DataView v-else :value="object">
                            <template #list="slotProps">
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
                                            <div class="flex flex-col">
                                                <div v-for="(item, index) in object.overviewItems">
                                                    <div v-if="checkDisplay(item.value)" class="p-4" :class="{ 'border-t border-surface-200 dark:border-surface-700': index !== 0 }">
                                                        <div v-if="item.value" class="grid grid-rows-2 justify-items-stretch">
                                                            <div class="justify-self-start gap-2 row-span-2">
                                                                <div class="text-xl font-black font-bold mt-2">{{ item.name }}</div>
                                                            </div>
                                                            <template v-if="Array.isArray(item.value)">
                                                                <div class="justify-self-start">
                                                                    <span v-for="value in item.value" class="text-lg">
                                                                        {{ value }}<br>
                                                                    </span>
                                                                </div>
                                                            </template>
                                                            <template v-else>
                                                                <div class="justify-self-start">
                                                                    <span class="text-lg">{{ item.value }}</span>
                                                                </div>
                                                            </template>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </TabPanel>
                                        <TabPanel value="1">
                                            <div class="overflow-x-auto">
                                                <pre id="code" class="text-gray-300">
                                                    <JsonViewer style="background: none;" :value="rawObject" copyable sort expanded theme="dark"/>
        </pre>
                                            </div>
                                        </TabPanel>
                                    </TabPanels>
                                </Tabs>
                            </template>
                        </DataView>
                    </template>
                </Card>
                <!-- TODO Add check here -->
                <Card v-if="activeTabItems.length > 0">
                    <template #content>
                        <Tabs value="0" class="rounded">
                            <TabList class="overflow-x-auto">
                                <template v-for="(item, tabIndex) in activeTabItems" :key="item.name">
                                    <Tab :value="String(tabIndex)" v-if="object[item.attribute].length">
                                        {{ item.name }}
                                        <Tag v-if="item && item.attribute" severity="info"
                                            :value="object[item.attribute].length"></Tag>
                                    </Tab>
                                </template>
                            </TabList>
                            <TabPanels>
                                <template v-for="(item, tabIndex) in activeTabItems" :key="item.attribute">
                                    <TabPanel :value="String(tabIndex)" v-if="object[item.attribute].length">
                                        <ObjectTable 
                                            :columns="item.columns" 
                                            :values="object[item.attribute]"
                                            :filterFields="item.filterFields"
                                            :filters
                                            :lazy="false"
                                        />
                                    </TabPanel>
                                </template>
                            </TabPanels>
                        </Tabs>
                    </template>
                </Card>
            </div>
        </div>
    </main>
</template>

<script>
import { ref, toRaw } from 'vue'
import dayjs from 'dayjs';
import ObjectTable from '../partials/dashboard/ObjectTable.vue'
import { FilterMatchMode } from '@primevue/core/api';
import Tabs from 'primevue/tabs';
import TabList from 'primevue/tablist';
import Tab from 'primevue/tab';
import TabPanels from 'primevue/tabpanels';
import TabPanel from 'primevue/tabpanel';
import axios from 'axios'
import Card from 'primevue/card';
import Tag from 'primevue/tag';
import DataView from 'primevue/dataview';
import {JsonViewer} from "vue3-json-viewer"
import "vue3-json-viewer/dist/vue3-json-viewer.css";
import { showError } from '../services/toast';

const filters = ref();

export default {
    name: 'RowDetail',
    components: {
        ObjectTable,
        Card,
        Tab,
        Tag,
        Tabs,
        TabList,
        TabPanels,
        TabPanel,
        DataView,
        FilterMatchMode,
    },
    data() {
        return {
            object: {
                memberOfRole: [],
                tabItems: [],
            },
            activeTabItems: [],
            name: "User detail",
            rawObject: null,
            err: null,
            loading: false,
            columns: {
                devices: [
                    { field: 'displayName', header: 'Name' },
                    { field: 'accountEnabled', header: 'Enabled', isTag: true },
                    { field: 'deviceManufacturer', header: 'Manufacturer' },
                    { field: 'deviceModel', header: 'Model' },
                    { field: 'deviceOSType', header: 'OS' },
                    { field: 'deviceOSVersion', header: 'OS Version' },
                    { field: 'deviceTrustType', header: 'Trust type' },
                    { field: 'isCompliant', header: 'Compliant', isTag: true },
                    { field: 'isManaged', header: 'Managed', isTag: true },
                    { field: 'isRooted', header: 'Rooted', isTag: true },
                ],
                servicePrincipals: [
                    { field: 'displayName', header: 'Name' },
                    { field: 'publisherName', header: 'Publisher' },
                    { field: 'microsoftFirstParty', header: 'Microsoft app' },
                    { field: 'passwordCredentials.length', header: 'Passwords' },
                    { field: 'keyCredentials.length', header: 'Keys' },
                    { field: 'appRoles.length', header: 'Roles defined' },
                    { field: 'oauth2Permissions.length', header: 'OAuth2 Permissions' },
                    { field: 'ownerUsers.length', header: 'Custom owner' },
                ],
                applications: [
                    { field: 'displayName', header: 'Name' },
                    { field: 'passwordCredentials.length', header: 'Passwords' },
                    { field: 'keyCredentials.length', header: 'Keys' },
                    { field: 'appRoles.length', header: 'Roles defined' },
                    { field: 'oauth2Permissions.length', header: 'OAuth2 Permissions' },
                    { field: 'appRoles.length', header: 'Custom owner' },
                ],
                groupsMembership: [
                    { field: 'displayName', header: 'Name' },
                    { field: 'description', header: 'Description' },
                ]
            },
        };
    },
    mounted() {
        const objectId = this.$route.params.objectId;
        const objectType = this.$route.params.objectType;

        var apiRoute = ""

        if (objectType === "User") {
            apiRoute = "users"
        }
        else if (objectType === "Group") {
            apiRoute = "groups"
        }
        else if (objectType === "Device") {
            apiRoute = "devices"
        }
        else if (objectType === "Application") {
            apiRoute = "applications"
        }
        else if (objectType === "ServicePrincipal") {
            apiRoute = "serviceprincipals"
        }
        else if (objectType === "AdministrativeUnit") {
            apiRoute = "administrativeunits"
        }
        else if (objectType === "Policy") {
            apiRoute = "policy"
        }

        this.loading = true
        axios
            .get(`/api/${apiRoute}/${objectId}`)
            .then(response => {
                this.rawObject = JSON.parse(JSON.stringify(response.data))//Deep copy to ensure its not bound to this.object
                this.object = response.data;
                this.object.activeTabItems = []

                if (objectType === "User") {
                    this.object.tabItems = [
                        {
                            name: "Role Membership",
                            attribute: "memberOfRole",
                            filterFields: ["displayName", "description"],
                            columns: [
                                { field: 'displayName', header: 'Name' },
                                { field: 'description', header: 'Description' },
                            ],
                        },
                        {
                            name: "Owned Devices",
                            attribute: "ownedDevices",
                            filterFields: ["displayName"],
                            columns: this.columns.devices,
                        },
                        {
                            name: "Owned ServicePrincipals",
                            attribute: "ownedServicePrincipals",
                            filterFields: ["displayName"],
                            columns: this.columns.servicePrincipals,
                        },
                        {
                            name: "Owned Applications",
                            attribute: "ownedApplications",
                            filterFields: ["displayName"],
                            columns: this.columns.applications,
                        },
                        {
                            name: "Owned Groups",
                            attribute: "ownedGroups",
                            filterFields: ["displayName"],
                            columns: this.columns.groupsMembership,
                        },
                        {
                            name: "Group Membership",
                            attribute: "memberOf",
                            filterFields: ["displayName", "description"],
                            columns: this.columns.groupsMembership,
                        }
                    ];
                    this.object.overviewItems = [
                        {
                            name: "Display name",
                            value: this.object.displayName,
                        },
                        {
                            name: "UserPrincipalName",
                            value: this.object.userPrincipalName,
                        },
                        {
                            name: "ObjectId",
                            value: this.object.objectId,
                        },
                        {
                            name: "Last password change",
                            value: dayjs(this.object.lastPasswordChangeDateTime).format("DD/MM/YYYY HH:mm"),
                        },
                        {
                            name: "Account source",
                            value: this.object.dirSyncEnabled ? "Synced with AD" : "Cloud-only",
                        },
                        {
                            name: "Account type",
                            value: this.object.userType,
                        },
                        {
                            name: "Creation date",
                            value: dayjs(this.object.createdDateTime).format("DD/MM/YYYY HH:mm"),
                        },
                    ];
                }
                else if (objectType === "Group") {
                    this.object.tabItems = [
                        {
                            name: "Group memberships (parent groups)",
                            attribute: "memberOf",
                            filterFields: ["displayName", "userPrincipalName", "accountEnabled"],
                            columns: this.columns.groupsMembership,
                        },
                        {
                            name: "Owner users",
                            attribute: "ownerUsers",
                            filterFields: ["displayName", "userPrincipalName", "accountEnabled"],
                            columns: [
                                { field: 'displayName', header: 'Name' },
                                { field: 'userPrincipalName', header: 'userPrincipalName' },
                                { field: 'accountEnabled', header: 'Enabled', isTag: true },
                            ],
                        },
                        {
                            name: "Owner service principals",
                            attribute: "ownerServicePrincipals",
                            filterFields: ["displayName", "servicePrincipalType"],
                            columns: [
                                { field: 'displayName', header: 'Name' },
                                { field: 'servicePrincipalType', header: 'Type' },
                            ],
                        },
                        {
                            name: "Member users",
                            attribute: "memberUsers",
                            filterFields: ["displayName", "userPrincipalName", "userType", "accountEnabled"],
                            columns: [
                                { field: 'displayName', header: 'Name' },
                                { field: 'userPrincipalName', header: 'userPrincipalName' },
                                { field: 'userType', header: 'Type' },
                                { field: 'accountEnabled', header: 'Enabled', isTag: true },
                            ],
                        },
                        {
                            name: "Member groups (subgroups)",
                            attribute: "memberGroups",
                            filterFields: ["displayName", "description"],
                            columns: this.columns.groups,
                        },
                        {
                            name: "Member ServicePrincipal",
                            attribute: "memberServicePrincipals",
                            filterFields: ["displayName", "servicePrincipalType"],
                            columns: [
                                { field: 'displayName', header: 'Name' },
                                { field: 'servicePrincipalType', header: 'Type' },
                            ],
                        },
                        {
                            name: "Member devices",
                            attribute: "memberDevices",
                            filterFields: ["displayName", "userPrincipalName", "accountEnabled"],
                            columns: this.columns.devices,
                        },
                    ];
                    this.object.overviewItems = [
                        {
                            name: "Display name",
                            value: this.object.displayName,
                        },
                        {
                            name: "Description",
                            value: this.object.description,
                        },
                        {
                            name: "ObjectId",
                            value: this.object.objectId,
                        },
                        {
                            name: "Can be assigned to roles ?",
                            value: this.object.isAssignableToRole ? "Yes" : "No",
                        },
                        {
                            name: "Created",
                            value: dayjs(this.object.createdDateTime).format("DD/MM/YYYY HH:mm"),
                        },
                        {
                            name: "Group source",
                            value: this.object.groups ? "Synced with AD" : "Cloud-only",
                        },
                    ];
                }
                else if (objectType === "Device") {
                    this.object.tabItems = [
                        {
                            name: "Owners",
                            attribute: "owner",
                            filterFields: ["name", "userPrincipalName", "accountEnabled"],
                            columns: [
                                { field: 'displayName', header: 'Owner' },
                                { field: 'userPrincipalName', header: 'userPrincipalName' },
                                { field: 'accountEnabled', header: 'Enabled', isTag: true }
                            ],
                        },
                        {
                            name: "Groups",
                            attribute: "memberOf",
                            filterFields: ["name", "userPrincipalName", "accountEnabled"],
                            columns: [
                                { field: 'displayName', header: 'Name' },
                                { field: 'description', header: 'Description' },
                            ],
                        },
                        {
                            name: "Bitlocker Keys",
                            attribute: "blkeys",
                            filterFields: ["keyIdentifier", "keyMaterial"],
                            columns: [
                                { field: 'keyIdentifier', header: 'Identifier' },
                                { field: 'keyMaterial', header: 'Recovery key' }
                            ],
                        },
                    ];
                    this.object.overviewItems = [
                        {
                            name: "Display name",
                            value: this.object.displayName,
                        },
                        {
                            name: "ObjectId",
                            value: this.object.objectId,
                        },
                        {
                            name: "Device ID",
                            value: this.object.deviceId,
                        },
                        {
                            name: "Device OS Version",
                            value: this.object.deviceOSVersion,
                        },
                        {
                            name: "Device OS Type",
                            value: this.object.deviceOSType,
                        },
                    ];
                }
                else if (objectType === "Application") {
                    this.object.tabItems = [
                        {
                            name: "Owners",
                            attribute: "ownerUsers",
                            filterFields: ["displayName", "userPrincipalName"],
                            columns: [
                                { field: 'displayName', header: 'Name' },
                                { field: 'userPrincipalName', header: 'userPrincipalName' },
                            ],
                        },
                        {
                            name: "Application roles (application permissions)",
                            attribute: "appRoles",
                            filterFields: ["value", "allowedMemberTypes", "description", "vale", "id"],
                            columns: [
                                { field: 'displayName', header: 'Name' },
                                { field: 'allowedMemberTypes', header: 'Allowed types' },
                                { field: 'description', header: 'Description' },
                                { field: 'value', header: 'Value' },
                                { field: 'id', header: 'ID' },
                            ],
                        },
                        {
                            name: "OAuth2 permissions (delegated permissions)",
                            attribute: "oauth2Permissions",
                            filterFields: ["value", "allowedMemberTypes", "description", "vale", "id"],
                            columns: [
                                { field: 'userConsentDisplayName', header: 'User Consent Name' },
                                { field: 'type', header: 'Allowed types' },
                                { field: 'userConsentDescription', header: 'User Consent Description' },
                                { field: 'adminConsentDisplayName', header: 'Admin Consent Name' },
                                { field: 'adminConsentDescription', header: 'Admin Consent Description' },
                                { field: 'value', header: 'Value' },
                                { field: 'id', header: 'ID' },
                            ],
                        },
                        {
                            name: "Passwords",
                            attribute: "passwordCredentials",
                            filterFields: ["value","keyId"],
                            columns: [
                                { field: 'value', header: 'Value' },
                                { field: 'keyId', header: 'Key ID' },
                            ],
                        },
                        {
                            name: "Keys",
                            attribute: "keyCredentials",
                            filterFields: ["type","keyId","usage"],
                            columns: [
                                { field: 'type', header: 'Type' },
                                { field: 'keyId', header: 'Key ID' },
                                { field: 'usage', header: 'Usage' },
                            ],
                        },
                    ];
                    this.object.overviewItems = [
                        {
                            name: "Display name",
                            value: this.object.displayName,
                        },
                        {
                            name: "ObjectId",
                            value: this.object.objectId,
                        },
                        {
                            name: "Application ID",
                            value: this.object.appid,
                        },
                        {
                            name: "Publisher",
                            value: this.object.ownerServicePrincipals.publisherName,
                        },
                        {
                            name: "Homepage",
                            value: this.object.homepage,
                        }
                    ];
                    
                    if(this.object.ownerServicePrincipals.length > 0)
                    {
                        this.object.overviewItems.push(
                            {
                                name: "Service Principal",
                                value: this.object.ownerServicePrincipals[0].displayName,
                            }
                        )
                    }
                }
                else if (objectType === "ServicePrincipal") {
                    this.object.tabItems = [
                        {
                            name: "App defined permissions (app permissions)",
                            attribute: "appRoles",
                            value: "0",
                            filterFields: ["value", "displayName", "description", "id", "allowedMemberTypes"],
                            columns: [
                                { field: 'value', header: 'Value' },
                                { field: 'displayName', header: 'Name' },
                                { field: 'description', header: 'Description' },
                                { field: 'id', header: 'ID' },
                                { field: 'allowedMemberTypes', header: 'Allowed types' },
                            ],
                        },
                        {
                            name: "App roles assigned to others",
                            attribute: "appRolesAssigned",
                            value: "1",
                            filterFields: ["principalDisplayName", "principalType", "value", "desc"],
                            columns: [
                                { field: 'principalDisplayName', header: 'PrincipalName' },
                                { field: 'principalType', header: 'Principal Type' },
                                { field: 'value', header: 'Role' },
                                { field: 'desc', header: 'Description' },
                            ],
                        },
                        {
                            name: "App roles assigned to this principal",
                            attribute: "appRolesAssignedTo",
                            value: "2",
                            filterFields: ["value", "displayName", "description", "id", "allowedMemberTypes"],
                            columns: [
                                { field: 'principalDisplayName', header: 'PrincipalName' },
                                { field: 'principalType', header: 'Principal Type' },
                                { field: 'value', header: 'Role' },
                                { field: 'resourceDisplayName', header: 'Application' },
                                { field: 'desc', header: 'Description' },
                            ],
                        },
                        {
                            name: "OAuth2 permissions (delegated permissions)",
                            attribute: "oauth2Permissions",
                            value: "3",
                            filterFields: ["value", "displayName", "description", "id", "allowedMemberTypes"],
                            columns: [
                                { field: 'value', header: 'Value' },
                                { field: 'userConsentDisplayName', header: 'User Consent Name' },
                                { field: 'userConsentDescription', header: 'User Consent Description' },
                                { field: 'adminConsentDisplayName', header: 'Admin Consent Name' },
                                { field: 'adminConsentDescription', header: 'Admin Consent Description' },
                                { field: 'id', header: 'Admin Consent Description' },
                                { field: 'type', header: 'Allowed types' },
                            ],
                        },
                        {
                            name: "Owner",
                            attribute: "ownerUsers",
                            value: "4",
                            filterFields: ["value", "displayName", "description", "id", "allowedMemberTypes"],
                            columns: [
                                { field: 'displayName', header: 'Name' },
                                { field: 'userPrincipalName', header: 'userPrincipalName' },
                                { field: 'accountEnabled', header: 'Enabled', isTag: true },
                            ],
                        },
                    ];
                    this.object.overviewItems = [
                        {
                            name: "Display name",
                            value: this.object.displayName,
                        },
                        {
                            name: "ObjectId",
                            value: this.object.objectId,
                        },
                        {
                            name: "Application ID",
                            value: this.object.appId,
                        },
                        {
                            name: "Microsoft App",
                            value: this.object.microsoftFirstParty ? "Yes" : "No",
                        },
                        {
                            name: "Publisher",
                            value: this.object.publisherName,
                        },
                        {
                            name: "ReplyUrls",
                            value: this.object.replyUrls,
                        }
                    ];
                }
                else if (objectType === "AdministrativeUnit") {
                    this.object.tabItems = [
                        {
                            name: "Member users",
                            attribute: "memberUsers",
                            filterFields: ["value", "description", "type"],
                            columns: [
                                { field: 'value', header: 'Name' },
                                { field: 'description', header: 'Description' },
                                { field: 'userType', header: 'userType' },
                            ],
                        },
                        {
                            name: "Member groups",
                            attribute: "memberGroups",
                            filterFields: ["displayName", "description"],
                            columns: [
                                { field: 'displayName', header: 'name' },
                                { field: 'description', header: 'Description' },
                            ],
                        },
                        {
                            name: "Member devices",
                            attribute: "memberDevices",
                            filterFields: ["value", "displayName", "description", "id", "allowedMemberTypes"],
                            columns: this.columns.devices,
                        },
                    ];
                    this.object.overviewItems = [
                        {
                            name: "Display name",
                            value: this.object.displayName,
                        },
                        {
                            name: "Description",
                            value: this.object.description,
                        },
                        {
                            name: "ObjectId",
                            value: this.object.objectId,
                        },
                        {
                            name: "Dynamic Membership",
                            value: this.object.membershipRule,
                        },
                    ];
                }
                else if (objectType === "Policy") {
                    this.object.tabItems = [
                    ];
                    this.object.overviewItems = [
                        {
                            name: "Display name",
                            value: this.object.displayName,
                        },
                        {
                            name: "ObjectId",
                            value: this.object.objectId,
                        },
                    ];
                }

                this.object.nbItems = 0

                for (var i = 0; i < this.object.tabItems.length; i++) {
                    if (this.object[this.object.tabItems[i].attribute] != undefined && this.object[this.object.tabItems[i].attribute].length > 0) {
                        this.activeTabItems.push(this.object.tabItems[i])
                    }
                }
            })
            .catch(error => {
                if(error.status == 404){
                    this.err="User not found"
                    showError(this.err, error.message)
                    console.log(this.err)
                    return
                }
                else if(error.status == 500){
                    this.err="Unknown object"
                    showError(this.err, error.message)
                    console.log(this.err)
                    return
                }
                else if(error.status != 200){
                    this.err="Unknown error"
                    showError(this.err, error.message)
                    console.log(error)
                    return
                }
            }).finally(() => {
                this.loading = false;
            });
    },
    methods: {
        checkDisplay(value) {
            if (value === null || value === undefined) return false;
            if (typeof value === 'boolean') return value;
            if (typeof value === 'string' || Array.isArray(value)) return value.length > 0;
            return true;
        },
    },
    setup() {
        const filters = ref();
        filters.value = {
            global: { value: null, matchMode: FilterMatchMode.CONTAINS }
        };

        return {
            filters,
        };
    }
}
</script>

<style>
    .jv-container .jv-code.open {
        padding: 0 !important;
    }
</style>