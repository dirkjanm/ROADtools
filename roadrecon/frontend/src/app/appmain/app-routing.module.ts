import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { UsersComponent } from './users/users.component';
import { DevicesComponent } from './devices/devices.component';
import { GroupsComponent } from './groups/groups.component';
import { ApplicationsComponent } from './applications/applications.component';
import { AppRolesComponent } from './approles/approles.component';
import { DirectoryRolesComponent } from './directoryroles/directoryroles.component';
import { IndexComponent } from './index/index.component';
import { ServicePrincipalsComponent } from './serviceprincipals/serviceprincipals.component';
import { UsersdialogInitComponent } from './users/usersdialog/usersdialog.component';
import { DevicesdialogInitComponent } from './devices/devicesdialog/devicesdialog.component';
import { GroupsdialogInitComponent } from './groups/groupsdialog/groupsdialog.component';
import { ApplicationsdialogInitComponent } from './applications/applicationsdialog/applicationsdialog.component';
import { ServicePrincipalsdialogInitComponent } from './serviceprincipals/serviceprincipalsdialog/serviceprincipalsdialog.component';
import { UsersResolveService, GroupsResolveService, ServicePrincipalsResolveService, DevicesResolveService, ApplicationsResolveService } from './aadobjects.service'
import { ConfigComponent } from './config/config.component';
import { MfaComponent } from './mfa/mfa.component';
import { Oauth2permissionsComponent } from './oauth2permissions/oauth2permissions.component';

const routes: Routes = [
      { path: '', component: IndexComponent },
      { path: 'config', component: ConfigComponent },
      { path: 'oauth2permissions', component: Oauth2permissionsComponent },
      { path: 'mfa', component: MfaComponent },
      { path: 'users',
        component: UsersComponent,
        children: [
          {
            path: ':id',
            component: UsersdialogInitComponent,
            resolve: {
              user: UsersResolveService
            }
          }
        ]
      },
      { path: 'devices',
        component: DevicesComponent,
        children: [
          {
            path: ':id',
            component: DevicesdialogInitComponent,
            resolve: {
              device: DevicesResolveService
            }
          }
        ]
      },
      { path: 'groups',
        component: GroupsComponent,
        children: [
          {
            path: ':id',
            component: GroupsdialogInitComponent,
            resolve: {
              user: GroupsResolveService
            }
          }
        ]
      },
      { path: 'serviceprincipals',
        component: ServicePrincipalsComponent,
        children: [
          {
            path: ':id',
            component: ServicePrincipalsdialogInitComponent,
            resolve: {
              sp: ServicePrincipalsResolveService
            }
          }
        ]
      },
      { path: 'applications',
        component: ApplicationsComponent,
        children: [
          {
            path: ':id',
            component: ApplicationsdialogInitComponent,
            resolve: {
              application: ApplicationsResolveService
            }
          }
        ]
      },
      { path: 'approles',
        component: AppRolesComponent
      },
      { path: 'directoryroles',
        component: DirectoryRolesComponent
      },
      // { path: 'users/:objectId', component: UsersComponentDetail },
    ];
@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
