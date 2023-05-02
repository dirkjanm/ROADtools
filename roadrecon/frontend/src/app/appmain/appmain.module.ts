import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { UsersComponent } from './users/users.component';
import { IndexComponent, DetailDialog } from './index/index.component';
import { GroupsComponent } from './groups/groups.component';
import { MatTableModule } from '@angular/material/table';
import { MatPaginatorModule } from '@angular/material/paginator';
import { MatSortModule } from '@angular/material/sort';
import { MatTabsModule } from '@angular/material/tabs';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatListModule } from '@angular/material/list';
import { MatDividerModule } from '@angular/material/divider';
import { MatDialogModule } from '@angular/material/dialog';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { HttpClientModule } from '@angular/common/http';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { UsersItem, DatabaseService, UsersResolveService, DevicesResolveService, GroupsResolveService, ServicePrincipalsResolveService } from './aadobjects.service'
import { RouterModule } from '@angular/router';
import { UsersdialogComponent } from './users/usersdialog/usersdialog.component';
import { GroupsdialogComponent } from './groups/groupsdialog/groupsdialog.component';
import { AdministrativeUnitsdialogComponent } from './administrativeunits/administrativeunitsdialog/administrativeunitsdialog.component';
import { ServicePrincipalsComponent } from './serviceprincipals/serviceprincipals.component';
import { ServicePrincipalsdialogComponent } from './serviceprincipals/serviceprincipalsdialog/serviceprincipalsdialog.component';
import { MatInputModule } from '@angular/material/input';
import { AppRolesComponent } from './approles/approles.component';
import { ApplicationsComponent } from './applications/applications.component';
import { ApplicationsdialogComponent } from './applications/applicationsdialog/applicationsdialog.component';
import { DirectoryRolesComponent } from './directoryroles/directoryroles.component';
import { RoletableComponent } from './directoryroles/roletable.component';
import { DevicesComponent } from './devices/devices.component';
import { AdministrativeUnitsComponent } from './administrativeunits/administrativeunits.component';
import { DevicesdialogComponent } from './devices/devicesdialog/devicesdialog.component'
import { JsonFormatDirective } from './json-format.directive';
import { ConfigComponent } from './config/config.component';
import { NgxWebstorageModule } from 'ngx-webstorage';
import { FormsModule }   from '@angular/forms';
import { MfaComponent } from './mfa/mfa.component';
import { Oauth2permissionsComponent } from './oauth2permissions/oauth2permissions.component';

@NgModule({
  declarations: [
    UsersComponent,
    IndexComponent,
    UsersdialogComponent,
    GroupsComponent,
    GroupsdialogComponent,
    AdministrativeUnitsComponent,
    AdministrativeUnitsdialogComponent,
    ServicePrincipalsComponent,
    ServicePrincipalsdialogComponent,
    AppRolesComponent,
    ApplicationsComponent,
    ApplicationsdialogComponent,
    DirectoryRolesComponent,
    RoletableComponent,
    DetailDialog,
    DevicesComponent,
    DevicesdialogComponent,
    JsonFormatDirective,
    ConfigComponent,
    MfaComponent,
    Oauth2permissionsComponent
  ],
  imports: [
    CommonModule,
    FormsModule,
    MatTableModule,
    MatPaginatorModule,
    MatSortModule,
    HttpClientModule,
    RouterModule,
    MatTabsModule,
    MatIconModule,
    MatDialogModule,
    MatDividerModule,
    MatCardModule,
    MatInputModule,
    MatExpansionModule,
    MatSnackBarModule,
    MatListModule,
    MatButtonModule,
    MatTooltipModule,
    MatSlideToggleModule,
    NgxWebstorageModule.forRoot({'prefix':'RT'}),
  ],
  exports: [
    UsersComponent,
    IndexComponent,
    GroupsComponent
  ],
  providers: [
    DatabaseService,
    UsersResolveService,
    GroupsResolveService,
    DevicesResolveService,
    ServicePrincipalsResolveService
  ]
})
export class AppmainModule { }
