import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { AppmainModule } from './appmain/appmain.module'
import { AppRoutingModule } from './appmain/app-routing.module';
import { AppComponent } from './app.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { AppnavComponent } from './appnav/appnav.component';
import { LayoutModule } from '@angular/cdk/layout';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatButtonModule } from '@angular/material/button';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatIconModule } from '@angular/material/icon';
import { MatListModule } from '@angular/material/list';
import { NgxWebstorageModule } from 'ngx-webstorage';

@NgModule({
  declarations: [
    AppComponent,
    AppnavComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    BrowserAnimationsModule,
    LayoutModule,
    MatToolbarModule,
    MatButtonModule,
    MatSidenavModule,
    MatIconModule,
    MatListModule,
    AppmainModule,
    NgxWebstorageModule.forRoot({'prefix':'RT'}),
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
