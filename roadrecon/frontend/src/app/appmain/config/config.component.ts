import { Component, OnInit } from '@angular/core';
import { LocalStorage } from 'ngx-webstorage';

@Component({
  standalone: false,
  selector: 'app-config',
  templateUrl: './config.component.html',
  styleUrls: ['./config.component.less']
})
export class ConfigComponent implements OnInit {
  @LocalStorage()
  public mfa: any;
  @LocalStorage()
  public portallinks: any;
  @LocalStorage()
  public paging: any;
  @LocalStorage()
  public blueteam: any;

  constructor() { }

  ngOnInit(): void {
  }

}
