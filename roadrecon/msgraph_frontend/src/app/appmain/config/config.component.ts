import { Component, OnInit } from '@angular/core';
import { LocalStorage } from 'ngx-webstorage';

@Component({
  selector: 'app-config',
  templateUrl: './config.component.html',
  styleUrls: ['./config.component.less']
})
export class ConfigComponent implements OnInit {
  @LocalStorage()
  public mfa;

  constructor() { }

  ngOnInit(): void {
  }

}
