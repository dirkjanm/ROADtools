import { Component } from '@angular/core';
import { BreakpointObserver, Breakpoints } from '@angular/cdk/layout';
import { Observable } from 'rxjs';
import { map, shareReplay } from 'rxjs/operators';
import { LocalStorage } from 'ngx-webstorage';

@Component({
  selector: 'app-appnav',
  templateUrl: './appnav.component.html',
  styleUrls: ['./appnav.component.less']
})
export class AppnavComponent {
  @LocalStorage()
  public mfa;

  isHandset$: Observable<boolean> = this.breakpointObserver.observe(Breakpoints.Handset)
    .pipe(
      map(result => result.matches),
      shareReplay()
    );

  constructor(private breakpointObserver: BreakpointObserver) {}

}
