import { Directive, Input, OnChanges, ElementRef } from '@angular/core';
import JSONFormatter from 'json-formatter-js';


@Directive({
  selector: '[appJsonFormat]'
})
export class JsonFormatDirective implements OnChanges {
  @Input() json: any;

  constructor(private elRef: ElementRef) { }

  ngOnChanges() {
    if (this.json) {
      const formatter = new JSONFormatter(this.json, 3);
      this.elRef.nativeElement.appendChild(formatter.render());
    }
  }
}
