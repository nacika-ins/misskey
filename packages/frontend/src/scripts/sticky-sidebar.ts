export class StickySidebar {
  private lastScrollTop = 0;
  private container: HTMLElement;
  private el: HTMLElement;
  private spacer: HTMLElement;
  private marginTop: number;
  private isTop = false;
  private isBottom = false;
  private offsetTop: number;
  private globalHeaderHeight = 59;

  constructor(container: StickySidebar['container'], marginTop = 0, globalHeaderHeight = 0) {
    this.container = container;
    this.el = this.container.children[0] as HTMLElement;
    this.el.style.position = 'sticky';
    this.spacer = document.createElement('div');
    this.container.prepend(this.spacer);
    this.marginTop = marginTop;
    this.offsetTop = this.container.getBoundingClientRect().top;
    this.globalHeaderHeight = globalHeaderHeight;
  }

  public calc(scrollTop: number) {
    const url = new URL(window.location.href);
    const isChat = url.pathname.includes('/my/messaging/');

    if (scrollTop > this.lastScrollTop) {
      // downscroll
      const overflow = Math.max(
        0,
        this.globalHeaderHeight + (this.el.clientHeight + this.marginTop) - window.innerHeight,
      );
      // @ts-ignore
      this.el.style.bottom = null;
      this.el.style.top = `${-overflow + this.marginTop + this.globalHeaderHeight}px`;

      this.isBottom = scrollTop + window.innerHeight >= this.el.offsetTop + this.el.clientHeight;

      if (this.isTop) {
        this.isTop = false;
        if (!isChat) {
          this.spacer.style.marginTop = `${Math.max(
            0,
            this.globalHeaderHeight + this.lastScrollTop + this.marginTop - this.offsetTop,
          )}px`;
        } else {
          this.spacer.style.marginTop = '0';
        }
      }
    } else {
      // upscroll
      const overflow = this.globalHeaderHeight + (this.el.clientHeight + this.marginTop) - window.innerHeight;
      if (!isChat) {
        // @ts-ignore
        this.el.style.top = null;
        this.el.style.bottom = `${-overflow}px`;
      } else {
        this.el.style.top = '0';
      }

      this.isTop = scrollTop + this.marginTop + this.globalHeaderHeight <= this.el.offsetTop;

      if (this.isBottom) {
        this.isBottom = false;

        if (!isChat) {
          this.spacer.style.marginTop = `${
            this.globalHeaderHeight + this.lastScrollTop + this.marginTop - this.offsetTop - overflow
          }px`;
        } else {
          this.spacer.style.marginTop = '0';
        }
      }
    }

    this.lastScrollTop = scrollTop <= 0 ? 0 : scrollTop;
  }
}
