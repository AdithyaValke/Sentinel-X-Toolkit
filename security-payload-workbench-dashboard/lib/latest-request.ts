/** Cancels superseded requests and identifies the only request allowed to update UI state. */
export class LatestRequest {
  private sequence = 0
  private controller: AbortController | null = null

  begin(): { id: number; signal: AbortSignal } {
    this.controller?.abort()
    this.controller = new AbortController()
    return { id: ++this.sequence, signal: this.controller.signal }
  }

  isCurrent(id: number): boolean {
    return id === this.sequence && !this.controller?.signal.aborted
  }

  cancel(): void {
    this.sequence += 1
    this.controller?.abort()
    this.controller = null
  }
}
