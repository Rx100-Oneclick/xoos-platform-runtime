type Handler = (payload: unknown) => void;

export class EventManager {
  private readonly listeners = new Map<string, Set<Handler>>();

  emit(event: string, payload?: unknown): void {
    this.listeners.get(event)?.forEach((handler) => handler(payload));
  }

  on(event: string, handler: Handler): () => void {
    const set = this.listeners.get(event) ?? new Set<Handler>();
    set.add(handler);
    this.listeners.set(event, set);
    return () => {
      set.delete(handler);
      if (set.size === 0) this.listeners.delete(event);
    };
  }

  clear(): void {
    this.listeners.clear();
  }
}
