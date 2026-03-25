class MessageQueue {
  constructor() {
    this.queue = [];
    this.processing = false;
  }

  async enqueue(message, handler) {
    this.queue.push({ message, handler });
    if (this.processing) {
      return;
    }
    this.processing = true;
    while (this.queue.length) {
      const { message: msg, handler: cb } = this.queue.shift();
      try {
        await cb(msg);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error('[MessageQueue] Handler error:', error);
      }
    }
    this.processing = false;
  }
}

export default MessageQueue;
