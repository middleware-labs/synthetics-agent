export class CustomLogger {
  constructor(cmdArgs) {
    this.cmdArgs = cmdArgs;
  }

  info(msg) {
    if (this.cmdArgs.debug) {
      console.log(msg);
    }
  }

  error(msg) {
    if(this.cmdArgs.debug) {
        console.error(msg);
    }
  }
}
