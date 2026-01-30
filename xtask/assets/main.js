function start() {
    let ptyDecoder = new TextDecoder();
    let ptyOutput = "";

    let outputPre = document.getElementById("output");
    while (outputPre.firstChild) {
        outputPre.removeChild(outputPre.firstChild);
    }
    let outputText = document.createTextNode("");
    outputPre.appendChild(outputText);

    const worker = new Worker("worker.js");
    worker.addEventListener("message", (event) => {
        if (event.data.kind === "error") {
            console.error("worker error message", event.data.message);
        } else if (event.data.kind === "pty_write") {
            ptyOutput += ptyDecoder.decode(event.data.buffer, {stream: true});
            outputText.textContent = ptyOutput;
        } else {
            console.error("unexpected event kind", event.data.kind);
        }
    });
    worker.addEventListener("error", (event) => {
        console.error("worker error event", event);
    });
    worker.addEventListener("messageerror", (_event) => {
        console.error("worker message could not be deserialized");
    })
}

document.addEventListener("DOMContentLoaded", (_event) => {
    start();
});
