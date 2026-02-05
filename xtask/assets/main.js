function clearChildren(node) {
    while (node.firstChild) {
        node.removeChild(node.firstChild);
    }
}

async function start() {
    let ptyDecoder = new TextDecoder();
    let ptyOutput = "";

    let outputPre = document.getElementById("output");
    clearChildren(outputPre);
    let outputText = document.createTextNode("");
    outputPre.appendChild(outputText);

    let progressSpan = document.getElementById("progress");
    clearChildren(progressSpan);
    let progressText = document.createTextNode("");
    progressSpan.appendChild(progressText);

    let copyButton = document.getElementById("copy");
    copyButton.addEventListener("click", (_event) => {
        navigator.clipboard.writeText(ptyOutput);
    });

    let notificationsButton = document.getElementById("notifications");
    notificationsButton.addEventListener("click", (_event) => {
        Notification.requestPermission();
    });

    const worker = new Worker("worker.js");
    worker.addEventListener("message", (event) => {
        if (event.data.kind === "error") {
            console.error("worker error message", event.data.message);
            progressText.textContent = "Error";
            progressSpan.style.color = "red";
            if (Notification.permission === "granted") {
                new Notification("Benchmark failed");
            }
        } else if (event.data.kind === "pty_write") {
            ptyOutput += ptyDecoder.decode(event.data.buffer, {stream: true});
            outputText.textContent = ptyOutput;
        } else if (event.data.kind === "done") {
            progressText.textContent = "Complete";
            progressSpan.style.color = "green";
            if (Notification.permission === "granted") {
                new Notification("Benchmark complete");
            }
        } else {
            console.error("unexpected event kind", event.data.kind);
        }
    });
    worker.addEventListener("error", (event) => {
        console.error("worker error event", event);
    });
    worker.addEventListener("messageerror", (_event) => {
        console.error("worker message could not be deserialized");
    });

    const argsResponse = await fetch("/args");
    if (!argsResponse.ok) {
        throw new Error(`Response status from /args: ${argsResponse.status}`);
    }
    const args = await argsResponse.json();

    worker.postMessage({"kind": "run", "args": args});
    progressText.textContent = "Running";
    progressSpan.style.color = "orange";
}

document.addEventListener("DOMContentLoaded", (_event) => {
    start();
});
