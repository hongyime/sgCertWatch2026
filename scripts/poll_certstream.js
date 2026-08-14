const INGEST_URL = process.env.INGEST_URL || "http://localhost:3000/api/ingest";
const INGEST_TOKEN = process.env.INGEST_TOKEN || "";
const CERTSTREAM_URL = process.env.CERTSTREAM_URL || "wss://certstream.calidog.io/";
const RUN_SECONDS = Number(process.env.RUN_SECONDS || 0);
const BATCH_SIZE = Number(process.env.BATCH_SIZE || 25);

let buffered = [];
let posted = 0;

async function postBatch() {
  if (!buffered.length) return;

  const entries = buffered;
  buffered = [];

  const response = await fetch(INGEST_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(INGEST_TOKEN ? { Authorization: `Bearer ${INGEST_TOKEN}` } : {})
    },
    body: JSON.stringify({ entries })
  });

  if (!response.ok) {
    throw new Error(`ingest failed: ${response.status} ${await response.text()}`);
  }

  const result = await response.json();
  posted += entries.length;
  console.log(JSON.stringify({ posted, matched: result.matched, persisted: result.persisted }));
}

function connect() {
  const socket = new WebSocket(CERTSTREAM_URL);

  socket.addEventListener("open", () => {
    console.log(JSON.stringify({ event: "connected", url: CERTSTREAM_URL, ingestUrl: INGEST_URL }));
  });

  socket.addEventListener("message", async (event) => {
    const message = JSON.parse(event.data);
    if (message.message_type !== "certificate_update") return;

    buffered.push(message.data);
    if (buffered.length >= BATCH_SIZE) {
      try {
        await postBatch();
      } catch (error) {
        console.error(error.message);
      }
    }
  });

  socket.addEventListener("close", async () => {
    await postBatch().catch((error) => console.error(error.message));
    console.log(JSON.stringify({ event: "closed", posted }));
    if (!RUN_SECONDS) setTimeout(connect, 2000);
  });

  socket.addEventListener("error", (error) => {
    console.error(error.message || "certstream websocket error");
    socket.close();
  });

  if (RUN_SECONDS > 0) {
    setTimeout(() => socket.close(), RUN_SECONDS * 1000);
  }
}

connect();
