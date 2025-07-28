<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";

  let password = "";
  let file_path = "";
  let current_status = "Drop a file or enter a path";

  async function callEncrypt() {
    try {
      await invoke("encrypt_file", { path: file_path, password });
      current_status = `Encrypted: ${file_path}`;
    } catch (e) {
      current_status = `Error: ${e}`;
    }
  }

  async function callDecrypt() {
    try {
      await invoke("decrypt_file", { path: file_path, password });
      current_status = `Decrypted: ${file_path}`;
    } catch (e) {
      current_status = `Error: ${e}`;
    }
  }

  listen("tauri://file-drop", async (event: any) => {
    file_path = (event.payload as string[])[0];
    current_status = `Dropped: ${file_path}`;
  });
</script>

<main class="container">
  <input placeholder="Enter path or Drop a file" bind:value={file_path} />
  <input type="password" placeholder="Enter password" bind:value={password} />
  <button on:click={callEncrypt} disabled={!file_path || !password}
    >Encrypt File</button
  >
  <button on:click={callDecrypt} disabled={!file_path || !password}
    >Decrypt File</button
  >
  <p>{current_status}</p>
</main>

<style>
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  :root {
    font-family: Avenir, Inter, Helvetica, Arial, sans-serif;
    font-size: 16px;
    line-height: 24px;
    font-weight: 400;

    color: #0f0f0f;
    background-color: #f6f6f6;

    font-synthesis: none;
    text-rendering: optimizeLegibility;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    -webkit-text-size-adjust: 100%;
  }

  .container {
    margin: 0;
    padding-top: 10vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    text-align: center;
  }

  input,
  button {
    border-radius: 8px;
    border: 1px solid transparent;
    padding: 0.6em 1.2em;
    font-size: 1em;
    font-weight: 500;
    font-family: inherit;
    color: #0f0f0f;
    background-color: #ffffff;
    transition: border-color 0.25s;
    box-shadow: 0 2px 2px rgba(0, 0, 0, 0.2);
  }

  button {
    cursor: pointer;
  }

  button:hover {
    border-color: #396cd8;
  }
  button:active {
    border-color: #396cd8;
    background-color: #e8e8e8;
  }

  input,
  button {
    outline: none;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      color: #f6f6f6;
      background-color: #2f2f2f;
    }

    input,
    button {
      color: #ffffff;
      background-color: #0f0f0f98;
    }
    button:active {
      background-color: #0f0f0f69;
    }
  }
</style>
