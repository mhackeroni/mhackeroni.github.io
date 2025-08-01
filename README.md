# mHACKeroni

Website of mHACKeroni CTF team

## How to edit
1. Install [Hugo](https://gohugo.io/installation/) on your machine.
2. Clone this repository:
   ```bash
   git clone git@github.com:mhackeroni/mhackeroni.github.io.git
   ```
3. Navigate to the cloned directory:
   ```bash
   cd mhackeroni.github.io
   ```
4. Initialize the submodules (Blowfish theme):
   ```bash
   git submodule update --init --recursive
   ```
5. Start the Hugo server:
   ```bash
   hugo server
   ```
6. Open your web browser and go to `http://localhost:1313` to view the site. Edits you make will automatically refresh the page.

Once you are done editing, you can commit your changes and push them to remote to trigger a deployment.