""" Handle installing the ghidra_bridge server scripts (and supporting jfx_bridge) to a specified directory """
import argparse
import os
import pkg_resources

JFX_BRIDGE = "jfx_bridge"
GHIDRA_BRIDGE = "ghidra_bridge"
SERVER_DIR = "server"


def do_install(install_dir):
    # list the files from jfx_bridge
    jfx_bridge_files = [f for f in pkg_resources.resource_listdir(JFX_BRIDGE, ".") if f != "__pycache__"]

    # create a jfx_bridge directory in the install dir
    jfx_bridge_path = os.path.join(install_dir, JFX_BRIDGE)
    if not os.path.isdir(jfx_bridge_path):
        os.makedirs(jfx_bridge_path)

    print("Installing " + JFX_BRIDGE + "...")

    # write out the jfx_bridge files
    for f in jfx_bridge_files:
        dest_path = os.path.join(jfx_bridge_path, f)
        with pkg_resources.resource_stream(JFX_BRIDGE, f) as resource:
            with open(dest_path, "wb") as dest:
                print("\t" + dest_path)
                dest.write(resource.read())

    # list the files from ghidra_bridge server directory
    server_files = [f for f in pkg_resources.resource_listdir(GHIDRA_BRIDGE, SERVER_DIR) if f not in ["__init__.py", "__pycache__"]]

    print("Installing ghidra_bridge server scripts...")

    # write out the ghidra_bridge server files directly in the install dir
    for f in server_files:
        dest_path = os.path.join(install_dir, f)
        with pkg_resources.resource_stream(GHIDRA_BRIDGE, SERVER_DIR + "/" + f) as resource:
            with open(dest_path, "wb") as dest:
                print("\t" + dest_path)
                dest.write(resource.read())

    print("Install completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Install ghidra_bridge server scripts")
    parser.add_argument("install_dir", help="A directory on ghidra's script loading path (e.g., ~/ghidra_scripts)")

    args = parser.parse_args()

    do_install(args.install_dir)
