#!/usr/bin/env python3

import click
import json
import frida
import sys
import os
from pkg_resources import resource_string
from tabulate import tabulate


registernatives = []
script = None
device = None
pid = None

@click.command()
@click.argument("package_name", type=str)
@click.argument("library", type=str)
@click.option("-o", "--output", type=click.File("w"))
def cli(package_name, library, output):
    global script
    global device
    global pid

    devices = frida.get_device_manager().enumerate_devices()
    device = get_device(devices)

    pid = device.spawn([package_name])
    process = device.attach(pid)

    js = resource_string("trace_registernatives.build", "_agent.js").decode()
    script = process.create_script(js, runtime="v8")

    script.on("message", process_message)
    script.load()
    device.resume(pid)
    script.post({"type": "library", "name": library})

    input()
    print("Stopped tracing...")

    if output:
        print("Saving output to file...")
        json.dump(registernatives, output)


def process_message(message, data):
    # if message["type"] == "init":
    #     print("init")
    if message["type"] == "send":
        payload = message["payload"]
        if payload["type"] == "registernatives":
            process_registernatives(payload)


def process_registernatives(payload):
    print("RegisterNatives called:")
    print("class: {}".format(payload["clazz"]))
    print("methods: {}".format(payload["methods"]))
    print("nMethods: {}".format(payload["nMethods"]))
    print()

    registernatives.append({
        "name": payload["clazz"],
        "methods_ptr": payload["methods"],
        "nMethods": payload["nMethods"],
    })


def get_device(devices):
    click.echo("Available devices:")
    list_devices(devices)

    click.echo()
    click.echo("Select device (by index): ", nl=False)
    selection = input()

    try:
        return devices[int(selection)]
    except:
        click.echo("Please enter a valid device selection...")
        os._exit(1)


def list_devices(devices):
    devices_info = [(i.id, i.name, i.type) for i in devices]
    click.echo(tabulate(
        devices_info, headers=["id", "name", "type"], showindex=True))


if __name__ == "__main__":
    cli()
