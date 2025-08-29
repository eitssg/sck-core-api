import os
import sys
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

from core_renderer import Jinja2Renderer
from core_api.facts.facter import get_facts_action

ITEMS = {
    "api-roles": "core-automation-api-roles.yaml.j2",
    "api": "core-automation-api.yaml.j2",
    "api-gateway": "core-automation-api-gateway.yaml.j2",
    "component": "core-automation-component.yaml.j2",
    "deployspec": "core-automation-deployspec.yaml.j2",
    "execute": "core-automation-execute.yaml.j2",
    "invoker": "core-automation-invoker.yaml.j2",
    "runner": "core-automation-runner.yaml.j2",
}


def _run_it(query: dict) -> None:

    try:

        prn = query.get("prn", "")
        if not prn:
            print("No PRN")
            return

        app = prn.split(":")[2] if len(prn.split(":")) > 2 else ""
        if not app:
            print("No app found in PRN")
            return

        filename = ITEMS.get(app)
        if not filename:
            print("Usage: python testme.py <path to yaml file with query params>")
            return

        filename = f"components/{filename}"

        # strip the last 8 characters off ".yaml.j2"
        basename = filename[:-8] if filename else None
        output_name = f"{basename}-output.yaml" if basename else None

        if not output_name:
            print("Could not determine output filename.")
            return

        if not os.path.exists(filename):
            print(f"Input file {filename} does not exist.")
            return

        print("Testing get_facts_action with query:", query)

        results = get_facts_action(query_params=query)
        facts = results.data

        base_folder = os.path.dirname(os.path.abspath(__file__))
        renderer = Jinja2Renderer(base_folder)
        rendered = renderer.render_file(filename, {"context": facts})

        with open(output_name, "w") as f:
            f.write(rendered)

        print("Done.")

    except Exception as e:

        print("Error occurred:", e)


def _test_get_facts():

    for item in ITEMS.keys():
        print(f"--- Generating {item} ---")
        query = {"client": "core", "prn": f"prn:core-automation:{item}:main:latest"}
        _run_it(query)


if __name__ == "__main__":
    _test_get_facts()
