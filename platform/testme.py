import os
import sys
from tkinter import E
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

from core_renderer import Jinja2Renderer
from core_api.facts.facter import get_facts_action


def _test_get_facts() -> None:

    try:
        query = {"client": "core", "prn": "prn:core-automation:api:main:latest"}

        filename = sys.argv[1] if len(sys.argv) > 1 else None
        if not filename:
            print("Usage: python testme.py <path to yaml file with query params>")
            return

        basename = filename[0 : filename.rfind(".")] if filename else None
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


if __name__ == "__main__":
    _test_get_facts()
