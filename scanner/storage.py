import json
from datetime import datetime
from pathlib import Path


def save_results_to_json(results, target, output_dir="outputs"):
    """
    Save parsed scan results into a structured JSON file.
    """

    # Ensure output directory exists
    Path(output_dir).mkdir(exist_ok=True)

    filename = f"{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = Path(output_dir) / filename

    data = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "results": results
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    return str(filepath)