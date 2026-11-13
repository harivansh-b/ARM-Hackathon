import argparse
import json
import sys

from .detectors import analyze_sms, analyze_url


def main() -> None:
    """Run one offline detector invocation and print JSON for a demo or script."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Guardian Person C baseline detectors")
    parser.add_argument("--kind", choices=("sms", "url"), required=True)
    parser.add_argument("--text")
    parser.add_argument("--url")
    args = parser.parse_args()
    if args.kind == "sms":
        if args.text is None:
            parser.error("--text is required for sms")
        result = analyze_sms(args.text)
    else:
        if args.url is None:
            parser.error("--url is required for url")
        result = analyze_url(args.url)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
