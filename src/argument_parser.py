import argparse


def arguments_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--rules", type=str, required=True, help="Path to the rules file")
    parser.add_argument("-f", "--rules_format", type=str, required=True, help="Rules file format")
    return parser.parse_args()