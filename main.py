#!/usr/bin/env python3
import argparse
import json
import csv
import xml.etree.ElementTree as ET
import logging
import os
import re
import chardet
from faker import Faker


# Initialize Faker for generating fake data
fake = Faker()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Anonymizes structured data (JSON, CSV, XML) by replacing sensitive fields with configurable placeholder values."
    )
    parser.add_argument("input_file", help="Path to the input data file.")
    parser.add_argument("output_file", help="Path to the output anonymized file.")
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv", "xml"],
        required=True,
        help="Format of the input data (json, csv, xml).",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Path to the configuration file (JSON) containing field anonymization rules.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging."
    )
    return parser.parse_args()


def load_config(config_file):
    """
    Loads the anonymization configuration from a JSON file.
    Args:
        config_file (str): Path to the JSON configuration file.

    Returns:
        dict: A dictionary containing the anonymization rules.  Returns None if file not found or invalid JSON.
    """
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in configuration file: {config_file}")
        return None


def detect_encoding(file_path):
    """
    Detects the encoding of the input file.

    Args:
        file_path (str): Path to the input file.

    Returns:
        str: The detected encoding, or None if detection fails.
    """
    try:
        with open(file_path, 'rb') as f:
            rawdata = f.read()
        result = chardet.detect(rawdata)
        return result['encoding']
    except Exception as e:
        logging.error(f"Error detecting encoding: {e}")
        return None

def anonymize_json(data, config):
    """
    Anonymizes JSON data based on the provided configuration.

    Args:
        data (dict): The JSON data to anonymize.
        config (dict): The anonymization configuration.

    Returns:
        dict: The anonymized JSON data.
    """
    if not isinstance(data, dict) and not isinstance(data, list):
      return data, 0

    if isinstance(data, list):
      total = 0
      out = []
      for item in data:
          new_item, n = anonymize_json(item, config)
          out.append(new_item)
          total += n
      return out, total

    count = 0
    for key, value in list(data.items()):
        if key in config:
            action = config[key].get("action", "replace")
            placeholder = config[key].get("placeholder", "")
            regex = config[key].get("regex")
            
            if regex:
                try:
                    if isinstance(value, str):
                        data[key], n = re.subn(regex, placeholder, value)
                        count += n
                    else:
                        logging.warning(f"Field {key} with regex requires a string value, skipping.")

                except re.error as e:
                    logging.error(f"Invalid regex for field {key}: {e}")
                    continue

            elif action == "replace":
                count += 1
                if placeholder == "fake.name":
                    data[key] = fake.name()
                elif placeholder == "fake.email":
                    data[key] = fake.email()
                elif placeholder == "fake.address":
                    data[key] = fake.address()
                elif placeholder == "fake.phone_number":
                    data[key] = fake.phone_number()
                elif placeholder == "fake.date":
                    data[key] = str(fake.date())
                elif placeholder == "null":
                    data[key] = None  # Use None for JSON null
                else:
                    data[key] = placeholder

            elif action == "remove":
                del data[key]
                count += 1
            else:
                logging.warning(f"Unknown action '{action}' for field '{key}'. Skipping.")

        elif isinstance(value, dict):
            data[key], n = anonymize_json(value, config)
            count += n
        elif isinstance(value, list):
            new_list = []
            for item in value:
                new_item, n = anonymize_json(item, config)
                new_list.append(new_item)
                count += n
            data[key] = new_list
    return data, count


def anonymize_csv(input_file, output_file, config):
    """
    Anonymizes CSV data. Reads the whole input before opening the output,
    propagates errors, and returns the number of values anonymized.
    """
    if os.path.realpath(input_file) == os.path.realpath(output_file):
        raise ValueError("Output file resolves to the input file; refusing to overwrite it.")
    encoding = detect_encoding(input_file)
    if not encoding:
        logging.error("Failed to detect file encoding.  Using utf-8 as default.")
        encoding = 'utf-8'
    with open(input_file, 'r', encoding=encoding, newline='') as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames
        if not fieldnames:
            raise ValueError("CSV file is empty or has no header.")
        rows = list(reader)
    if not rows:
        raise ValueError("CSV file has no data rows.")
    count = 0
    out_rows = []
    for row in rows:
        anonymized_row = {}
        for field in fieldnames:
            if field in config:
                action = config[field].get("action", "replace")
                placeholder = config[field].get("placeholder", "")
                regex = config[field].get("regex")
                value = row.get(field, "")
                if regex:
                    if isinstance(value, str):
                        anonymized_row[field], n = re.subn(regex, placeholder, value)
                        count += n
                    else:
                        anonymized_row[field] = value
                elif action == "replace":
                    if placeholder == "fake.name":
                        anonymized_row[field] = fake.name()
                    elif placeholder == "fake.email":
                        anonymized_row[field] = fake.email()
                    elif placeholder == "fake.address":
                        anonymized_row[field] = fake.address()
                    elif placeholder == "fake.phone_number":
                        anonymized_row[field] = fake.phone_number()
                    elif placeholder == "fake.date":
                        anonymized_row[field] = str(fake.date())
                    else:
                        anonymized_row[field] = placeholder
                    count += 1
                elif action == "remove":
                    anonymized_row[field] = ""
                    count += 1
                else:
                    logging.warning(f"Unknown action '{action}' for field '{field}'. Skipping.")
                    anonymized_row[field] = value
            else:
                anonymized_row[field] = row[field]
        out_rows.append(anonymized_row)
    if count == 0:
        raise ValueError("No values were anonymized.")
    with open(output_file, 'w', newline='', encoding=encoding) as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)
    return count


def _apply_rule_to_text(value, rule):
    """Returns (new_value, changes) for a replace or regex rule on a string."""
    placeholder = rule.get("placeholder", "")
    regex = rule.get("regex")
    if regex:
        return re.subn(regex, placeholder, value)
    action = rule.get("action", "replace")
    if action == "replace":
        if placeholder == "fake.name":
            return fake.name(), 1
        if placeholder == "fake.email":
            return fake.email(), 1
        if placeholder == "fake.address":
            return fake.address(), 1
        if placeholder == "fake.phone_number":
            return fake.phone_number(), 1
        if placeholder == "fake.date":
            return str(fake.date()), 1
        return placeholder, 1
    return value, 0


def anonymize_xml(input_file, output_file, config):
    """
    Anonymizes XML data. Element text for elements matched by a rule path is
    anonymized, and so are attribute values whose attribute name matches a
    rule key or the last element name in a rule path. Errors propagate, and
    the function returns the number of values anonymized.
    """
    tree = ET.parse(input_file)
    root = tree.getroot()
    count = 0
    # Attribute rules: plain key, or last path segment of an element path.
    attr_rules = {}
    for key, rule in config.items():
        name = key.rstrip('/').split('/')[-1]
        name = name.split('[')[0].lstrip('.')
        if name:
            attr_rules[name] = rule
    for element in root.iter():
        for attr_name in list(element.attrib.keys()):
            if attr_name in attr_rules:
                rule = attr_rules[attr_name]
                if rule.get("action") == "remove" and not rule.get("regex"):
                    del element.attrib[attr_name]
                    count += 1
                else:
                    new_value, n = _apply_rule_to_text(element.attrib[attr_name], rule)
                    element.attrib[attr_name] = new_value
                    count += n
    for element_path, rule in config.items():
        try:
            elements = root.findall(element_path)
        except SyntaxError:
            elements = []
        for element in elements:
            action = rule.get("action", "replace")
            regex = rule.get("regex")
            if regex:
                if element.text:
                    element.text, n = re.subn(regex, rule.get("placeholder", ""), element.text)
                    count += n
            elif action == "replace":
                element.text, n = _apply_rule_to_text(element.text or "", rule)
                count += n
            elif action == "remove":
                parent = find_parent(root, element)
                if parent is not None:
                    parent.remove(element)
                    count += 1
                else:
                    logging.warning(f"Could not find parent of element {element_path}. Skipping removal.")
            else:
                logging.warning(f"Unknown action '{action}' for element '{element_path}'. Skipping.")
    if count == 0:
        raise ValueError("No values were anonymized.")
    tree.write(output_file, encoding="utf-8", xml_declaration=True)
    return count


def find_parent(root, element):
    """Finds the parent of an element in an XML tree."""
    for parent in root.iter():
        for child in parent:
            if child is element:
                return parent
    return None


def main():
    """
    Main function to execute the data anonymization process.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = None
    if args.config:
        config = load_config(args.config)
        if config is None:
            exit(1)

    if not os.path.exists(args.input_file):
        logging.error(f"Input file does not exist: {args.input_file}")
        exit(1)


    try:
        if args.format == "json":
            with open(args.input_file, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON file: {e}")
                    exit(1)
            if config is None:
                logging.error("Configuration file is required for JSON anonymization.")
                exit(1)
            anonymized_data, count = anonymize_json(data, config)
            if count == 0:
                logging.error("No values were anonymized; nothing was saved.")
                exit(1)
            with open(args.output_file, "w") as f:
                json.dump(anonymized_data, f, indent=4)
            logging.info(f"JSON data anonymized and saved to {args.output_file} ({count} value(s) anonymized)")
        elif args.format == "csv":
            if config is None:
                logging.error("Configuration file is required for CSV anonymization.")
                exit(1)
            if os.path.realpath(args.input_file) == os.path.realpath(args.output_file):
                logging.error("Output file resolves to the input file; refusing to overwrite it.")
                exit(1)
            count = anonymize_csv(args.input_file, args.output_file, config)
            logging.info(f"CSV data anonymized and saved to {args.output_file} ({count} value(s) anonymized)")
        elif args.format == "xml":
            if config is None:
                logging.error("Configuration file is required for XML anonymization.")
                exit(1)
            count = anonymize_xml(args.input_file, args.output_file, config)
            logging.info(f"XML data anonymized and saved to {args.output_file} ({count} value(s) anonymized)")
        else:
            logging.error(f"Unsupported format: {args.format}")
            exit(1)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        exit(1)


if __name__ == "__main__":
    main()