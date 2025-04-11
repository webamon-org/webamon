import os
import time
import requests
from report import Formatting, Technology, Resources, Enrichment
from selenium.common.exceptions import WebDriverException
from threatai import analyze
import argparse
import uuid
from selenium import webdriver
from bs4 import BeautifulSoup
import datetime
from datetime import timezone
import json
import threading
from opensearch import Helper, Domains, Servers
import logging
import urllib3
import distutils.util
import queue
import warnings
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
import io
import base64
from monitoring import generate_fingerprints, monitor

warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)

enrich = Enrichment()
tech = Technology()


def get_config():
    parser = argparse.ArgumentParser(description='Process some configurations.')
    parser.add_argument('--resources', type=str, choices=["images", "scripts", "all", "none", "txt_html"],
                        help='Select which resources to save to Elastic',
                        default=os.getenv('RESOURCES', 'scripts'))
    parser.add_argument('--threads', type=int, help='Count of threads to run', default=int(os.getenv('THREADS', 2)))
    parser.add_argument('--source', type=str, choices=[], help='Source data which contains the domains/urls to scan',
                        default=os.getenv('SOURCE', 'openphish'))
    parser.add_argument('--elastic_query', type=str, help='Query to use when source is set to query',
                        default=os.getenv('ELASTIC_QUERY', ''))
    parser.add_argument('--elastic_size', type=int, help='Max results to return from elasticsearch query',
                        default=int(os.getenv('ELASTIC_SIZE', 100)))
    parser.add_argument('--tag', type=str, help='Tag to add to scan report',
                        default=os.getenv('TAG', ''))
    parser.add_argument('--save_screenshot', type=str, help='Save screenshot true/false',
                        default=str(os.getenv('SAVE_SCREENSHOT', "False")))
    parser.add_argument('--scan_timeout', type=int, help='Time in seconds to wait for url to load',
                        default=int(os.getenv('SCAN_TIMEOUT', 30)))
    parser.add_argument('--save_elastic', type=str, help='Save data (report/resources) to elastic',
                        default=str(os.getenv('SAVE_ELASTIC', "True")))
    parser.add_argument('--save_dom', type=str, help='Save DOM to elastic',
                        default=str(os.getenv('SAVE_DOM', "True")))
    parser.add_argument('--threat_ai', type=str, help='Webamon AI analyse final report',
                        default=str(os.getenv('THREAT_AI', "False")))
    parser.add_argument('--threat_ai_endpoint', type=str, help='Webamon AI endpoint for LLM',
                        default=str(os.getenv('THREAT_AI_ENDPOINT', '')))
    parser.add_argument('--whois', type=str, choices=["ALL", "MAIN", "NONE"], help='Lookup Domain(s) WHOIS info',
                        default=os.getenv('WHOIS', 'NONE'))
    parser.add_argument('--dns', type=str, choices=["ALL", "MAIN", "NONE"], help='Lookup Domain(s) DNS info',
                        default=os.getenv('DNS', 'NONE'))
    parser.add_argument('--check_dangling', type=str, choices=["ALL", "MAIN", "NONE"],
                        help='Check for dangling dns records',
                        default=os.getenv('CHECK_DANGLING', 'NONE'))
    parser.add_argument('--user_agent', type=str, help='Set Custom User Agent String',
                        default=os.getenv('USER_AGENT',
                                          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.3'))
    parser.add_argument('--monitor', type=str, help='Monitor url/domain for changes',
                        default=os.getenv('MONITOR', 'False'))
    parser.add_argument('--aws_save', type=str, help='Save all resources to aws',
                        default=str(os.getenv('AWS_SAVE', "False")))
    parser.add_argument('--aws_key', type=str, help='aws key',
                        default=os.getenv('AWS_KEY', ''))
    parser.add_argument('--aws_resource_bucket', type=str, help='S3 bucket to save resources',
                        default=os.getenv('AWS_RESOURCE_BUCKET', ''))
    parser.add_argument('--aws_dom_bucket', type=str, help='S3 bucket to save DOM',
                        default=os.getenv('AWS_DOM_BUCKET', ''))
    parser.add_argument('--aws_screenshot_bucket', type=str, help='S3 bucket to save screenshot',
                        default=os.getenv('AWS_SCREENSHOT_BUCKET', ''))
    parser.add_argument('--feed', type=str, help='Webamon feed to add the results too',
                        default=os.getenv('FEED', ''))
    parser.add_argument('--save_resources', type=str, help='Save Resources',
                        default=os.getenv('SAVE_RESOURCES', "False"))
    parser.add_argument('--elastic_base', type=str, help='Base url for elastic',
                        default=os.getenv('ELASTIC_BASE', 'https://localhost:9200'))
    parser.add_argument('--skip_if_exists', type=str, help='Skip if the url has been scanned previously',
                        default=str(os.getenv('SKIP_IF_EXISTS', "False")))
    parser.add_argument('--elastic_query_index', type=str, help='Index to user with elastic_query',
                        default=os.getenv('ELASTIC_QUERY_INDEX', 'feeds'))
    parser.add_argument('--queue_worker', type=str, help='Always on, consumes queue',
                        default=os.getenv('QUEUE_WORKER', 'False'))
    parser.add_argument('--webamon_apikey', type=str, help='Always on, consumes queue',
                        default=os.getenv('WEBAMON_APIKEY', ''))
    parser.add_argument('--save_images', type=str, help='Save Image Mime Types',
                        default=os.getenv('SAVE_IMAGES', 'False'))
    parser.add_argument('--save_css', type=str, help='Save CSS Mime Types',
                        default=os.getenv('SAVE_CSS', 'False'))
    parser.add_argument('--set_cookies', type=str, help='Set + Change Cookies, dictionary format',
                        default=os.getenv('SET_COOKIES', '{}'))
    parser.add_argument('--log_level', type=str, choices=["INFO", "DEBUG"], help='Set Logging Level INFO/DEBUG',
                        default=os.getenv('LOG_LEVEL', 'INFO'))
    parser.add_argument('--elastic_username', type=str, help='Elastic Password',
                        default=os.getenv('ELASTIC_USERNAME', 'admin'))
    parser.add_argument('--elastic_password', type=str, help='Elastic Password',
                        default=os.getenv('ELASTIC_PASSWORD', 'admin'))
    parser.add_argument('--url', type=str, help='Pass URL to scan',
                        default=os.getenv('URL', ''))

    args = parser.parse_args()
    args = vars(args)

    # Convert boolean strings to actual booleans
    args['skip_if_exists'] = bool(distutils.util.strtobool(args['skip_if_exists']))
    args['save_resources'] = bool(distutils.util.strtobool(args['save_resources']))
    args['aws_save'] = bool(distutils.util.strtobool(args['aws_save']))
    args['threat_ai'] = bool(distutils.util.strtobool(args['threat_ai']))
    args['save_dom'] = bool(distutils.util.strtobool(args['save_dom']))
    args['save_elastic'] = bool(distutils.util.strtobool(args['save_elastic']))
    args['save_screenshot'] = bool(distutils.util.strtobool(args['save_screenshot']))
    args['queue_worker'] = bool(distutils.util.strtobool(args['queue_worker']))
    args['save_images'] = bool(distutils.util.strtobool(args['save_images']))
    args['save_css'] = bool(distutils.util.strtobool(args['save_css']))
    args['monitor'] = bool(distutils.util.strtobool(args['monitor']))

    return args


def format_utc_datetime(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


config = get_config()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=eval(f'logging.{config["log_level"].upper()}'))
logger = logging.getLogger(__name__)
engine_log = {"start_utc": format_utc_datetime(datetime.datetime.now(timezone.utc)), "date": datetime.datetime.utcnow().strftime("%Y-%m-%d"), "errors": [], "tag": [], 'engine_id': str(uuid.uuid4())}
app = Flask(__name__)
CORS(app)
q = queue.Queue()


if config['save_elastic']:
    OpenSearch = Helper(config)
    domains = Domains(config)
    servers = Servers(config)


counter = 0
success = 0
failed = 0
skipped = 0


def get_openPhish():
    response = requests.get("https://www.openphish.com/feed.txt")
    if response.status_code == 200:
        _urls = response.text.splitlines()
        return _urls
    else:
        print(f"Failed to retrieve data: {response.status_code}")
        return False


@app.route('/scan', methods=['POST'])
def enqueue():
    data = request.json
    report_id = data.get('report_id', str(uuid.uuid4()))  # generate one if not provided
    submission_url = data.get('submission_url')

    def run_scan():
        report = phuck(submission_url, report_id)
        if config['save_elastic']:
            OpenSearch.save_report(Formatting.clean_data(report))
            if 'domain' in report:
                for domain in report['domain']:
                    domains.update(domain)
            if 'server' in report:
                for server in report['server']:
                    servers.update(server)

    # Launch scan in background thread
    threading.Thread(target=run_scan, daemon=True).start()

    # Return immediately
    return jsonify({
        "scan_status": "queued",
        "data": {
            "submission_url": submission_url,
            "report_id": report_id
        }
    }), 202


def set_cookies(driver, domain):
    # TODO Change to run after driver.get
    cookies = json.loads(config['set_cookies'])
    if cookies:
        for cookie in cookies:
            logger.info(f'Setting Cookie {cookie}')
            driver.add_cookie({'name': cookie, "value": cookies[cookie], 'domain': f'.{domain}'})
    return driver


def phuck(url, report_id=''):
    start_time = format_utc_datetime(datetime.datetime.now(timezone.utc))
    global counter, success, failed
    url = url if url.startswith('https://') or url.startswith('http://') else f'http://{url}'
    start = datetime.datetime.now()
    network_data = {'request': {}, 'submission_utc': start_time, 'tag': config['tag'], 'report_id': report_id if report_id else str(uuid.uuid4()), 'submission_url': url,
                    'source': config['source'], "feed": config['feed'], "date": datetime.datetime.utcnow().strftime("%Y-%m-%d"), "save_resources": config['resources'], "engine_id": engine_log['engine_id'], "errors": []}
    network_data['domain_name'], network_data['sub_domain'], network_data['tld'] = enrich.domain_extract(url)
    options = webdriver.ChromeOptions()
    service = webdriver.ChromeService("/app/chromedriver")
    options.binary_location = '/app/chrome/chrome'
    options.add_argument("--headless")
    options.add_argument('--no-sandbox')
    options.add_argument("--disable-gpu")
    options.add_argument('--ignore-ssl-errors')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument("--window-size=1280x1696")
    options.add_argument("--single-process")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-dev-tools")
    options.add_argument("--no-zygote")
    options.add_argument(f"user-agent={config['user_agent']}")
    options.set_capability('goog:loggingPrefs', {'browser': 'ALL', 'performance': 'ALL'})
    chrome = set_cookies(webdriver.Chrome(options=options, service=service), network_data['domain_name'])
    chrome.execute_cdp_cmd("Network.enable", {})
    chrome.set_page_load_timeout(config['scan_timeout'])

    try:
        chrome.get(url)
        network_data['monitor'] = True if config['monitor'] else False
        network_data['dom'] = chrome.page_source
        network_data['page_title'] = chrome.title
        network_data['resolved_url'] = chrome.current_url
        network_data['cookie'] = chrome.get_cookies()
        network_data['resolved_domain'], network_data['resolved_sub_domain'], network_data['resolved_tld'] = enrich.domain_extract(network_data['resolved_url'])
        performance_logs = chrome.get_log('performance')
        network_data = enrich.response_data(performance_logs, network_data)
        network_data['resource'], network_data['resource_master'] = Resources.getResources(network_data['request'], chrome, network_data['report_id'], url, start_time)
        if config['save_screenshot']:
            x = chrome.get_screenshot_as_base64()
            screenshot_base64 = chrome.get_screenshot_as_base64()
            screenshot_bytes = base64.b64decode(screenshot_base64)
            image = Image.open(io.BytesIO(screenshot_bytes))
            if image.mode == 'RGBA':
                image = image.convert('RGB')
            new_width = image.width // 2  # For example, reduce by 50%
            new_height = image.height // 2
            resized_image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
            buffer = io.BytesIO()
            resized_image.save(buffer, format="JPEG", quality=50)  # quality=50 reduces the image quality
            compressed_image_bytes = buffer.getvalue()
            compressed_image_base64 = base64.b64encode(compressed_image_bytes).decode('utf-8')
            OpenSearch.raw_save('screenshots',
                     {"screenshot": compressed_image_base64, "page_title": network_data['page_title'],
                      "domain_name": network_data['domain_name'], "tag": network_data['tag'], 'date': network_data["date"],
                      "submission_url": network_data['submission_url'], 'submission_utc': network_data['submission_utc']}, network_data['report_id'])
        soup = BeautifulSoup(network_data['dom'], 'html.parser')
        script_tags = soup.find_all('script')
        link_tags = soup.find_all('link')
        network_data['page_links'] = [str(x) for x in link_tags]
        network_data['page_scripts'] = [str(x) for x in script_tags]
        network_data['technology'] = tech.getTech(script_tags, link_tags, network_data['request'])
        _subs = []
        certs = []
        requestlist = []

        bad_starts = ["blob", "data"]
        keys_to_delete = []
        for x in network_data['request']:
            if 'response' in network_data['request'][x]:
                request_url = network_data['request'][x]['request']['url']
                response_url = network_data['request'][x]['response']['url']
                if request_url[:4] in bad_starts or response_url[:4] in bad_starts:
                    keys_to_delete.append(x)
                    continue
                if 'securityDetails' in network_data['request'][x]['response']:
                    _ = network_data['request'][x]['response']['securityDetails']
                    _['domain_name'], _['sub_domain'], _['tld'] = enrich.domain_extract(request_url)
                    sub_name = network_data['request'][x]['response']['securityDetails']['subjectName']
                    if sub_name not in _subs:
                        certs.append(network_data['request'][x]['response']['securityDetails'])
                        _subs.append(sub_name)
                    requestlist.append(network_data['request'][x])
        for key in keys_to_delete:
            del network_data['request'][key]
        network_data['certificate'] = certs
        network_data['request'] = requestlist
        network_data = Formatting.transform_headers(network_data)
        for x in network_data['certificate']:
            x['valid_from_utc'] = format_utc_datetime(datetime.datetime.fromtimestamp(x['validFrom'], tz=timezone.utc))
            x['valid_to_utc'] = format_utc_datetime(datetime.datetime.fromtimestamp(x['validTo'], tz=timezone.utc))

        network_data['domain'] = enrich.thirdParties(network_data, network_data['resolved_url'])
        network_data['server'] = enrich.server_data(network_data)
        network_data = enrich.scanMeta(network_data)
        network_data['fingerprint'] = generate_fingerprints(network_data)
        network_data['scan_status'] = "success"
        if config['threat_ai']:
            network_data['threat_ai'] = analyze(network_data, config['threat_ai_endpoint'])
        if network_data['monitor']:
            network_data['changed'] = False
            network_data['changes'] = monitor(network_data)
            if network_data['changes']:
                network_data['changed'] = True

    except WebDriverException as e:
        if "unknown error: net::ERR_NAME_NOT_RESOLVED" in str(e):
            logger.critical(f"Not Resolved - {url}")
            network_data['errors'].append({'error': 'ERR_NAME_NOT_RESOLVED', 'url': url})
        elif "unknown error: net::ERR_CONNECTION_REFUSED" in str(e):
            logger.critical(f"Connection Refused - {url}")
            network_data['errors'].append({'error': 'ERR_CONNECTION_REFUSED', 'url': url})
        else:
            network_data['errors'].append({'error': str(e), 'url': url})
        failed += 1
        network_data['scan_status'] = "failed"
    except Exception as e:
        failed += 1
        network_data['scan_status'] = "failed"
        network_data['errors'].append({'error': str(e), 'url': url})
        print('uncaught error')
        print(e)
    finally:
        chrome.quit()
        network_data['completion_utc'] = format_utc_datetime(datetime.datetime.now(timezone.utc))
        end = datetime.datetime.now()
        network_data['scan_time'] = str(end - start)
        # print(json.dumps(network_data, indent=4))
        return network_data


def url_worker(q, worker_id):
    """Pulls URLs from the queue and processes them."""
    global counter, success, failed, errors, skipped # Access global counters

    logger.info(f"Worker {worker_id} started.")
    while True:
        try:
            # Get a URL from the queue, wait up to 1 second if empty
            url = q.get(timeout=1)
            if url is None: # Sentinel value received
                logger.info(f"Worker {worker_id} received sentinel. Exiting.")
                q.task_done() # Signal that the sentinel was processed
                break # Exit the loop

            logger.debug(f"Worker {worker_id} processing URL: {url}")

            # --- Retry Logic (copied and adapted from previous process_chunk) ---
            max_retries = 2
            retry_delay = 2
            attempt = 0
            report = None
            current_url_processed = False # Flag to track if this URL was processed/skipped

            if config['skip_if_exists']:
                 try:
                    previously_scanned = OpenSearch.value_exists('submission_url', url, 'scans', 'report_id')
                    if previously_scanned:
                        logger.info(f'Worker {worker_id}: Skipping - Scanned Previously {url} - Previous Report: {previously_scanned}')
                        # Ensure counters reflect skipping *before* task_done
                        with threading.Lock(): # Use a lock for thread-safe counter updates
                            skipped += 1
                            counter += 1
                        q.task_done() # Mark skipped task as done
                        current_url_processed = True
                        continue # Skip to the next URL from the queue
                 except Exception as skip_check_e:
                     logger.error(f"Worker {worker_id}: Error checking skip_if_exists for {url}: {skip_check_e}")
                     # Decide if you want to proceed or treat as failure

            # If not skipped, proceed with processing
            while attempt <= max_retries and not current_url_processed:
                try:
                    report = Formatting.clean_data(phuck(url))
                    # If phuck succeeds, break the retry loop
                    current_url_processed = True # Mark as processed
                    break
                except Exception as e:
                    logger.warning(f"Worker {worker_id}: Attempt {attempt + 1} failed for URL {url}. Error: {e}")
                    attempt += 1
                    if attempt <= max_retries:
                        logger.info(f"Worker {worker_id}: Retrying {url} in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                    else:
                        logger.error(f"Worker {worker_id}: Max retries reached for URL {url}. Marking as failed.")
                        if report is None:
                             report = {'submission_url': url, 'scan_status': 'failed', 'errors': [{'error': f'Max retries reached after exception: {e}', 'url': url}]}
                        else: # Ensure status is failed if phuck partially ran then failed
                             report['scan_status'] = 'failed'
                             report.setdefault('errors', []).append({'error': f'Failed during retry attempts: {e}', 'url': url})

                        current_url_processed = True # Mark as processed (failed)
                        break # Exit retry loop after max retries

            # --- Save Logic (adapted from process_chunk) ---
            if report is None and current_url_processed:
                 # This case should ideally not happen if skip logic or retry logic ran
                 logger.error(f"Worker {worker_id}: Report object is None for URL {url} after processing attempt. Inconsistent state.")
                 with threading.Lock(): # Use lock for counters
                     failed += 1
                     counter += 1
                 q.task_done() # Still need to mark task done
                 continue

            if report: # Only proceed if we have a report object
                # Update global counters (use a lock for thread safety)
                with threading.Lock():
                    counter += 1
                    if report.get('scan_status') == 'success':
                        success += 1
                    else:
                        # Ensure status reflects failure if it wasn't already set
                        if 'scan_status' not in report or report['scan_status'] != 'failed':
                             report['scan_status'] = 'failed'
                             if 'errors' not in report: report['errors'] = []
                             if not any('Max retries reached' in err.get('error', '') for err in report.get('errors',[])) and \
                                not any('Scan failed' in err.get('error', '') for err in report.get('errors',[])):
                                 report['errors'].append({'error': 'Scan failed after retries or initial attempt.', 'url': url})
                        failed += 1


                # Save report if configured
                if config['save_elastic']:
                    report.setdefault('report_id', str(uuid.uuid4()))
                    report.setdefault('date', datetime.datetime.utcnow().strftime("%Y-%m-%d"))
                    report.setdefault('submission_utc', format_utc_datetime(datetime.datetime.now(timezone.utc)))
                    try:
                        OpenSearch.save_report(report)
                        if report['scan_status'] == 'success':
                            if 'domain' in report:
                                for domain in report['domain']:
                                    domains.update(domain)
                            if 'server' in report:
                                for server in report['server']:
                                    servers.update(server)
                    except Exception as save_e:
                         logger.error(f"Worker {worker_id}: Failed to save report for {url} to OpenSearch. Error: {save_e}")
                         # Optionally add save error to report object if needed elsewhere
                         # report.setdefault('errors', []).append({'error': f'Failed to save report: {save_e}', 'url': url})

            q.task_done() # Signal that this task is complete

        except queue.Empty:
            # Queue was empty during the timeout, loop again to check for sentinel or new items
            continue
        except Exception as worker_e:
            # Catch unexpected errors in the worker loop itself
            logger.error(f"Worker {worker_id}: Unhandled exception in worker loop: {worker_e}", exc_info=True)
            # Ensure task_done is called if a URL was retrieved but processing failed unexpectedly
            # This is tricky; if url was retrieved, we should call task_done.
            # If the error was before q.get(), we shouldn't.
            # For simplicity, we might lose a task count here, or call it anyway.
            # Let's assume the error happened after getting an item (most likely)
            try:
                q.task_done()
            except ValueError: # If task_done() called too many times
                pass
            # Optionally break or continue depending on desired robustness
            # break # Exit worker on unhandled error
            continue # Try to continue with the next item


def main():
    global success, failed, skipped, counter # Ensure counters are global
    success, failed, skipped, counter = 0, 0, 0, 0 # Reset counters
    start = datetime.datetime.now()
    q = queue.Queue(maxsize=int(config['threads']) * 20) # Maxsize prevents queue from using too much memory if producer is much faster

    if not config['queue_worker']: # Assuming this means run-once mode

        threads = []
        if config['source'] == 'url':
            config['threads'] = 1
        num_threads = int(config['threads'])

        # Start worker threads
        for i in range(num_threads):
            thread = threading.Thread(target=url_worker, args=(q, i+1), daemon=True) # Make threads daemons
            thread.start()
            threads.append(thread)
            logger.info(f"Started worker thread {i+1}")

        # --- Producer Logic ---
        producer_finished = False
        try:
            if config['source'] == 'mass_scan':
                logger.info('Mass scan mode — reading URLs from /app/data/all_domains.txt and queuing...')
                try:
                    with open('/app/data/mass_scan.txt', 'r') as f:
                        file_line_count = 0
                        for line in f:
                            url = line.strip()
                            if url:
                                q.put(url) # Add URL to the queue (blocks if queue is full)
                                file_line_count += 1
                                if file_line_count % 10000 == 0: # Log progress periodically
                                     logger.info(f"Queued {file_line_count} URLs... (Queue size: {q.qsize()})")
                        logger.info(f"Finished reading {file_line_count} URLs from file.")
                except FileNotFoundError:
                    logger.error("Error: /app/data/mass_scan.txt not found.")
                    # Signal workers to exit early
                    for _ in range(num_threads):
                        q.put(None)
                    return # Exit main
                except Exception as e:
                    logger.error(f"Failed to read or queue URLs from mass_urls.txt: {e}")
                    # Signal workers to exit early
                    for _ in range(num_threads):
                        q.put(None)
                    return # Exit main

            elif config['source'] == 'query':
                logger.info(f"Querying OpenSearch index '{config['elastic_query_index']}'...")
                try:
                    urls_from_query = OpenSearch.query(config['elastic_query_index'], config['elastic_query'], config['elastic_size'])
                    query_url_count = 0
                    for record in urls_from_query:
                        url = record.get('fields', {}).get('url') or record.get('fields', {}).get('domain')
                        if url:
                            # If URL is actually a list (can happen with some field types), take the first
                            if isinstance(url, list):
                                url = url[0]
                            q.put(url)
                            query_url_count +=1
                    logger.info(f"Queued {query_url_count} URLs from OpenSearch query.")
                except Exception as e:
                    logger.error(f"Failed to get or queue URLs from OpenSearch query: {e}")
                    # Signal workers to exit early
                    for _ in range(num_threads):
                        q.put(None)
                    return # Exit main

            elif config['source'] == 'openphish':
                logger.info("Getting URLs from OpenPhish...")
                urls_openphish = get_openPhish()
                if urls_openphish:
                    op_count = 0
                    for url in urls_openphish:
                         if url:
                             q.put(url)
                             op_count += 1
                    logger.info(f"Queued {op_count} URLs from OpenPhish.")
                else:
                    logger.error("Failed to get URLs from OpenPhish.")
                    # Signal workers to exit early
                    for _ in range(num_threads):
                        q.put(None)
                    return # Exit main


            elif config['url']:
                logger.info(f"Queueing single URL: {config['url']}")
                q.put(config['url'])
                config['source'] = 'url' # Ensure source is set correctly if using --url

            else:
                 logger.error(f"No valid source specified and no --url provided.")
                 # Signal workers to exit early
                 for _ in range(num_threads):
                     q.put(None)
                 return # Exit main

            producer_finished = True
            logger.info("Producer finished queuing URLs.")

        finally:
            # Signal workers to stop once the queue is empty
            logger.info("Adding sentinels to queue for workers...")
            for _ in range(num_threads):
                q.put(None) # Add sentinel values for each worker thread

            # Wait for all tasks in the queue to be processed
            logger.info("Waiting for queue to empty...")
            q.join() # Blocks until all items have been gotten and processed (task_done called)
            logger.info("Queue empty. All tasks processed.")

            # Threads are daemons, so they will exit automatically when the main thread exits.
            # If they weren't daemons, you'd use:
            # for t in threads:
            #     t.join()
            # logger.info("All worker threads finished.")


        # --- Reporting ---
        engine_log['total'] = counter # Use the thread-safe counter
        engine_log['success'] = success
        engine_log['failed'] = failed
        engine_log['skipped'] = skipped
        engine_log['completion_utc'] = format_utc_datetime(datetime.datetime.now(timezone.utc))
        engine_log['time'] = str(datetime.datetime.now()-start)

        if config['save_elastic']:
            try:
                OpenSearch.raw_save('engine_log', engine_log, engine_log['engine_id'])
            except Exception as e:
                logger.error(f"Failed to save engine_log: {e}")

        print("--- Final Scan Report ---")
        print(json.dumps(engine_log, indent=4))
        print("-------------------------")

    else: # queue_worker is True (Flask mode)
        logger.info("Starting in Queue Worker mode (Flask API)...")

        # Start persistent worker threads
        num_flask_workers = int(config['threads']) # Use configured threads for Flask workers too
        flask_threads = []
        for i in range(num_flask_workers):
            thread = threading.Thread(target=url_worker, args=(q, f"FlaskWorker-{i+1}"), daemon=True)
            thread.start()
            flask_threads.append(thread)
            logger.info(f"Started persistent worker thread {i+1}")

        # Start Flask app - This will block until Flask stops
        logger.info(f"Starting Flask server on 0.0.0.0:5000")
        app.run(host='0.0.0.0', port=5000, debug=False) # Turn debug off for production/stability

        # --- Cleanup (Optional - may not be reached if Flask runs forever) ---
        logger.info("Flask server stopped. Signaling worker threads to exit...")
        for _ in range(num_flask_workers):
            q.put(None) # Add sentinels


        logger.info("Queue worker mode finished.")


if __name__ == '__main__':
    main()
