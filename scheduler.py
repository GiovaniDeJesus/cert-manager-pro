from apscheduler.schedulers.blocking import BlockingScheduler
import subprocess
import logging
import argparse
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='SSL Certificate Expiration Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  %(prog)s --config config.yaml\n'
               )

    parser.add_argument('--config', required=True, help='Path to configuration YAML file')
    parser.add_argument('--scheduler-interval', required=True, type=int, default=6,
                        help='Interval in hours for scheduler (default: 6 hours)')
    
    return parser.parse_args()

def run_check():
    logger.info("Running scheduled certificate check")
    subprocess.run(['python3', 'cert_checker.py', '--config', args.config])

if __name__ == '__main__':
    args = parse_arguments()
    scheduler = BlockingScheduler()
    scheduler.add_job(run_check, 'interval', hours=args.scheduler_interval)

    logger.info("Scheduler started. Checking every {hours} hours.".format(hours=args.scheduler_interval))
    run_check()  # Run once immediately
    scheduler.start()