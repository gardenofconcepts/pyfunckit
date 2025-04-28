logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")

if not OPENAI_API_KEY:
    logger.error("OPEN_API_KEY is not set")
    sys.exit(1)

if not JWT_SECRET:
    logger.error("JWT_SECRET is not set")
    sys.exit(1)
