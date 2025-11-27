import sys
from pathlib import Path

current_dir = Path(__file__).parent.resolve()
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))


try:
    from vaulty.app_streamlit import main
except ImportError as e:
    print(f"Error importing vaulty: {e}")
    raise e

if __name__ == "__main__":
    main()
