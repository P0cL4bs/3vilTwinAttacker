#from http://stackoverflow.com/questions/1057431/loading-all-modules-in-a-folder-in-python
import os
import glob
__all__ = [ os.path.basename(f)[:-3] for f in glob.glob(os.path.dirname(__file__)+"/*.py")]