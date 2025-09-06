"""
UHF RFID Reader Integration (Java JNI Bridge)
-------------------------------------------------
This module bridges the vendor-provided Java JNI wrapper (Reader18) with the
Python application using JPype. It exposes a Pythonic interface for:

 - Initializing the UHF reader over Serial/COM
 - Performing inventory (EPC GEN2) scans
 - Running a background continuous scan loop with callback
 - Graceful shutdown and resource cleanup

Assumptions / Notes:
 - Vendor libraries (UHFReader18.dll / .so) are located in `app/java`.
 - The Java wrapper class is `UHF.Reader18` under `app/java` source root.
 - JPype is used instead of subprocess to avoid parsing CLI output.
 - On Raspberry Pi, vendor usually ships a `.so` instead of `.dll`. The user
   should place it beside the existing DLLs using same base name.

Safety / Error Handling:
 - All Java calls wrapped with try/except logging
 - Automatic JVM start only once; verifies class availability
 - Fallback simulation mode if JVM or library load fails

Future Enhancements:
 - Add configurable power dbm adjustment
 - Add lock / write EPC utilities
 - Add network (TCP) open alternative
"""

from __future__ import annotations

import os
import threading
import time
import logging
from typing import Callable, Optional, List

# Simple logging setup to replace app.services.log_service.Logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SimpleLogger:
    """Simple logger replacement for standalone operation."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    @classmethod
    def get_instance(cls):
        return cls()
    
    def log_info(self, message: str):
        self.logger.info(message)
    
    def log_warning(self, message: str):
        self.logger.warning(message)
    
    def log_error(self, message: str):
        self.logger.error(message)

try:
	import jpype
	import jpype.imports  # noqa: F401 (side-effect enabling)
	HAS_JPYPE = True
except ImportError:
	HAS_JPYPE = False


class UHFReader:
	"""Python wrapper around the Java `UHF.Reader18` JNI class."""

	def __init__(self, port_index: int = 0, address: int = 0xFF, baud: int = 57600):
		"""
		Initialize UHF reader instance.

		Args:
			port_index: Index to attempt (maps to physical /dev/ttyUSB* or COM*)
			address: Reader address (0xFF broadcast typical)
			baud: Baud rate (reader internal – not always changeable here)
		"""
		self.logger = SimpleLogger.get_instance()
		self.port_index = port_index
		self.address = address
		self.baud = baud
		self.reader = None
		self.is_open = False
		self.scan_thread: Optional[threading.Thread] = None
		self._stop_event = threading.Event()
		self._callback: Optional[Callable[[str], None]] = None
		self.simulation_mode = False

		self.logger.log_info("Initializing UHFReader bridge")
		self._ensure_jvm()
		if not self.simulation_mode:
			self._instantiate_reader()
			self._open_port()

	# ------------------------------------------------------------------ #
	# JVM / Java Setup
	# ------------------------------------------------------------------ #
	def _ensure_jvm(self):
		if not HAS_JPYPE:
			self.logger.log_warning("JPype not installed – running UHF reader in simulation mode")
			self.simulation_mode = True
			return

		if jpype.isJVMStarted():
			return

		# Build classpath – include java source directory. If compiled .class
		# files are required, user can pre-compile; JPype can also compile on
		# the fly for simple cases.
		java_src = os.path.join(os.path.dirname(__file__), '..', 'java')
		java_src = os.path.abspath(java_src)

		# Attempt to locate native library directory for JVM (so/dll)
		lib_path = java_src

		try:
			jvm_path = jpype.getDefaultJVMPath()
			jvm_args = [
				f"-Djava.class.path={java_src}",
				f"-Djava.library.path={lib_path}",
			]
			jpype.startJVM(jvm_path, *jvm_args)
			self.logger.log_info("JVM started for UHF Reader integration")
		except Exception as e:
			self.logger.log_error(f"JVM not available ({e}); entering simulation mode. Set JAVA_HOME and install a JRE to enable hardware.")
			self.simulation_mode = True

	def _instantiate_reader(self):
		if self.simulation_mode:
			return
		try:
			from UHF import Reader18  # JPype import style
			self.reader = Reader18()
			self.logger.log_info("Reader18 Java instance created")
		except Exception as e:
			self.logger.log_error(f"Failed to instantiate Reader18: {e}")
			self.simulation_mode = True

	# ------------------------------------------------------------------ #
	# Port / Connection Handling
	# ------------------------------------------------------------------ #
	def _open_port(self):
		"""Attempt to open COM/Serial port using vendor API."""
		if self.simulation_mode or not self.reader:
			return
		try:
			# The vendor API typically expects an int array parameter with
			# structure-dependent fields. Without vendor docs, we attempt a
			# common pattern: [ComAdr, ComIndex, BaudRateFlag, ResultPlaceholders...]
			arr = [self.address, self.port_index, 5, 0, 0, 0, 0, 0]
			result = self.reader.OpenComPort(arr)
			if result and isinstance(result, list):
				# Heuristic: last element 0 means success for many vendor libs
				status_code = result[-1]
				if status_code == 0:
					self.is_open = True
					self.logger.log_info(f"UHF Reader COM port opened (index={self.port_index})")
				else:
					self.logger.log_warning(f"OpenComPort returned status {status_code}; falling back to simulation")
			else:
				self.logger.log_warning("Unexpected OpenComPort response – enabling simulation")
		except Exception as e:
			self.logger.log_error(f"Exception opening UHF port: {e}")
			self.simulation_mode = True

	def close(self):
		if self.is_open and self.reader and not self.simulation_mode:
			try:
				code = self.reader.CloseComPort()
				self.logger.log_info(f"Closed UHF reader (code={code})")
			except Exception as e:
				self.logger.log_error(f"Error closing UHF reader: {e}")
		self.is_open = False
		self.stop_continuous_inventory()

	# ------------------------------------------------------------------ #
	# Inventory (Scan)
	# ------------------------------------------------------------------ #
	def inventory_once(self) -> List[str]:
		"""
		Perform a single inventory cycle and return EPC list (hex strings).
		In simulation mode returns mock values.
		"""
		if self.simulation_mode or not self.reader or not self.is_open:
			return ["SIM_EPC1234567890"]
		try:
			param = [0] * 256
			data = self.reader.Inventory_G2(param)
			if not data:
				return []
			tags: List[str] = []
			current: List[int] = []
			for raw in data:
				try:
					val = int(raw)
				except Exception:
					continue
				if val < 0:
					continue
				if val == 0:
					if len(current) >= 4:
						tags.append(''.join([f"{b & 0xFF:02X}" for b in current]))
					current = []
					continue
				current.append(val & 0xFF)
			if current and len(current) >= 4:
				tags.append(''.join([f"{b & 0xFF:02X}" for b in current]))
			return tags
		except Exception as e:
			self.logger.log_error(f"Inventory exception: {e}")
			return []

	def start_continuous_inventory(self, callback: Callable[[str], None], interval: float = 0.5):
		"""Begin background inventory loop invoking callback per tag seen."""
		self._callback = callback
		if self.scan_thread and self.scan_thread.is_alive():
			return
		self._stop_event.clear()

		def worker():
			seen_cache = set()  # simple cache to avoid spamming duplicates rapidly
			while not self._stop_event.is_set():
				tags = self.inventory_once()
				for epc in tags:
					if epc not in seen_cache:
						seen_cache.add(epc)
						if self._callback:
							try:
								self._callback(epc)
							except Exception as cb_err:
								self.logger.log_error(f"UHF callback error: {cb_err}")
				if len(seen_cache) > 512:
					# prevent unbounded growth; periodic reset
					seen_cache.clear()
				time.sleep(interval)
		self.scan_thread = threading.Thread(target=worker, daemon=True)
		self.scan_thread.start()
		self.logger.log_info("Started continuous UHF inventory loop")

	def stop_continuous_inventory(self):
		if self.scan_thread and self.scan_thread.is_alive():
			self._stop_event.set()
			self.scan_thread.join(timeout=2)
			self.logger.log_info("Stopped UHF inventory loop")
		self.scan_thread = None

	# ------------------------------------------------------------------ #
	# Utility
	# ------------------------------------------------------------------ #
	def set_callback(self, callback: Callable[[str], None]):
		self._callback = callback

	def is_ready(self) -> bool:
		return self.is_open or self.simulation_mode

	def __del__(self):  # best-effort cleanup
		try:
			self.close()
		except Exception:
			pass


# Convenience test harness (manual run):
if __name__ == "__main__":
	reader = UHFReader()
	if reader.is_ready():
		print("UHF Reader ready. Single inventory run:")
		print(reader.inventory_once())
		def cb(tag):
			print("TAG:", tag)
		reader.start_continuous_inventory(cb, interval=2)
		time.sleep(6)
		reader.stop_continuous_inventory()
	else:
		print("Reader not ready.")
