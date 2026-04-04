"""
core/integrations/audio_manager.py — Pygame Audio Alert Engine
Generates synthetic sound effects for scan lifecycle and vulnerability discoveries.
"""

import os
import time
import logging
import threading
try:
    import pygame
    import numpy as np
    PYGAME_AVAILABLE = True
except ImportError:
    PYGAME_AVAILABLE = False
    np = None 

logger = logging.getLogger(__name__)

class PygameAudioManager:
    """
    Manages audio feedback using Pygame.
    If no WAV files are found, it generates synthetic tones on the fly.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(PygameAudioManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        
        self.enabled = PYGAME_AVAILABLE and os.environ.get("VULNSCOUT_AUDIO", "1") == "1"
        self.sample_rate = 44100
        self.sounds = {}
        
        if self.enabled:
            try:
                pygame.mixer.init(frequency=self.sample_rate, size=-16, channels=1)
                self._generate_synthetic_sounds()
                self._initialized = True
                logger.info("Pygame Audio Manager initialized.")
            except Exception as e:
                logger.error(f"Failed to initialize Pygame mixer: {e}")
                self.enabled = False

    def _generate_synthetic_sounds(self):
        """Generates various notification sounds as pygame.mixer.Sound objects."""
        # Helper to create a Sound from a numpy array
        def array_to_sound(arr):
            # Scale to 16-bit PCM
            sound_arr = (arr * 32767).astype(np.int16)
            return pygame.sndarray.make_sound(sound_arr)

        t = np.linspace(0, 0.5, int(self.sample_rate * 0.5), False)

        # 1. Scan Start (Ascending sweep)
        sweep = np.sin(2 * np.pi * np.linspace(440, 880, len(t)) * t)
        self.sounds["scan_start"] = array_to_sound(sweep * 0.5)

        # 2. Scan Loop (Low hum)
        hum_t = np.linspace(0, 1.0, int(self.sample_rate * 1.0), False)
        hum = np.sin(2 * np.pi * 60 * hum_t) * 0.2
        self.sounds["scan_loop"] = array_to_sound(hum)

        # 3. Critical Alert (High-pitch rapid pulse)
        pulse_t = np.linspace(0, 0.1, int(self.sample_rate * 0.1), False)
        pulse = np.sin(2 * np.pi * 1500 * pulse_t)
        self.sounds["critical"] = array_to_sound(pulse * 0.8)

        # 4. High Alert (Standard beep)
        beep = np.sin(2 * np.pi * 1000 * t)
        self.sounds["high"] = array_to_sound(beep * 0.6)

        # 5. Medium Alert (Lower beep)
        low_beep = np.sin(2 * np.pi * 600 * t)
        self.sounds["medium"] = array_to_sound(low_beep * 0.5)

        # 6. Success Chime (Major chord)
        chime_t = np.linspace(0, 0.8, int(self.sample_rate * 0.8), False)
        s1 = np.sin(2 * np.pi * 523.25 * chime_t) # C5
        s2 = np.sin(2 * np.pi * 659.25 * chime_t) # E5
        s3 = np.sin(2 * np.pi * 783.99 * chime_t) # G5
        chord = (s1 + s2 + s3) / 3.0
        self.sounds["success"] = array_to_sound(chord * 0.6)

    def play(self, sound_name: str, loops: int = 0):
        if not self.enabled or sound_name not in self.sounds:
            return
        
        try:
            self.sounds[sound_name].play(loops=loops)
        except Exception as e:
            logger.debug(f"Error playing sound {sound_name}: {e}")

    def stop_all(self):
        if self.enabled:
            pygame.mixer.stop()

    def play_alert(self, severity: str):
        severity = severity.lower()
        if severity == "critical":
            self.play("critical", loops=2)
        elif severity == "high":
            self.play("high")
        elif severity == "medium":
            self.play("medium")

# Global instance for easy access
audio_manager = PygameAudioManager()
