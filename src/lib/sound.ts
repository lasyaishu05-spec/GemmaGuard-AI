// Web Audio API synthesizer for cybernetic UI feedback (zero external audio files)
class SoundManager {
  private ctx: AudioContext | null = null;
  public enabled: boolean = true;

  private initCtx() {
    if (!this.ctx && typeof window !== "undefined") {
      const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
      }
    }
    if (this.ctx && this.ctx.state === "suspended") {
      this.ctx.resume();
    }
  }

  playBeep(freq = 880, type: OscillatorType = "sine", duration = 0.08, gain = 0.05) {
    if (!this.enabled || typeof window === "undefined") return;
    try {
      this.initCtx();
      if (!this.ctx) return;
      const osc = this.ctx.createOscillator();
      const gainNode = this.ctx.createGain();

      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
      gainNode.gain.setValueAtTime(gain, this.ctx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);

      osc.connect(gainNode);
      gainNode.connect(this.ctx.destination);

      osc.start();
      osc.stop(this.ctx.currentTime + duration);
    } catch {
      // AudioContext policy fallback
    }
  }

  playExecute() {
    this.playBeep(440, "triangle", 0.06, 0.08);
    setTimeout(() => this.playBeep(880, "triangle", 0.12, 0.08), 70);
  }

  playSuccess() {
    this.playBeep(523.25, "sine", 0.08, 0.06);
    setTimeout(() => this.playBeep(659.25, "sine", 0.08, 0.06), 90);
    setTimeout(() => this.playBeep(1046.5, "sine", 0.16, 0.06), 180);
  }

  playClick() {
    this.playBeep(1200, "sine", 0.03, 0.02);
  }
}

export const sound = new SoundManager();
