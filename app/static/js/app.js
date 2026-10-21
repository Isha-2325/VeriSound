// Forensic UI controller and interactive waveform player

function openModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('active');
}

function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('active');
}

// Waveform Player Engine
class ForensicWaveformViewer {
    constructor(canvasId, audioId, waveformData) {
        this.canvas = document.getElementById(canvasId);
        this.audio = document.getElementById(audioId);
        this.waveformData = waveformData || { min: [], max: [] };
        
        if (!this.canvas || !this.audio) return;
        this.ctx = this.canvas.getContext('2d');
        this.init();
    }

    init() {
        // Adjust for device pixel ratio
        const rect = this.canvas.getBoundingClientRect();
        this.canvas.width = rect.width * window.devicePixelRatio;
        this.canvas.height = rect.height * window.devicePixelRatio;
        this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
        this.width = rect.width;
        this.height = rect.height;

        this.render(0);

        this.audio.addEventListener('timeupdate', () => {
            const progress = this.audio.duration ? (this.audio.currentTime / this.audio.duration) : 0;
            this.render(progress);
            this.updateTimeDisplay();
        });

        this.canvas.addEventListener('click', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const clickX = e.clientX - rect.left;
            const progress = Math.max(0, Math.min(1, clickX / rect.width));
            if (this.audio.duration) {
                this.audio.currentTime = progress * this.audio.duration;
            }
        });
    }

    render(playheadProgress = 0) {
        const { width, height } = this;
        const ctx = this.ctx;
        ctx.clearRect(0, 0, width, height);

        const centerY = height / 2;
        const mins = this.waveformData.min;
        const maxs = this.waveformData.max;
        const len = Math.max(mins.length, maxs.length);

        if (len === 0) {
            ctx.fillStyle = '#64748b';
            ctx.font = '12px sans-serif';
            ctx.fillText('No waveform samples available', 20, centerY);
            return;
        }

        const step = width / len;

        for (let i = 0; i < len; i++) {
            const x = i * step;
            const yMin = centerY - (mins[i] || 0) * (height * 0.45);
            const yMax = centerY - (maxs[i] || 0) * (height * 0.45);

            // Played vs unplayed coloring
            const isPlayed = (x / width) <= playheadProgress;
            ctx.strokeStyle = isPlayed ? '#38bdf8' : '#334155';
            ctx.lineWidth = Math.max(1, step * 0.8);
            ctx.beginPath();
            ctx.moveTo(x, yMin);
            ctx.lineTo(x, yMax);
            ctx.stroke();
        }

        // Draw Playhead
        const playheadX = playheadProgress * width;
        ctx.strokeStyle = '#ef4444';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(playheadX, 0);
        ctx.lineTo(playheadX, height);
        ctx.stroke();
    }

    updateTimeDisplay() {
        const disp = document.getElementById('audio-time-label');
        if (!disp) return;
        const cur = this.formatTime(this.audio.currentTime);
        const dur = this.formatTime(this.audio.duration || 0);
        disp.innerText = `${cur} / ${dur}`;
    }

    formatTime(sec) {
        const m = Math.floor(sec / 60);
        const s = Math.floor(sec % 60);
        const ms = Math.floor((sec % 1) * 100);
        return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}.${String(ms).padStart(2, '0')}`;
    }

    seekTo(sec) {
        if (this.audio) {
            this.audio.currentTime = sec;
            this.audio.play();
            const btn = document.getElementById('play-btn');
            if (btn) btn.innerText = 'Pause';
        }
    }

    togglePlay() {
        if (!this.audio) return;
        const btn = document.getElementById('play-btn');
        if (this.audio.paused) {
            this.audio.play();
            if (btn) btn.innerText = 'Pause';
        } else {
            this.audio.pause();
            if (btn) btn.innerText = 'Play';
        }
    }
}

// Global hook for splice table rows to seek in audio
let activeViewer = null;
function jumpToTimestamp(seconds) {
    if (activeViewer) {
        activeViewer.seekTo(seconds);
    }
}
