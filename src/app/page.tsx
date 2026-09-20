import Link from "next/link";

function ShieldLogo({ className = "h-7 w-7" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <path
        d="M12 2.5 4.5 5.2v6.1c0 4.6 3.2 8.4 7.5 10.2 4.3-1.8 7.5-5.6 7.5-10.2V5.2L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path d="m8.7 12.1 2.3 2.3 4.3-4.6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="none" className="mt-0.5 h-4 w-4 shrink-0 text-safe" aria-hidden>
      <circle cx="10" cy="10" r="8.25" stroke="currentColor" strokeWidth="1.5" />
      <path d="m6.5 10.2 2.2 2.2 4.6-4.9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const CATEGORY_CARDS = [
  {
    title: "Urgency & pressure",
    body: "Countdowns, “final warnings”, threats to close your account — pressure is the scammer’s favourite tool.",
  },
  {
    title: "Authority impersonation",
    body: "Fake banks, delivery firms, tax offices and “security teams” that real institutions never send this way.",
  },
  {
    title: "Payment traps",
    body: "Gift cards, crypto, wire transfers and surprise “fees” — payment methods designed to be unrecoverable.",
  },
  {
    title: "Credential harvesting",
    body: "Requests for one-time codes, passwords, PINs or card details. Nobody legitimate asks for these.",
  },
  {
    title: "Suspicious links",
    body: "Shorteners, look-alike domains and brand names that don’t match where the link actually leads.",
  },
  {
    title: "Prize & opportunity baits",
    body: "Lotteries you never entered, guaranteed returns, easy money — the oldest baits in the book.",
  },
];

const STEPS = [
  {
    n: "01",
    title: "Paste the message",
    body: "Drop in a suspicious email, text, WhatsApp forward or payment request. No account, no setup.",
  },
  {
    n: "02",
    title: "Get a verdict in seconds",
    body: "ScamShield weighs the red flags across ten scam-tactic categories and scores the risk.",
  },
  {
    n: "03",
    title: "Follow safe next steps",
    body: "A plain-language explanation and concrete recommendations — so you know what to do, and what not to.",
  },
];

const VERDICTS = [
  { level: "HIGH", color: "text-danger", ring: "border-danger/40 bg-danger/10", body: "Do not act. Strong hallmarks of a scam." },
  { level: "MEDIUM", color: "text-warn", ring: "border-warn/40 bg-warn/10", body: "Proceed with extreme caution and verify first." },
  { level: "LOW", color: "text-safe", ring: "border-safe/40 bg-safe/10", body: "No red flags found — stay alert anyway." },
];

export default function Home() {
  return (
    <div className="flex min-h-screen flex-col">
      {/* Nav */}
      <header className="sticky top-0 z-40 border-b border-line/70 bg-background/80 backdrop-blur-md">
        <nav className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4 sm:px-6">
          <Link href="/" className="flex items-center gap-2.5">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent/30 bg-accent/10 text-accent">
              <ShieldLogo className="h-5 w-5" />
            </span>
            <span className="text-lg font-semibold tracking-tight">
              Scam<span className="text-accent">Shield</span>
            </span>
          </Link>
          <div className="hidden items-center gap-8 text-sm text-muted md:flex">
            <a href="#what-we-check" className="transition-colors hover:text-foreground">What we check</a>
            <a href="#how-it-works" className="transition-colors hover:text-foreground">How it works</a>
            <a href="#verdicts" className="transition-colors hover:text-foreground">Verdicts</a>
            <Link href="/history" className="transition-colors hover:text-foreground">History</Link>
          </div>
          <Link
            href="/analyze"
            className="rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-background transition hover:bg-accent-strong"
          >
            Analyze a message
          </Link>
        </nav>
      </header>

      {/* Hero */}
      <section className="grid-bg relative overflow-hidden">
        <div className="mx-auto grid w-full max-w-6xl gap-12 px-4 pb-20 pt-16 sm:px-6 lg:grid-cols-[1.05fr_0.95fr] lg:items-center lg:pt-24">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-accent/25 bg-accent/10 px-3 py-1 text-xs font-medium text-accent">
              <span className="pulse-dot inline-block h-1.5 w-1.5 rounded-full bg-accent" />
              Scam risk analysis · emails, SMS, WhatsApp & payment requests
            </div>
            <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl lg:text-6xl">
              Analyze suspicious messages{" "}
              <span className="bg-gradient-to-r from-accent to-accent-strong bg-clip-text text-transparent">
                before you act.
              </span>
            </h1>
            <p className="mt-6 max-w-xl text-lg leading-8 text-muted">
              ScamShield scans messages for the tactics scammers rely on — urgency, fake authority,
              payment traps, credential harvesting — then shows you the red flags and your safest next
              move. It explains its reasoning and never claims certainty.
            </p>
            <div className="mt-8 flex flex-col gap-3 sm:flex-row">
              <Link
                href="/analyze"
                className="inline-flex h-12 items-center justify-center gap-2 rounded-lg bg-accent px-6 font-semibold text-background shadow-[0_0_40px_-10px_rgba(45,212,191,0.5)] transition hover:bg-accent-strong"
              >
                <ShieldLogo className="h-5 w-5" />
                Scan a message free
              </Link>
              <a
                href="#how-it-works"
                className="inline-flex h-12 items-center justify-center rounded-lg border border-line bg-surface/60 px-6 font-medium text-foreground transition hover:border-accent/40 hover:text-accent"
              >
                See how it works
              </a>
            </div>
            <p className="mt-4 font-mono text-xs text-muted">
              NO SIGN-UP · HISTORY ENCRYPTED ON YOUR DEVICE · VERDICTS IN SECONDS
            </p>
          </div>

          {/* Sample verdict card */}
          <div className="relative">
            <div className="panel panel-glow relative overflow-hidden rounded-2xl p-5 sm:p-6">
              <div className="scanline" aria-hidden />
              <div className="flex items-center justify-between">
                <p className="font-mono text-[11px] uppercase tracking-widest text-muted">Sample scan · SMS</p>
                <span className="rounded-md border border-danger/40 bg-danger/10 px-2.5 py-1 font-mono text-xs font-bold text-danger">
                  HIGH RISK
                </span>
              </div>
              <div className="mt-4 rounded-lg border border-line/70 bg-background/60 p-4 font-mono text-[13px] leading-6 text-foreground/90">
                <p className="text-muted">From: ROYAL MAIL</p>
                <p>
                  Your parcel is on hold, unpaid customs fee of £2.99. Pay now to reschedule delivery:{" "}
                  <span className="text-danger">bit.ly/rm-parcel-4u</span>
                </p>
              </div>
              <div className="mt-4">
                <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-widest text-muted">
                  <span>Confidence</span>
                  <span className="text-danger">High</span>
                </div>
                <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
                  <div className="h-full w-[91%] rounded-full bg-accent" />
                </div>
              </div>
              <ul className="mt-4 space-y-2.5 text-sm">
                <li className="flex gap-2.5">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-danger" />
                  <span><span className="font-medium">Shortened URL</span> hides the real destination</span>
                </li>
                <li className="flex gap-2.5">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-danger" />
                  <span><span className="font-medium">Delivery fee trick</span> — couriers bill in their app, never by text</span>
                </li>
                <li className="flex gap-2.5">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-warn" />
                  <span><span className="font-medium">Brand mismatch</span> — “Royal Mail” link doesn’t lead to royalmail.com</span>
                </li>
              </ul>
              <div className="mt-4 rounded-lg border border-accent/25 bg-accent/5 p-3.5 text-sm">
                <p className="font-medium text-accent">Recommended next step</p>
                <p className="mt-1 text-foreground/85">Track the parcel in the courier’s official app — don’t pay anything from a text link.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* What we check */}
      <section id="what-we-check" className="border-t border-line/70 bg-surface/30 py-20">
        <div className="mx-auto w-full max-w-6xl px-4 sm:px-6">
          <p className="font-mono text-xs uppercase tracking-widest text-accent">What ScamShield checks</p>
          <h2 className="mt-3 max-w-2xl text-3xl font-semibold tracking-tight sm:text-4xl">
            Red flags across ten scam-tactic categories
          </h2>
          <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {CATEGORY_CARDS.map((c) => (
              <div
                key={c.title}
                className="panel rounded-xl p-5 transition-colors hover:border-accent/35"
              >
                <h3 className="font-medium text-foreground">{c.title}</h3>
                <p className="mt-2 text-sm leading-6 text-muted">{c.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how-it-works" className="border-t border-line/70 py-20">
        <div className="mx-auto w-full max-w-6xl px-4 sm:px-6">
          <p className="font-mono text-xs uppercase tracking-widest text-accent">How it works</p>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">From paste to peace of mind</h2>
          <div className="mt-10 grid gap-4 md:grid-cols-3">
            {STEPS.map((s) => (
              <div key={s.n} className="panel relative rounded-xl p-6">
                <span className="font-mono text-sm text-accent/70">{s.n}</span>
                <h3 className="mt-3 text-lg font-medium">{s.title}</h3>
                <p className="mt-2 text-sm leading-6 text-muted">{s.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Verdicts */}
      <section id="verdicts" className="border-t border-line/70 bg-surface/30 py-20">
        <div className="mx-auto w-full max-w-6xl px-4 sm:px-6">
          <p className="font-mono text-xs uppercase tracking-widest text-accent">Reading the verdict</p>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">Clear levels, honest language</h2>
          <div className="mt-10 grid gap-4 md:grid-cols-3">
            {VERDICTS.map((v) => (
              <div key={v.level} className={`rounded-xl border p-6 ${v.ring}`}>
                <p className={`font-mono text-xl font-bold tracking-wide ${v.color}`}>{v.level}</p>
                <p className="mt-2 text-sm leading-6 text-foreground/85">{v.body}</p>
              </div>
            ))}
          </div>
          <div className="panel mt-8 flex flex-col gap-4 rounded-xl p-6 sm:flex-row sm:items-center">
            <ShieldLogo className="h-8 w-8 shrink-0 text-accent" />
            <div>
              <h3 className="font-medium">Built on honesty, not fear</h3>
              <p className="mt-1 text-sm leading-6 text-muted">
                ScamShield never claims certainty. Every verdict comes with its reasoning, so the final
                judgment — and the stop-and-check habit — stays with you, where it belongs.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="grid-bg border-t border-line/70 py-24">
        <div className="mx-auto flex w-full max-w-3xl flex-col items-center px-4 text-center sm:px-6">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
            Got a message that feels off?
          </h2>
          <p className="mt-4 max-w-xl text-muted">
            Don’t click, don’t pay, don’t reply. Paste it here first — a ten-second check can save you
            a very bad week.
          </p>
          <Link
            href="/analyze"
            className="mt-8 inline-flex h-12 items-center justify-center gap-2 rounded-lg bg-accent px-8 font-semibold text-background shadow-[0_0_40px_-10px_rgba(45,212,191,0.5)] transition hover:bg-accent-strong"
          >
            <ShieldLogo className="h-5 w-5" />
            Analyze a message
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-line/70 py-10">
        <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-between gap-4 px-4 text-sm text-muted sm:flex-row sm:px-6">
          <div className="flex items-center gap-2">
            <ShieldLogo className="h-4 w-4 text-accent" />
            <span>ScamShield © 2026</span>
          </div>
          <p>If you think you’ve already been scammed, contact your bank immediately.</p>
        </div>
      </footer>
    </div>
  );
}
